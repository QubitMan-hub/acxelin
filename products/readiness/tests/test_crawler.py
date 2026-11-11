"""Relationships must be evidenced, scoped, private, and useful across module boundaries."""
import ast
import json
import subprocess
from pathlib import Path

from acxelin_readiness import pipeline, cbom
from acxelin_readiness.crawler import CodeCrawler
from acxelin_readiness.detectors import Scope, iter_files, snapshot


def test_cross_module_wrappers_are_attached_to_actual_crypto_findings(tmp_path):
    (tmp_path / "keys.py").write_text('from cryptography.hazmat.primitives.asymmetric import rsa\ndef make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    (tmp_path / "service.py").write_text('from keys import make as issue\ndef enroll():\n    return issue()\ndef route():\n    return enroll()\n')
    result = pipeline.run(tmp_path, "test")
    asset = next(a for a in result.assets if a.algo == "RSA" and "code_impact" in a.params)
    impact = asset.params["code_impact"]
    assert impact["functions"] == ["keys.py#make"]
    assert impact["callers"] == ["service.py#enroll", "service.py#route"]
    component = cbom.algorithm_component(asset)
    assert any(p["name"] == "acxelin:code-impact" for p in component["properties"])


def test_shadowing_dynamic_dispatch_and_ambiguous_definitions_are_not_confirmed():
    crawler = CodeCrawler()
    crawler.observe("a.py", ast.parse('def target(): pass\ndef target(): pass\ndef run(target):\n target()\n object().method()\ndef other(): target()'))
    graph = crawler.finish([])
    assert all(call["target"] is None for call in graph["calls"])
    assert all("unresolved" in call["confidence"] for call in graph["calls"])


def test_relative_imports_nested_functions_and_async_are_resolved(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text('')
    (tmp_path / "pkg/helper.py").write_text('def verify(): pass')
    (tmp_path / "pkg/api.py").write_text('from .helper import verify as check\nasync def endpoint():\n def inner():\n  return check()\n return inner()')
    graph = pipeline.run(tmp_path, "project").relationships
    assert any(c["target"] == "pkg/helper.py#verify" for c in graph["calls"])
    assert any(c["target"] == "pkg/api.py#endpoint.inner" for c in graph["calls"])


def test_graph_does_not_export_literals_snippets_or_docstrings():
    crawler = CodeCrawler()
    crawler.observe("safe.py", ast.parse('import hashlib\ndef digest():\n "PRIVATE_DOCSTRING"\n return hashlib.sha256(b"PRIVATE_ARGUMENT_VALUE")'))
    encoded = json.dumps(crawler.finish([]))
    assert "PRIVATE_" not in encoded
    assert "hashlib" in encoded


def test_shared_scope_keeps_gitignored_keys_and_applies_exclusions_size_and_symlinks(tmp_path):
    """Deployed keys and secrets are usually gitignored, and they are exactly what an inventory must find."""
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / '.gitignore').write_text('ignored.py\n')
    (tmp_path / 'ignored.py').write_text('import rsa')
    (tmp_path / 'kept.py').write_text('import hashlib')
    (tmp_path / 'large.py').write_text('x' * 2_000_001)
    (tmp_path / 'outside.py').symlink_to(Path(__file__).resolve())
    scope = snapshot(tmp_path, Scope(exclude=('large.py',)))
    names = [p.name for p in iter_files(tmp_path, scope)]
    assert 'kept.py' in names
    assert 'ignored.py' in names
    assert 'outside.py' not in names
    assert 'large.py' not in names
    assert scope.files is not None


def test_nonpython_and_malformed_sources_keep_existing_detectors(tmp_path):
    (tmp_path / 'broken.py').write_text('def broken(')
    (tmp_path / 'code.js').write_text('const crypto = require("crypto"); crypto.createHash("sha256");')
    result = pipeline.run(tmp_path, 'mixed')
    assert result.relationships['languages'].get('Python', 0) == 0
    assert any(a.algo == 'SHA-256' for a in result.assets)
    assert any('could not be parsed' in n for n in result.notes)


def test_crypto_families_and_pqc_wrappers_have_supported_callers(tmp_path):
    (tmp_path/'crypto.py').write_text('''from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, ssl, oqs
def protect():
 ec.ECDSA()
 ec.ECDH()
 AESGCM.generate_key(bit_length=256)
 hashlib.sha256(b"PRIVATE_VALUE")
 ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
 oqs.KeyEncapsulation("ML-KEM-768")
''')
    (tmp_path/'app.py').write_text('from crypto import protect\ndef workflow():\n return protect()')
    result=pipeline.run(tmp_path,'families')
    supported={a.algo for a in result.assets if a.params.get('code_impact',{}).get('callers') == ['app.py#workflow']}
    assert {'ECDSA','ECDH','AES','SHA-256','TLS 1.2','ML-KEM-768'} <= supported


def test_deferred_lambda_and_definition_defaults_are_not_function_uses(tmp_path):
    (tmp_path/'a.py').write_text('import hashlib\ndef deferred(x=hashlib.md5()):\n return lambda: hashlib.sha256()')
    result=pipeline.run(tmp_path,'deferred')
    assert not any('code_impact' in a.params for a in result.assets)


def test_git_fsmonitor_is_not_executed_during_source_discovery(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)],check=True)
    hook=tmp_path/'dangerous-hook'
    hook.write_text('#!/bin/sh\ntouch '+str(tmp_path/'EXECUTED')+'\n')
    hook.chmod(0o700)
    subprocess.run(['git','-C',str(tmp_path),'config','core.fsmonitor',str(hook)],check=True)
    (tmp_path/'safe.py').write_text('import hashlib')
    assert list(iter_files(tmp_path))
    assert not (tmp_path/'EXECUTED').exists()


def test_same_line_default_is_not_reported_as_a_function_body_use(tmp_path):
    (tmp_path/'default.py').write_text('import hashlib\ndef api(x=hashlib.md5()): return x')
    result=pipeline.run(tmp_path,'default')
    assert not any('code_impact' in a.params for a in result.assets)


def test_module_objects_are_not_resolved_as_callable_functions(tmp_path):
    (tmp_path/'helper.py').write_text('x=1')
    (tmp_path/'api.py').write_text('import helper\ndef run(): helper()')
    result=pipeline.run(tmp_path,'module')
    assert all(c['target'] is None for c in result.relationships['calls'])


def test_python_package_reexports_preserve_crypto_caller_chain(tmp_path):
    (tmp_path/'keys').mkdir()
    (tmp_path/'keys/crypto.py').write_text('import hashlib\ndef digest(): return hashlib.sha256()')
    (tmp_path/'keys/__init__.py').write_text('from .crypto import digest as sign')
    (tmp_path/'api.py').write_text('from keys import sign\ndef payment(): return sign()')
    r=pipeline.run(tmp_path,'public-api')
    assert any(c['target']=='keys/crypto.py#digest' for c in r.relationships['calls'])
    asset=next(a for a in r.assets if a.algo=='SHA-256' and a.params.get('code_impact'))
    assert asset.params['code_impact']['callers']==['api.py#payment']


def test_cyclic_python_reexports_stay_unresolved(tmp_path):
    (tmp_path/'a.py').write_text('from b import helper')
    (tmp_path/'b.py').write_text('from a import helper\ndef run(): helper()')
    assert all(c['target'] is None for c in pipeline.run(tmp_path,'cycle').relationships['calls'])


def test_incremental_parsing_recomputes_relationships_and_invalidates_edits(tmp_path):
    from acxelin_readiness.crawler import ParseCache
    cache = ParseCache()
    (tmp_path/'a.py').write_text('def key(): pass\n')
    (tmp_path/'b.py').write_text('from a import key\ndef run(): key()\n')
    first = pipeline.run(tmp_path, 'cache', cache=cache).relationships
    second = pipeline.run(tmp_path, 'cache', cache=cache).relationships
    assert second['incremental']['reused_syntax'] == 2
    assert first['calls'] == second['calls']
    (tmp_path/'a.py').write_text('def renamed(): pass\n')
    edited = pipeline.run(tmp_path, 'cache', cache=cache).relationships
    assert edited['incremental']['reused_syntax'] == 1
    assert edited['calls'][0]['target'] is None
    (tmp_path/'a.py').unlink()
    assert pipeline.run(tmp_path, 'cache', cache=cache).relationships['calls'][0]['target'] is None
    tiny = ParseCache(max_bytes=15, max_entries=1)
    import ast
    for src in (b'x=1', b'y=2', b'z=' + b'1'*30):
        tiny.parse('Python', src, ast.parse)
    assert len(tiny.entries) <= 1 and tiny.bytes <= 15


def test_production_precedes_tests_and_budget_names_omissions(tmp_path, monkeypatch):
    (tmp_path/'tests').mkdir()  # sorts before z_service.py, so the order below is the rule, not the alphabet
    (tmp_path/'tests/test_big.py').write_text('test_call()\n'*30)
    (tmp_path/'z_service.py').write_text('production_call()\n')
    monkeypatch.setattr('acxelin_readiness.crawler.LIMIT_CALLS', 2)
    graph = pipeline.run(tmp_path, 'budget').relationships
    assert graph['calls'][0]['file'] == 'z_service.py'
    assert graph['truncated_files'] == {'tests/test_big.py': {'calls (including unvisited nested calls)': 29}}


def test_nonsecurity_partition_and_same_line_security_trap(tmp_path):
    (tmp_path/'hashes.py').write_text('import hashlib\nhashlib.md5(b"cache", usedforsecurity=False)\nhashlib.md5(password)\n')
    result = pipeline.run(tmp_path, 'purpose')
    assert {(a.variant, a.tier) for a in result.assets} == {('MD5', 'critical'), ('MD5 (declared non-security)', 'low')}
    (tmp_path/'hashes.py').write_text('import hashlib\nhashlib.md5(b"cache", usedforsecurity=False); hashlib.md5(password)\n')
    assert all(a.tier == 'critical' for a in pipeline.run(tmp_path, 'mixed').assets)


def test_web_signer_table_resolution_and_mutation_trap(tmp_path):
    import pytest
    pytest.importorskip('tree_sitter_typescript')
    source = '''import { ml_dsa44, ml_dsa65 } from './ml-dsa.js';
const cases = [[ml_dsa44, 80], [ml_dsa65, 55]] as const;
for (const [dsa, count] of cases) { dsa.sign(msg); }
'''
    path = tmp_path/'sign.ts'
    path.write_text(source)
    result = pipeline.run(tmp_path, 'signers')
    assert not any(a.algo == 'DSA' for a in result.assets)
    assert {'ML-DSA-44', 'ML-DSA-65'} <= {a.algo for a in result.assets}
    path.write_text(source.replace('for (', 'cases.push([classicalDSA, 1]);\nfor ('))
    assert any(a.algo == 'DSA' for a in pipeline.run(tmp_path, 'mutated').assets)
    path.write_text(source.replace('const cases', 'const ml_dsa44 = DSA;\nconst cases'))
    assert any(a.algo == 'DSA' for a in pipeline.run(tmp_path, 'shadowed').assets)
    path.write_text(source + '\nDSA.sign(secret);\n')
    assert any(a.algo == 'DSA' for a in pipeline.run(tmp_path, 'classical').assets)


def test_hybrid_composition_is_context_not_blanket_risk_downgrade(tmp_path):
    import pytest
    pytest.importorskip('tree_sitter_typescript')
    (tmp_path/'hybrid.ts').write_text('import { ml_kem768 } from "./ml-kem.js";\nfunction build() { return combine(ml_kem768, _ecdhKem(p256)); }\nfunction old() { return _ecdhKem(p256); }')
    asset = next(a for a in pipeline.run(tmp_path, 'hybrid').assets if a.algo == 'ECDH')
    assert asset.tier == 'high'
    assert len(asset.params['hybrid_context']) == 1
    assert asset.params['hybrid_context'][0]['line'] == 2
    assert 'standalone' in asset.why


def test_password_hasher_recommendation_is_not_a_plain_hash_replacement(tmp_path):
    source = 'import hashlib\nclass MD5PasswordHasher:\n def encode(self, password): return hashlib.md5(password).hexdigest()\n'
    (tmp_path/'hashers.py').write_text(source)
    result = pipeline.run(tmp_path, 'password')
    asset = next(a for a in result.assets if a.params.get('purpose') == 'password')
    assert asset.tier == 'critical' and 'Argon2id' in asset.action
    assert 'not sufficient' in asset.action
    (tmp_path/'hashers.py').write_text(source.replace('MD5PasswordHasher', 'CacheHasher'))
    assert not any(a.params.get('purpose') == 'password' for a in pipeline.run(tmp_path, 'trap').assets)


def test_cache_hash_inside_password_hasher_is_not_password_hashing(tmp_path):
    (tmp_path / 'hashers.py').write_text('import hashlib\nclass MD5PasswordHasher:\n def cache(self, body): return hashlib.md5(body, usedforsecurity=False).hexdigest()\n')
    assets = pipeline.run(tmp_path, 'cache').assets
    assert not any(a.params.get('purpose') == 'password' for a in assets)
    assert any(a.algo == 'MD5' and a.tier == 'low' for a in assets)
