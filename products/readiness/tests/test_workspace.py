"""Unified scans keep evidence private and preserve optional capability boundaries."""
import json
import os

import pytest

from acxelin_readiness.workspace import append_history, scan


def fixture(root):
    (root / 'keys.py').write_text('from cryptography.hazmat.primitives.asymmetric import rsa\ndef make():\n return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    (root / 'api.py').write_text('from keys import make\ndef payment():\n return make()\n# PRIVATE_SENTINEL\n')


def test_scan_exports_and_history_have_evidence_without_source(tmp_path):
    fixture(tmp_path)
    stages = []
    out = tmp_path / 'out'
    history = tmp_path / 'history.json'
    result = scan(tmp_path, out, history, stages.append)
    assert stages[-1] == 'Complete'
    assert result['summary']['resolved_calls'] == 1
    assert any(a['impact'] and 'api.py#payment' in a['impact']['callers'] for a in result['assets'])
    for f in out.iterdir():
        assert 'PRIVATE_SENTINEL' not in f.read_text()
        if os.name != 'nt':
            assert f.stat().st_mode & 0o777 == 0o600
    rows = json.loads(history.read_text())
    assert set(rows[0]) == {'project', 'finished', 'summary'}
    for _ in range(102):
        append_history(history, result)
    assert len(json.loads(history.read_text())) == 100


def test_security_patterns_are_listed_without_source_or_secret_values(tmp_path):
    (tmp_path / 'client.py').write_text('import requests\nAPI_SECRET = "Zq8vN3kLp0RtX2"\nrequests.get("https://bank", verify=False)\n')
    out = tmp_path / 'out'
    result = scan(tmp_path, out)
    assert {(p['rule'], p['line']) for p in result['patterns']} == {('WPC001', 3), ('WPC002', 2)}
    assert result['summary']['security_patterns'] == 2
    assert all('snippet' not in p for p in result['patterns'])
    for f in out.iterdir():
        assert 'Zq8vN3kLp0RtX2' not in f.read_text()










def test_bad_history_does_not_discard_successful_scan(tmp_path):
    fixture(tmp_path)
    history=tmp_path/'history.json'; history.write_text('{')
    result=scan(tmp_path, out=tmp_path/"out", history=history)
    assert json.loads((tmp_path/"out/assessment.json").read_text())["notes"] == result["notes"]
    assert result['summary']['resolved_calls']==1
    assert any('History could not be saved' in n for n in result['notes'])
    assert history.read_text()=='{'


def test_history_read_limit_and_private_lock_symlink(tmp_path):
    from acxelin_readiness.workspace import read_history
    history=tmp_path/'history.json'; history.write_bytes(b' '*1_000_001)
    with pytest.raises(ValueError, match='1 MB'):
        read_history(history)
    outside=tmp_path/'private'; outside.write_text('UNCHANGED')
    (tmp_path/'.history.json.lock').symlink_to(outside)
    if os.name != 'nt':
        with pytest.raises(OSError):
            append_history(history, {'project':'a','finished':1,'summary':{}})
        assert outside.read_text()=='UNCHANGED'


def test_history_updates_are_preserved_across_processes(tmp_path):
    import subprocess
    import sys
    from acxelin_readiness.workspace import read_history
    history=tmp_path/'history.json'
    script='from acxelin_readiness.workspace import append_history; import sys; [append_history(sys.argv[1], {"project":sys.argv[2]+"-"+str(i), "finished":i, "summary":{}}) for i in range(20)]'
    children=[subprocess.Popen([sys.executable,'-c',script,str(history),str(i)]) for i in range(3)]
    try:
        assert [child.wait(timeout=30) for child in children]==[0,0,0]
        assert len({r['project'] for r in read_history(history)})==60
    finally:
        for child in children:
            if child.poll() is None:
                child.kill(); child.wait()


def test_workspace_rescan_tracking_missing_reappearing_and_privacy(tmp_path):
    from acxelin_readiness.workspace import ProjectStore
    repo = tmp_path/'repo'; repo.mkdir(); fixture(repo)
    store = ProjectStore(tmp_path/'private'/'workspace.json')
    first = store.save(repo, scan(repo))
    assert not first['comparison']['baseline']
    finding = first['assets'][0]['id']
    store.track(repo, {'finding': finding, 'owner':'Payments', 'status':'in_progress', 'due':'2099-01-01'})
    (repo/'keys.py').write_text('\n\n'+(repo/'keys.py').read_text())
    second = store.save(repo, scan(repo))
    assert second['assets'][0]['id'] == finding
    assert second['assets'][0]['tracking']['owner'] == 'Payments'
    assert second['comparison']['new'] == 0
    (repo/'keys.py').write_text('def make(): return None\n')
    third = store.save(repo, scan(repo))
    assert third['comparison']['not_observed'] > 0
    assert any(a['id'] == finding for a in third['not_observed'])
    fixture(repo)
    fourth = store.save(repo, scan(repo))
    assert fourth['assets'][0]['tracking']['owner'] == 'Payments'
    assert not fourth['not_observed']
    assert len(ProjectStore(store.path).assessment(repo)['history']) == 4
    assert 'PRIVATE_SENTINEL' not in store.path.read_text()
    if os.name != 'nt':
        assert store.path.stat().st_mode & 0o777 == 0o600




def test_workspace_invalid_updates_limits_and_competing_writers(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from acxelin_readiness.workspace import ProjectStore
    fixture(tmp_path)
    store = ProjectStore(tmp_path/'workspace.json')
    assessment = store.save(tmp_path, scan(tmp_path))
    finding = assessment['assets'][0]['id']
    valid = {'finding':finding, 'owner':'team', 'status':'exception', 'until':'2099-01-01', 'reason':'review'}
    for bad in ({'status':'done'}, {'until':'2000-01-01'}, {'reason':''}, {'finding':[]}, {'finding':'unknown'}, {'due':'not-a-date'}, {'owner':'x'*121}):
        with pytest.raises(ValueError):
            store.track(tmp_path, valid | bad)
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(lambda i: store.register(tmp_path, str(i)), range(30)))
    assert len(store.read()['registrations'][store.key(tmp_path)]) == 30
    store.track(tmp_path, valid)
    before = store.path.read_bytes()
    store.LIMIT = 1
    with pytest.raises(ValueError):
        store.register(tmp_path, 'refuse')
    assert store.path.read_bytes() == before
    store.LIMIT = 16_000_000
    store.path.write_text('{')
    with pytest.raises(ValueError):
        store.register(tmp_path, 'refuse')
    assert store.path.read_text() == '{'


def test_cancel_and_budget_never_replace_completed_outputs(tmp_path):
    import threading
    from acxelin_readiness.workspace import ScanStopped
    fixture(tmp_path)
    out = tmp_path/'out'
    scan(tmp_path, out=out)
    before = (out/'assessment.json').read_bytes()
    cancelled = threading.Event(); cancelled.set()
    for options in ({'cancel':cancelled}, {'max_files':1}, {'max_bytes':1}, {'timeout':-1}):
        with pytest.raises(ScanStopped):
            scan(tmp_path, out=out, **options)
        assert (out/'assessment.json').read_bytes() == before


@pytest.mark.parametrize("directory", ["test_vectors", "lib/Crypto/SelfTest"])
def test_crypto_test_vectors_remain_visible_without_production_migration_candidates(tmp_path, directory):
    root = tmp_path / directory
    root.mkdir(parents=True)
    fixture(root)
    result = scan(tmp_path)
    assert result['assets']
    assert all(a['test_only'] for a in result['assets'])
    assert result['summary']['migration_candidates'] == 0
    # The same algorithm used in production must remain a migration candidate.
    fixture(tmp_path)
    mixed = scan(tmp_path)
    assert mixed['summary']['migration_candidates'] > 0
    assert any(not a['test_only'] for a in mixed['assets'])




def test_persisted_graph_compression_is_lossless_bounded_and_backward_compatible(tmp_path, monkeypatch):
    import base64
    import zlib
    from acxelin_readiness.workspace import ProjectStore
    fixture(tmp_path)
    store = ProjectStore(tmp_path/'state.json')
    original = scan(tmp_path)
    saved = store.save(tmp_path, original)
    assert saved['relationships'] == original['relationships']
    record = store.read()['projects'][store.key(tmp_path)]
    assert 'relationships' not in record['assessment'] and 'graph_zlib' in record
    legacy = dict(record, assessment=dict(record['assessment'], relationships=original['relationships']))
    del legacy['graph_zlib']
    assert store.view(legacy)['relationships'] == original['relationships']
    monkeypatch.setattr(ProjectStore, 'GRAPH_LIMIT', 100)
    for packed in ('bad!', base64.b64encode(zlib.compress(b' '*101)).decode(), base64.b64encode(zlib.compress(b'{}') + b'extra').decode()):
        with pytest.raises(ValueError, match='damaged or exceeds'):
            store.view(record | {'graph_zlib': packed})


def test_workspace_upgrades_legacy_version_and_refuses_unknown_version(tmp_path):
    from acxelin_readiness.workspace import ProjectStore
    path = tmp_path / 'workspace.json'
    path.write_text(json.dumps({'version': 1, 'registrations': {}, 'projects': {}}))
    store = ProjectStore(path)
    assert store.read()['version'] == 1
    store.register(tmp_path, 'repo')
    assert store.read()['version'] == 2
    path.write_text(json.dumps({'version': 3, 'registrations': {}, 'projects': {}}))
    with pytest.raises(ValueError, match='Invalid project workspace'):
        store.read()


def test_scan_command_names_what_to_change_first(tmp_path, capsys):
    from acxelin_readiness import cli
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                              "def make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    assert cli.main(["scan", str(tmp_path / "app"), "-o", str(tmp_path / "out")]) == 0
    out = capsys.readouterr().out
    assert "high" in out and "RSA-2048" in out and "ML-DSA-65" in out
    assert "keys.py" in (tmp_path / "out" / "report.html").read_text()
    assert (tmp_path / "out" / "cbom.json").exists()
