import sys
import unittest
from pathlib import Path

from acxelin_readiness import pipeline, cbom
from acxelin_readiness.catalog import lookup, parse_transformation, curve
from acxelin_readiness.detectors.suites import cipher_string, ssh_token, sig_scheme

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
sys.path.insert(0, str(Path(__file__).resolve().parent))


class Catalog(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(lookup("DESede"), "3DES")
        self.assertEqual(lookup("mlkem768x25519-sha256"), "X25519MLKEM768")
        self.assertEqual(parse_transformation("AES/ECB/PKCS5Padding"), ("AES", {"mode": "ECB", "padding": "pkcs5"}))
        self.assertEqual(curve("NID_X9_62_prime256v1"), "P-256")
        self.assertEqual(lookup("SHA-512/256"), "SHA-512/256")  # its own entry: a 256-bit output is not SHA-512's strength
        self.assertEqual(lookup("HMACSHA1"), "HMAC")

    def test_generated_report_has_an_embedded_favicon(self):
        from acxelin_readiness.brand import page
        self.assertIn('<link rel="icon" href="data:image/svg+xml;base64,', page("Sample", "", "", "", "", ""))


class Image(unittest.TestCase):
    @staticmethod
    def layer(files, gz=False):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def archive(self, path, members):
        import io
        import tarfile
        with tarfile.open(path, "w") as t:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))

    def test_docker_save_layers_and_whiteouts(self):
        import json
        import tempfile
        from acxelin_readiness import image
        base = self.layer({"app/old.py": b"import hashlib\nhashlib.md5(b'x')\n", "../escape.py": b"import hashlib\nhashlib.sha1(b'x')\n"})
        top = self.layer({"app/.wh.old.py": b"", "app/new.py": b"import hashlib\nhashlib.sha256(b'x')\n"}, gz=True)
        with tempfile.TemporaryDirectory() as d:
            tar = Path(d) / "img.tar"
            self.archive(tar, {"manifest.json": json.dumps([{"Layers": ["a/layer.tar", "b/layer.tar"]}]).encode(), "a/layer.tar": base, "b/layer.tar": top})
            self.assertTrue(image.is_image(tar))
            root = Path(d) / "root"
            notes = image.unpack(tar, root)
            self.assertIn("2 layer(s)", notes[0])
            self.assertEqual(sorted(p.relative_to(root).as_posix() for p in root.rglob("*.py")), ["app/new.py"])
            self.assertEqual({s.algo for s in pipeline.run(root, "img").detections if s.verdict == "accepted"}, {"SHA-256"})

    def test_oci_layout(self):
        import hashlib
        import json
        import tempfile
        from acxelin_readiness import image
        layer = self.layer({"srv/app.py": b"import hashlib\nhashlib.sha512(b'x')\n"}, gz=True)
        digest = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
        man = json.dumps({"layers": [{"digest": digest(layer)}]}).encode()
        idx = json.dumps({"manifests": [{"digest": digest(man)}]}).encode()
        with tempfile.TemporaryDirectory() as d:
            tar = Path(d) / "oci.tar"
            self.archive(tar, {"oci-layout": b"{}", "index.json": idx, "blobs/" + digest(man).replace(":", "/"): man,
                               "blobs/" + digest(layer).replace(":", "/"): layer})
            image.unpack(tar, Path(d) / "root")
            self.assertTrue((Path(d) / "root/srv/app.py").exists())


class Policy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = pipeline.run(CORPUS, "corpus")

    def evaluate(self, policy, year=2026):
        from datetime import date
        from acxelin_readiness import compliance
        for a in self.r.assets:
            a.policy = []
        return compliance.evaluate(self.r.assets, self.r.endpoints, policy, date(year, 1, 1))

    def test_nist_status_names_the_real_problem(self):
        from acxelin_readiness.catalog import nist_status
        self.assertEqual(nist_status("AES", {"key_size": 256, "mode": "GCM"}), "Quantum-safe")
        self.assertIn("prefer 256-bit", nist_status("AES", {"key_size": 128, "mode": "GCM"}))
        self.assertIn("prefer 256-bit", nist_status("AES", {"mode": "GCM"}), "an unknown key size is not assumed to be 256-bit")
        self.assertIn("ECB", nist_status("AES", {"key_size": 256, "mode": "ECB"}))

    def test_nist_ir_8547_dates(self):
        c = self.evaluate({"profiles": ["nist-ir-8547"]})
        by = {(v["rule"], v["asset"]): v for v in c["violations"]}
        self.assertTrue(by["NIST SP 800-131A", "MD5"]["overdue"])
        self.assertEqual(by["NIST IR 8547", "RSA-2048"]["deadline"], 2030)
        self.assertFalse(by["NIST IR 8547", "RSA-2048"]["overdue"])
        self.assertTrue(self.evaluate({"profiles": ["nist-ir-8547"]}, 2031)["overdue"] > c["overdue"])
        self.assertFalse(any(v["asset"].startswith(("ML-KEM", "AES-256")) for v in c["violations"]))

    def test_cnsa_accepts_only_its_suite(self):
        bad = {v["asset"] for v in self.evaluate({"profiles": ["cnsa-2.0"]})["violations"]}
        self.assertIn("AES-128-GCM", bad)
        self.assertIn("SHA-256", bad)
        self.assertNotIn("SHA-384", bad)
        self.assertFalse({a for a in bad if a.startswith("ML-KEM-1024")})

    def test_own_rules_and_exemptions(self):
        c = self.evaluate({"forbid": ["md5"], "min_bits": {"RSA": 3072}, "require_hybrid": True})
        rules = {(v["rule"], v["asset"]) for v in c["violations"]}
        self.assertIn(("policy: forbid", "MD5"), rules)
        self.assertIn(("policy: min_bits", "RSA-2048"), rules)
        self.assertFalse(c["passed"])

    def test_tests_and_declared_non_security_uses_break_no_rule(self):
        import tempfile
        from acxelin_readiness import compliance
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tests").mkdir()
            (Path(d) / "tests" / "test_vectors.py").write_text("import hashlib\nhashlib.sha1(b'abc')\n")
            (Path(d) / "cache.py").write_text("import hashlib\nkey = hashlib.md5(b'x', usedforsecurity=False)\n")
            r = pipeline.run(d, "t")
            self.assertEqual({a.algo for a in r.assets}, {"SHA-1", "MD5"})
            self.assertEqual(compliance.evaluate(r.assets, [], {"profiles": ["nist-ir-8547"], "forbid": ["MD5", "SHA-1"]})["violations"], [])

    def test_settings_are_checked_and_gate_ci(self):
        import tempfile
        from acxelin_readiness import compliance
        from acxelin_readiness.cli import main
        self.assertTrue(compliance.check({"profiles": ["fips-9999"]}))
        self.assertTrue(compliance.check({"forbid": "md5"}))
        self.assertTrue(compliance.check({"min_bits": {"RSA": "3072"}}))
        self.assertEqual(compliance.check({"profiles": ["cnsa-2.0"], "min_bits": {"RSA": 3072}, "fail": True}), [])
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "p.toml"
            cfg.write_text('[policy]\nforbid = ["MD5"]\nfail = true\n')
            with self.assertRaises(SystemExit) as cm:
                main(["scan", str(CORPUS), "-o", d, "-q", "--config", str(cfg)])
            self.assertEqual(cm.exception.code, 2)
            cfg.write_text('[policy]\nforbid = ["Kyber-9"]\nfail = true\n')
            self.assertEqual(main(["scan", str(CORPUS), "-o", d, "-q", "--config", str(cfg)]), 0)


class Remedy(unittest.TestCase):
    def test_fixes_match_where_each_asset_was_found(self):
        r = pipeline.run(CORPUS, "corpus")
        fix = {a.variant: a.remedies for a in r.assets}
        self.assertIn(("python", "use SHA-256 or stronger: `hashlib.sha256()`"), fix["MD5"])
        self.assertTrue(any(w == "nginx" and "X25519MLKEM768" in f for w, f in fix["ECDH"]))
        self.assertTrue(fix["AES-ECB"], "ECB mode still gets a concrete fix")
        self.assertEqual(fix.get("ML-KEM-768"), [])
        b = cbom.build("corpus", r.assets, r.artifacts, r.libraries)
        props = [p for c in b["components"] for p in c.get("properties", []) if p["name"] == "acxelin:remediation"]
        self.assertTrue(props)


class Inventory(unittest.TestCase):
    def test_merge_ranks_systems_and_estimates_foreign_cboms(self):
        import json
        import tempfile
        from acxelin_readiness import inventory
        from acxelin_readiness.cli import main
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            main(["scan", str(CORPUS), "-o", str(d / "corpus"), "--name", "corpus", "-q"])
            (d / "other").mkdir()
            (d / "other" / "cbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "billing"}}, "components": [
                    {"type": "cryptographic-asset", "name": "RSA-1024", "cryptoProperties": {"assetType": "algorithm"}},
                    {"type": "cryptographic-asset", "name": "AES128-GCM", "cryptoProperties": {"assetType": "algorithm"}}]}))
            systems = inventory.run([d], "Acme", d / "inv")
            by = {s["name"]: s for s in systems}
            self.assertEqual(set(by), {"corpus", "billing"})
            self.assertTrue(by["billing"]["readiness"]["estimated"])
            self.assertEqual({a["name"]: a["tier"] for a in by["billing"]["assets"]}, {"RSA-1024": "critical", "AES128-GCM": "low"})
            self.assertFalse(by["corpus"]["readiness"]["estimated"])
            bom = json.loads((d / "inv" / "cbom.json").read_text())
            refs = {c["bom-ref"] for c in bom["components"]}
            self.assertTrue({"system/corpus", "system/billing"} <= refs)
            self.assertTrue(any(c["name"] == "RSA-1024" and c["bom-ref"].startswith("algorithm/") for c in bom["components"]))
            self.assertEqual(bom["dependencies"][0], {"ref": "organisation", "dependsOn": ["system/corpus", "system/billing"]})
            self.assertIn("Where each algorithm is used", (d / "inv" / "inventory.html").read_text())
            with self.assertRaises(SystemExit) as cm:
                main(["merge", str(d / "other"), "-o", str(d / "gate"), "-q", "--fail-on", "critical"])
            self.assertEqual(cm.exception.code, 2)


class Capture(unittest.TestCase):
    def scan(self, frames):
        import tempfile
        import pcapgen
        from acxelin_readiness.detectors import capture
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "traffic.pcap"
            f.write_bytes(pcapgen.pcap(frames))
            return capture.scan(f)

    def test_tls13_hybrid_and_tls12_ecdhe(self):
        import pcapgen
        s, eps, _ = self.scan(pcapgen.tls_capture([0x11EC, 0x001D], pcapgen.server_hello(0x1301, group=0x11EC)))
        self.assertEqual(eps[0]["pq_groups"], ["X25519MLKEM768"])
        self.assertEqual(eps[0]["clients_offering_pq"], 1)
        self.assertTrue({"TLS 1.3", "X25519MLKEM768", "AES"} <= {x.algo for x in s})
        s, eps, _ = self.scan(pcapgen.tls_capture([0x0017], pcapgen.server_hello(0xC02F, version=0x0303), pcapgen.server_key_exchange(0x0017)))
        self.assertEqual(eps[0]["version"], "TLSv1.2")
        self.assertEqual(eps[0]["pq_groups"], [])
        self.assertTrue({"TLS 1.2", "ECDH", "RSA", "AES"} <= {x.algo for x in s})

    def test_ssh_agreed_algorithms(self):
        import pcapgen
        s, eps, _ = self.scan(pcapgen.ssh_capture("mlkem768x25519-sha256,curve25519-sha256", "curve25519-sha256,diffie-hellman-group14-sha256"))
        self.assertEqual(eps[0]["preferred_group"], "curve25519-sha256")
        self.assertEqual(eps[0]["pq_groups"], [])
        self.assertEqual(eps[0]["clients_offering_pq"], 1)
        self.assertIn("RSA", {x.algo for x in s})
        self.assertNotIn("Ed25519", {x.algo for x in s})

    def test_not_a_capture(self):
        from acxelin_readiness.detectors import capture
        with self.assertRaises(ValueError):
            list(capture.packets(b"hello world, not a pcap"))


class Operations(unittest.TestCase):
    def test_history_keeps_one_row_per_day(self):
        import json
        import tempfile
        from acxelin_readiness import inventory
        from acxelin_readiness.cli import main
        with tempfile.TemporaryDirectory() as d:
            main(["scan", str(CORPUS / "config"), "-o", str(Path(d) / "s"), "-q"])
            h = Path(d) / "h.jsonl"
            h.write_text(json.dumps({"date": "2026-01-01", "systems": 1, "pq_ready_percent": 0, "critical": 1, "high": 0, "breaches": 0}) + "\n")
            inventory.run([Path(d) / "s"], "Acme", Path(d) / "inv", h)
            inventory.run([Path(d) / "s"], "Acme", Path(d) / "inv", h)
            self.assertEqual(len(h.read_text().splitlines()), 2)
            self.assertIn("Readiness over time", (Path(d) / "inv" / "inventory.html").read_text())

    def test_changed_since_reads_only_changed_files(self):
        import subprocess
        import tempfile
        from acxelin_readiness.cli import changed_files
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
            git("init", "-q")
            (Path(d) / "old.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
            git("add", ".")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one")
            (Path(d) / "new.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
            only = changed_files(Path(d), "HEAD")
            self.assertEqual(only, {"new.py"})
            from acxelin_readiness.detectors import Scope
            r = pipeline.run(d, "t", scope=Scope(only=only))
            self.assertEqual({a.algo for a in r.assets}, {"SHA-1"})


class Formats(unittest.TestCase):
    def test_noise_and_jose(self):
        from acxelin_readiness.detectors.suites import noise_name, jose_alg
        self.assertEqual([a for a, _ in noise_name("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")], ["X25519", "ChaCha20-Poly1305", "BLAKE2"])
        self.assertEqual([a for a, _ in jose_alg("PBES2-HS512+A256KW")], ["PBKDF2", "AES"])
        self.assertEqual(jose_alg("dir"), [])

    def test_kms_key_specs(self):
        from acxelin_readiness.detectors.suites import kms_spec
        self.assertEqual(kms_spec("RSA_SIGN_PSS_3072_SHA256")[0], ("RSA", {"key_size": 3072, "hash": "SHA-256"}))
        self.assertEqual(kms_spec("ECC_NIST_P384"), [("ECC", {"curve": "P-384"})])
        self.assertEqual(kms_spec("ENCRYPT_DECRYPT"), [])

    def test_hashlib_reference_counts_unless_only_compared(self):
        from acxelin_readiness.detectors.pysrc import scan_python
        found = {a for a, *_ in scan_python("x.py", "import hashlib\ndef f(d=hashlib.sha1):\n    if d in [hashlib.md5]:\n        pass\n")}
        self.assertEqual(found, {"SHA-1"})


class Suites(unittest.TestCase):
    def test_negations_are_ignored(self):
        algos = {a for a, _ in cipher_string("ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4")}
        self.assertEqual(algos, {"ECDH", "RSA", "AES", "SHA-256"})

    def test_ssh(self):
        self.assertEqual(ssh_token("diffie-hellman-group1-sha1")[0], ("DH", {"key_size": 1024}))
        self.assertEqual(ssh_token("-3des-cbc"), [])

    def test_sig(self):
        self.assertEqual([a for a, _ in sig_scheme("SHA1withRSA")], ["RSA", "SHA-1"])


class Pack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = pipeline.run(CORPUS, "corpus")

    def accepted(self, f):
        return {s.algo for s in self.r.detections if s.file == f and s.verdict == "accepted"}

    def test_cloud_kms_keys_but_not_retired_ones_in_comments(self):
        self.assertEqual(self.accepted("infra/kms.tf"), {"RSA", "AES", "ECDSA", "SHA-256"})
        sizes = {s.params.get("key_size") for s in self.r.detections if s.file == "infra/kms.tf" and s.verdict == "accepted" and s.algo == "RSA"}
        self.assertEqual(sizes, {2048, 3072})

    def test_traps_rejected(self):
        self.assertEqual(self.accepted("py/notes.py"), set())
        self.assertEqual(self.accepted("config/java.security"), set())
        self.assertNotIn("DES", self.accepted("java/TokenSigner.java"))

    def test_runtime_name_prefix_is_not_an_algorithm(self):
        self.assertEqual(self.accepted("java/Digests.java"), {"SHA-256"})

    def test_split_literal_shares_fate_but_neighbours_do_not(self):
        self.assertEqual(self.accepted("py/token_kind.py"), {"RSA", "SHA-256"})

    def test_jwt_default_only_when_algorithm_is_absent(self):
        self.assertEqual(self.accepted("py/jwt_calls.py"), {"ECDSA", "SHA-256"})

    def test_hmac_and_kdf_report_their_hash(self):
        self.assertEqual(self.accepted("java/Macs.java"), {"HMAC", "SHA-256", "PBKDF2", "SHA-1"})

    def test_libsodium_calls_but_not_its_size_constants(self):
        self.assertEqual(self.accepted("c/sodium.c"), {"BLAKE2", "Ed25519", "scrypt", "Salsa20"})
        self.assertEqual(self.accepted("c/sodium_api.h"), set())

    def test_names_that_are_not_algorithms(self):
        self.assertEqual(self.accepted("js/hmac_bits.js"), {"HMAC"})
        self.assertEqual(self.accepted("go/flags.go"), set())
        self.assertEqual(self.accepted("cs/Blob.cs"), set())

    def test_implementations_by_their_constants(self):
        self.assertEqual(self.accepted("c/keccak.c"), {"SHA-3"})
        self.assertEqual(self.accepted("c/md5_impl.c"), {"MD5"})
        self.assertEqual(self.accepted("c/ripemd160_impl.c"), {"RIPEMD-160"})
        self.assertEqual(self.accepted("go/sm4.go"), {"SM4"})

    def test_one_constant_table_for_source_and_binaries(self):
        import tempfile
        from acxelin_readiness.detectors import binary, implementations
        p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "k1.c").write_text(f"static const char P[] = \"{p}\";\n", encoding="utf-8")
            (Path(d) / "k1.so").write_bytes(b"\x7fELF" + bytes.fromhex(p)[::-1])
            src = implementations.scan(d)[0]
            bins = binary.scan(d)[0]
        self.assertEqual({(s.algo, s.params["curve"]) for s in src + bins}, {("ECC", "secp256k1")})
        self.assertEqual(len(bins), 1)

    def test_sodium_bindings_sjcl_and_extensionless_config(self):
        self.assertEqual(self.accepted("cs/SodiumInterop.cs"), set())
        self.assertEqual(self.accepted("cs/SodiumUse.cs"), {"Ed25519", "BLAKE2"})
        self.assertEqual(self.accepted("js/sjcl_use.js"), {"PBKDF2", "AES"})
        self.assertIn("TLS 1.2", self.accepted("config/tls"))
        self.assertEqual(self.accepted("config/NOTES"), set())
        self.assertEqual(self.accepted("js/perf.js"), set())

    def test_keys_by_variable_or_numbers_and_library_digests(self):
        self.assertEqual(self.accepted("java/Codec.java"), {"SHA-256", "MD5"})
        self.assertEqual(self.accepted("go/keygen.go"), {"RSA", "ECDSA"})
        self.assertEqual(self.accepted("cs/Kdf.cs"), {"HMAC", "SHA-512", "ECDH"})
        self.assertEqual(self.accepted("py/tpm_keys.py"), {"RSA", "ECC"})

    def test_second_look(self):
        self.assertIn("SHA-1", self.accepted("java/Hasher.java"))
        self.assertNotIn("AES", self.accepted("java/Hasher.java"))

    def test_tiers(self):
        t = {a.variant: a.tier for a in self.r.assets}
        self.assertEqual(t["AES-ECB"], "critical")
        self.assertEqual(t["ML-KEM-768"], "ok")
        self.assertEqual(t["TLS 1.3"], "high")

    def test_tls13_is_ok_only_where_a_hybrid_group_is_configured_with_it(self):
        from acxelin_readiness.detectors import Scope
        hybrid = pipeline.run(CORPUS / "config", "c", scope=Scope(exclude=("tls", "haproxy.cfg")))
        self.assertEqual({a.variant: a.tier for a in hybrid.assets}["TLS 1.3"], "ok")

    def test_cbom_shape(self):
        b = cbom.build("corpus", self.r.assets, self.r.artifacts, self.r.libraries)
        self.assertEqual(b["specVersion"], "1.6")
        kinds = {c["cryptoProperties"]["assetType"] for c in b["components"] if c["type"] == "cryptographic-asset"}
        self.assertTrue({"algorithm", "protocol", "certificate", "related-crypto-material"} <= kinds)



class Pack2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = pipeline.run(CORPUS, "corpus")

    def verdicts(self, f):
        return {(s.algo, s.verdict) for s in self.r.detections if s.file == f}

    def test_suppression(self):
        self.assertIn(("MD5", "suppressed"), self.verdicts("py/suppressed.py"))

    def test_registry_but_not_denylist(self):
        v = self.verdicts("py/policy.py")
        self.assertIn(("AES", "accepted"), v)
        self.assertIn(("MD5", "quarantined"), v)

    def test_binary_constants(self):
        self.assertTrue({("AES", "accepted"), ("MD5", "accepted")} <= self.verdicts("bin/legacy_tool"))

    def test_deployed_trail(self):
        a = next(x for x in self.r.assets if x.variant == "RSA-2048")
        self.assertEqual(a.exposure, "deployed key or certificate")

    def test_library_provides(self):
        b = cbom.build("corpus", self.r.assets, self.r.artifacts, self.r.libraries)
        prov = {d["ref"]: d.get("provides", []) for d in b["dependencies"]}
        self.assertIn("crypto/ML-KEM-768", prov["lib/pypi/liboqs-python"])


class Detectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = pipeline.run(CORPUS, "corpus")

    def accepted(self, off, f):
        return {s.algo for s in self.result.detections if s.file == f and s.verdict == "accepted"}



    def test_names_find_code_named_for_its_algorithm_but_not_declarations(self):
        self.assertEqual(self.accepted((), "c/blowfish_impl.c"), {"Blowfish"})
        self.assertEqual(self.accepted((), "c/cipher_api.h"), set())
        self.assertEqual(self.accepted((), "java/PasswordStore.java"), {"Argon2"})

    def test_javascript_imports_carry_constants_across_modules(self):
        self.assertEqual(self.accepted((), "js/checksum.js"), {"SHA-1"})
        self.assertEqual(self.accepted((), "js/settings.js"), {"SHA-1"})

    def test_symbols_count_used_constants_but_not_sizes_flags_declarations_or_refusals(self):
        self.assertEqual(self.accepted((), "c/kex_table.c"), {"Ed25519", "DH", "SHA-256"})
        self.assertEqual(self.accepted((), "cs/AlgFactory.cs"), {"HMAC", "SHA-256"})

    def test_lists_are_declared_support_calls_are_used(self):
        r = pipeline.run(CORPUS, "corpus")
        declared = {a.variant for a in r.assets if a.declared}
        self.assertIn("AES-128-CTR", declared)
        self.assertNotIn("MD5", declared)
        self.assertTrue(all("declared" in s.context for a in r.assets if a.declared for s in a.detections))

    def test_parameters_carry_literals_from_call_sites_to_the_api(self):
        self.assertEqual(self.accepted((), "java/DigestUtil.java"), {"SHA-512"})
        from acxelin_readiness.detectors.params import params_of
        self.assertEqual(params_of("byte[] data, final String algorithm"), ["data", "algorithm"])
        self.assertEqual(params_of("self, name: str = 'sha256', *, n=1"), ["self", "name", "n"])

    def test_cloud_and_kubernetes_tls(self):
        self.assertIn("RSA", self.accepted((), "infra/k8s.yaml"))
        self.assertEqual(self.accepted((), "infra/lb.tf"), {"TLS 1.2", "TLS 1.3"})
        from acxelin_readiness.detectors.config import lb_policy
        self.assertEqual([a for a, _ in lb_policy("ELBSecurityPolicy-2016-08")], ["TLS 1.0", "TLS 1.1", "TLS 1.2"])
        self.assertIn("X25519MLKEM768", [a for a, _ in lb_policy("ELBSecurityPolicy-TLS13-1-2-PQ-2025-09")])

    def test_swift_and_php(self):
        self.assertTrue({"ECDSA", "ChaCha20-Poly1305", "HMAC", "RSA"} <= self.accepted((), "swift/Crypto.swift"))
        self.assertTrue({"HMAC", "RSA", "bcrypt"} <= self.accepted((), "php/crypto.php"))
        from acxelin_readiness.detectors import names
        self.assertEqual(names.algos("hash_hmac"), ["HMAC"])
        self.assertEqual(list(names.scan("x = hash_hmac(a);", "c", "a.php")), [(1, "HMAC")])
        self.assertEqual(list(names.scan("if (isRsaKey(k)) {}", "java", "A.java")), [])

    def test_concat_keeps_only_complete_parts(self):
        self.assertEqual(self.accepted((), "js/runtime_names.js"), {"RSA"})

    def test_lists_read_multiline_entries_and_skip_denied_ones(self):
        self.assertEqual(self.accepted((), "yaml/gateway.yaml"), {"TLS 1.2", "ECDH", "ECDSA", "AES", "SHA-384", "ChaCha20-Poly1305"})

    def test_flow_follows_byte_literals_and_branches(self):
        self.assertIn("X25519", self.accepted((), "py/jwe_use.py"))
        self.assertIn("AES", self.accepted((), "go/noise.go"))

    def test_propagation_recovers_key_size(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "k.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n\nKEY_BITS = 1024\n\n\n"
                                          "def make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)\n", encoding="utf-8")
            full = {a.variant: a.tier for a in pipeline.run(d, "k").assets}
        self.assertEqual(full.get("RSA-1024"), "critical")

    def test_format_sniffing_is_not_a_registry(self):
        self.assertEqual(self.accepted([], "py/keysniff.py"), {"ECC"})
        self.assertIn("AES", self.accepted([], "py/policy.py"))

    def test_cross_file_constant_resolves_by_owner(self):
        self.assertEqual(self.accepted([], "java/Keys.java"), {"AES"})

    def test_final_int_constant_gives_key_size_but_a_local_does_not(self):
        sizes = {s.params.get("key_size") for s in pipeline.run(CORPUS, "c").detections if s.file == "java/KeySizes.java" and s.verdict == "accepted"}
        self.assertEqual(sizes, {1024, None})

    def test_declared_non_security_hashes_rank_low_only_when_every_use_says_so(self):
        import tempfile
        declared = {(s.file, s.algo) for s in pipeline.run(CORPUS, "corpus").detections if s.params.get("purpose") == "non-security"}
        self.assertEqual(declared, {("py/checksums.py", "MD5"), ("py/checksums.py", "SHA-1")})
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "etag.py").write_text("import hashlib\nhashlib.md5(b, usedforsecurity=False)\n", encoding="utf-8")
            tier = lambda **k: {a.algo: a.tier for a in pipeline.run(d, "t", **k).assets}["MD5"]
            self.assertEqual(tier(), "low")
            (Path(d) / "login.py").write_text("import hashlib\nhashlib.md5(password)\n", encoding="utf-8")
            r = pipeline.run(d, "t")
            self.assertEqual({(a.variant, a.tier) for a in r.assets if a.algo == "MD5"},
                             {("MD5", "critical"), ("MD5 (declared non-security)", "low")})
            levels = {x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: x["level"]
                      for x in cbom.sarif(r.assets, [])["runs"][0]["results"]}
            self.assertEqual(levels, {"etag.py": cbom.LEVEL["low"], "login.py": cbom.LEVEL["critical"]})

    def test_a_bundle_of_self_signed_roots_is_one_trust_store_line(self):
        import shutil
        import tempfile
        r = pipeline.run(CORPUS, "corpus")
        self.assertEqual({s.file for s in r.detections if "trust-store" in s.context}, {"certs/roots.pem"})
        self.assertTrue(any(w.startswith("certs/chain.pem") for _, _, w, _ in r.alerts))
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(CORPUS / "certs" / "roots.pem", d)
            r = pipeline.run(d, "t")
            self.assertEqual({a.tier for a in r.assets if a.algo in ("RSA", "ECC", "ECDSA")}, {"low"})
            self.assertEqual([(sev, t) for sev, t, _, _ in r.alerts], [("info", "Trust store of 5 root certificates (3 RSA, 2 ECC); ranked low")])

    def test_python_this_interpreter_cannot_parse_is_named_in_the_notes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "old.py").write_text('import hashlib\nprint "digest", hashlib.md5(x).hexdigest()\n', encoding="utf-8")
            (Path(d) / "new.py").write_text("import hashlib\nhashlib.sha1(b)\n", encoding="utf-8")
            notes = pipeline.run(d, "t").notes
        self.assertTrue(any("1 Python file(s) could not be parsed" in n and "old.py" in n for n in notes), notes)

    def test_files_too_large_to_read_are_named_in_the_notes(self):
        import tempfile
        from acxelin_readiness.detectors import MAX_BYTES
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.min.js").write_text("x" * (MAX_BYTES + 1), encoding="utf-8")
            (Path(d) / "small.py").write_text("import hashlib\nhashlib.md5()\n", encoding="utf-8")
            notes = pipeline.run(d, "t").notes
            self.assertTrue(any("app.min.js" in n and "not read" in n for n in notes), notes)
            self.assertFalse([n for n in pipeline.run(Path(d) / "app.min.js", "t").notes if "not read" in n])

    def test_sha1_keeps_the_initial_values_it_shares_with_ripemd160(self):
        import tempfile
        from acxelin_readiness.detectors import binary, implementations
        iv = "0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0"
        rmd = "0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "sha1.c").write_text(f"H[] = {{{iv}}};\nK[] = {{0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6}};\n", encoding="utf-8")
            (Path(d) / "both.c").write_text(f"H[] = {{{iv}}};\nR[] = {{{rmd}}};\nK = 0xca62c1d6;\n", encoding="utf-8")
            (Path(d) / "rmd.so").write_bytes(b"\x7fELF" + b"".join(v.to_bytes(4, "little") for v in (0x67452301, 0xefcdab89, 0x98badcfe,
                                                     0x10325476, 0xc3d2e1f0, 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9)))
            found = {(s.file, s.algo) for s in implementations.scan(d)[0] + binary.scan(d)[0]}
        self.assertEqual(found, {("sha1.c", "SHA-1"), ("both.c", "SHA-1"), ("both.c", "RIPEMD-160"), ("rmd.so", "RIPEMD-160")})



class Probe(unittest.TestCase):
    def test_hello_retry_parsing(self):
        import socket, struct, threading
        from acxelin_readiness.detectors import probe
        body = b"\x03\x03" + probe.HRR + b"\x00" + b"\x13\x01" + b"\x00"
        exts = struct.pack(">HHH", 0x002B, 2, 0x0304) + struct.pack(">HHH", 0x0033, 2, 0x11EC)
        body += struct.pack(">H", len(exts)) + exts
        hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
        record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(32)
        port = srv.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                c.recv(4096)
                c.sendall(record)
                c.close()
        threading.Thread(target=serve, daemon=True).start()
        r = probe.tls_groups("127.0.0.1", port, 3)
        self.assertEqual(r["preferred"], "X25519MLKEM768")
        self.assertEqual(r["pq"], ["X25519MLKEM768"])
        from acxelin_readiness.detectors import tls
        sights, _, notes, ep = tls.probe(f"127.0.0.1:{port}", 3)
        srv.close()
        self.assertNotIn("error", ep)
        self.assertEqual(ep["pq_groups"], ["X25519MLKEM768"])
        self.assertTrue({"TLS 1.3", "X25519MLKEM768"} <= {s.algo for s in sights})
        self.assertIn("certificate, which TLS 1.3 encrypts, was not read", notes[0])


class Scope(unittest.TestCase):
    def test_test_and_benchmark_directories(self):
        from acxelin_readiness.detectors import is_test
        for p in ("UnitTestsNet46/jwk/JwkTest.cs", "src/Jose.Tests/A.cs", "benches/x25519.rs", "browserTest/perf.js", "tests/a.py", "src/itest/resources/id_ecdsa", "t/unit/security/__init__.py", "lib/Crypto/SelfTest/PublicKey/vector.pem", "test_vectors/wycheproof/rsa.json", "regress/rsa_openssh.pub", "test-ca/rsa-3072/ca.cert"):
            self.assertTrue(is_test(p), p)
        for p in ("src/contests/a.py", "src/attestation/a.py", "latest/a.go", "src/jwt/a.py", "src/digest/a.java", "wittest/a.py", "src/units/convert.py", "unit.py", "src/selftest_loader.py", "src/test_vectors_service/crypto.py", "src/progress/a.py", "testament/a.py"):
            self.assertFalse(is_test(p), p)


class Regressions(unittest.TestCase):

    def test_bare_sighting_joins_its_only_variant(self):
        from acxelin_readiness import verify
        from acxelin_readiness.model import Detection
        S = lambda f, line, ev, **p: Detection("RSA", f, line, ev, "t", params=p, verdict="accepted", confidence=.7)
        one = [S("a.py", 1, "import"), S("a.py", 5, "call", key_size=2048)]
        two = [S("b.py", 1, "import"), S("b.py", 5, "call", key_size=2048), S("b.py", 9, "call", key_size=4096)]
        self.assertEqual([a.variant for a in verify.assets(one)], ["RSA-2048"])
        self.assertEqual(sorted(a.variant for a in verify.assets(two)), ["RSA", "RSA-2048", "RSA-4096"])

    def test_ssh_probe_survives_early_close(self):
        import socket, threading
        from acxelin_readiness.detectors import tls
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve():
            c, _ = srv.accept()
            c.sendall(b"SSH-2.0-test\r\n")
            c.recv(100)
            c.shutdown(socket.SHUT_RDWR)
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        out = []
        t = threading.Thread(target=lambda: out.append(tls.probe_ssh(f"127.0.0.1:{srv.getsockname()[1]}", 3)), daemon=True)
        t.start()
        t.join(5)
        srv.close()
        self.assertFalse(t.is_alive())
        self.assertIn("error", out[0][3])

    def test_targets_as_people_write_them(self):
        from acxelin_readiness.detectors.tls import _split
        self.assertEqual(_split("[::1]", 443), ("::1", 443))
        self.assertEqual(_split("[::1]:8443", 443), ("::1", 8443))
        self.assertEqual(_split("https://bank.example/login", 443), ("bank.example", 443))
        self.assertEqual(_split("ssh://bank.example:2222", 22), ("bank.example", 2222))
        self.assertEqual(_split("::1", 443), ("::1", 443), "a port on an IPv6 address needs brackets")
        self.assertEqual(_split("2001:db8::1", 22), ("2001:db8::1", 22))
        from acxelin_readiness.endpoints import endpoint
        self.assertEqual(endpoint("::1"), ("tls", "::1", 443))
        self.assertEqual(endpoint("ssh://2001:db8::1"), ("ssh", "2001:db8::1", 22))
        self.assertEqual(endpoint("[2001:db8::1]:8443"), ("tls", "2001:db8::1", 8443))

    def test_nuget_without_inline_version(self):
        import tempfile
        from acxelin_readiness.detectors import deps
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.csproj").write_text('<PackageReference Include="BouncyCastle.Cryptography" />\n'
                                                '<PackageReference Include="NSec.Cryptography" Version="24.4.0" />', encoding="utf-8")
            libs = {(l.name, l.version) for l in deps.scan(d)}
        self.assertEqual(libs, {("bouncycastle.cryptography", ""), ("nsec.cryptography", "24.4.0")})

    def test_corrupt_jar_entry_is_skipped(self):
        import io, tempfile, zipfile
        from acxelin_readiness.detectors import binary
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Bad.class", b"javax/crypto" * 50)
            z.writestr("Good.class", b"javax/crypto\x00\x03MD5\x00")
        data = bytearray(buf.getvalue())
        i = data.find(b"Bad.class") + len("Bad.class")
        data[i + 2:i + 12] = b"\xff" * 10
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.jar").write_bytes(bytes(data))
            sights, _, _ = binary.scan(d)
        self.assertEqual({(s.algo, s.file) for s in sights}, {("MD5", "app.jar!Good.class")})

    def test_haproxy_min_version_counts_and_disabled_versions_do_not(self):
        import tempfile
        from acxelin_readiness.detectors import config
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "haproxy.cfg").write_text("global\n  ssl-default-bind-options ssl-min-ver TLSv1.0\n"
                                                 "frontend f\n  bind :443 ssl crt x.pem no-tlsv10 no-tlsv11 ssl-min-ver TLSv1.2\n", encoding="utf-8")
            s = config.scan(d)[0]
        self.assertEqual([(x.algo, x.line) for x in s], [("TLS 1.0", 2), ("TLS 1.2", 4)])

    def test_config_key_size_does_not_blank_curve(self):
        import tempfile
        from acxelin_readiness.detectors import config
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "keys.yaml").write_text("key_algorithm: ECDSA\nkey_size: 2048\n", encoding="utf-8")
            s = config.scan(d)[0]
        self.assertEqual([(x.algo, x.params) for x in s], [("ECDSA", {})])


class Operation(unittest.TestCase):
    def tree(self, d):
        for f, body in {"app/auth.py": "import hashlib\nhashlib.md5(b'x')\n", "gen/stub.py": "import hashlib\nhashlib.sha1(b'x')\n",
                        "app/ui.min.js": "crypto.createHash('sha1')\n", "docs/old/legacy.py": "import hashlib\nhashlib.md5(b'x')\n"}.items():
            (Path(d) / f).parent.mkdir(parents=True, exist_ok=True)
            (Path(d) / f).write_text(body, encoding="utf-8")

    def test_exclude_by_name_and_by_path(self):
        import tempfile
        from acxelin_readiness.detectors import Scope, iter_files, rel
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            seen = {rel(d, p) for p in iter_files(d, Scope(exclude=("gen", "*.min.js", "docs/old/*")))}
            self.assertEqual(seen, {"app/auth.py"})
            self.assertEqual(len(list(iter_files(d))), 4)

    def test_settings_file_and_command_line(self):
        import json, tempfile
        from acxelin_readiness.cli import main
        with tempfile.TemporaryDirectory() as d:
            self.tree(d)
            (Path(d) / ".acxelin-readiness.toml").write_text('exclude = ["gen"]\nfail_on = "critical"\n', encoding="utf-8")
            out = Path(d) / "out"
            with self.assertRaises(SystemExit) as e:
                main(["scan", str(d), "-o", str(out), "-q", "--exclude", "docs/old/*"])
            self.assertEqual(e.exception.code, 2)
            files = {o["location"].split(":")[0] for c in json.loads((out / "cbom.json").read_text(encoding="utf-8"))["components"]
                     for o in (c.get("evidence") or {}).get("occurrences", [])}
            self.assertEqual(files, {"app/auth.py", "app/ui.min.js"})

    def test_bad_settings_are_refused(self):
        import tempfile
        from acxelin_readiness.cli import main
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".acxelin-readiness.toml").write_text('excludes = ["gen"]\n', encoding="utf-8")
            with self.assertRaises(SystemExit) as e:
                main(["scan", d, "-o", str(Path(d) / "out"), "-q"])
            self.assertIn("unknown setting 'excludes'", str(e.exception.code))
            with self.assertRaises(SystemExit) as e:
                main(["scan", d, "--fail-on", "severe"])
            self.assertEqual(e.exception.code, 1)
            (Path(d) / ".acxelin-readiness.toml").write_bytes(b"exclude = [\xff]\n")
            with self.assertRaises(SystemExit) as e:
                main(["scan", d, "-o", str(Path(d) / "out"), "-q"])
            self.assertIn("cannot read", str(e.exception.code))

    def test_unreadable_baseline_and_output_are_one_line_errors(self):
        import tempfile
        from acxelin_readiness.cli import main
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "bad.json").write_text("not json", encoding="utf-8")
            for argv, message in ((["--baseline", str(Path(d) / "bad.json")], "cannot read the baseline"),
                                  (["--baseline", str(Path(d) / "none.json")], "cannot read the baseline")):
                with self.assertRaises(SystemExit) as e:
                    main(["scan", d, "-o", str(Path(d) / "out"), "-q", *argv])
                self.assertIn(message, str(e.exception.code))
            (Path(d) / "file").write_text("x", encoding="utf-8")
            with self.assertRaises(SystemExit) as e:
                main(["scan", d, "-o", str(Path(d) / "file" / "out"), "-q"])
            self.assertIn("cannot write to", str(e.exception.code))

    def test_implementation_prefilter_keeps_split_tables(self):
        import tempfile
        from acxelin_readiness.detectors import implementations
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "md5.c").write_text("static const unsigned T[] = {0xd76aa478, /* 0x12345678 */ 0xe8c7b756, 0x242070db, 0xc1bdceee};\n", encoding="utf-8")
            (Path(d) / "plain.c").write_text("int x = 0xd76aa478;\n", encoding="utf-8")
            self.assertEqual([(s.algo, s.file) for s in implementations.scan(d)[0]], [("MD5", "md5.c")])


if __name__ == "__main__":
    unittest.main()
