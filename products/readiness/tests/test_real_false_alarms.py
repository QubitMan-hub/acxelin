"""False alarms found scanning Go, OpenSSL, Django, Vault, Kubernetes and a real /usr/share/ca-certificates: each one keeps a case
nearby that must still be found."""
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acxelin_readiness import workspace
from acxelin_readiness.detectors import is_test


def scan(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(text) if isinstance(text, bytes) else (tmp_path / name).write_text(text)
    return {a["name"]: a for a in workspace.scan(tmp_path)["assets"]}


def test_arc4random_is_a_random_generator_not_rc4(tmp_path):
    found = scan(tmp_path, {"r.go": 'package r\n\nimport "internal/syscall/unix"\n\nfunc read(b []byte) {\n\tunix.ARC4Random(b)\n}\n',
                            "c.go": 'package c\n\nimport "crypto/rc4"\n\nfunc k(key []byte) {\n\tc, _ := rc4.NewCipher(key)\n\t_ = c\n}\n'})
    assert {f for f, _ in found["RC4"]["locations"]} == {"c.go"}


def test_go_triple_des_is_3des_and_not_also_des(tmp_path):
    found = scan(tmp_path, {"d.go": 'package d\n\nimport "crypto/des"\n\nfunc d(key []byte) {\n\tb, _ := des.NewTripleDESCipher(key)\n\t_ = b\n}\n'})
    assert "3DES" in found and "DES" not in found


def test_a_tls_version_named_to_switch_it_off_is_not_its_use(tmp_path):
    found = scan(tmp_path, {"ssl_conf.c": 'static const ssl_flag_tbl t[] = {\n    SSL_FLAG_TBL_INV("TLSv1", SSL_OP_NO_TLSv1),\n};\n',
                            "client.c": 'void f(SSL_CTX *ctx) {\n    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);\n}\n'})
    assert "TLS 1.0" not in found and "TLS 1.1" in found


def test_a_secret_prefix_is_not_a_secret_but_a_real_looking_key_still_is(tmp_path):
    workspace_dir = tmp_path / "w"
    workspace_dir.mkdir()
    (workspace_dir / "base.py").write_text('SECRET_KEY_INSECURE_PREFIX = "django-insecure-"\nAPI_KEY = "f9a8b7c6d5e4f3a2b1c0d9e8"\n')
    from acxelin_readiness.detectors import patterns
    lines = [p.line for p in patterns.scan(workspace_dir)[0] if p.rule == "WPC002"] if isinstance(patterns.scan(workspace_dir), tuple) else \
        [p.line for p in patterns.scan(workspace_dir) if p.rule == "WPC002"]
    assert lines == [2]


def test_test_helpers_named_testing_are_tests():
    assert is_test("cmd/kube-apiserver/app/testing/testserver.go") and is_test("vault/testing.go") and is_test("command/agent/testutil.go")
    assert not is_test("vault/attesting.go") and not is_test("pkg/contesting/a.go")


def _root(name, digest):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, digest))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_a_folder_of_one_root_per_file_is_a_trust_store_and_root_self_signatures_do_not_count(tmp_path):
    """Six public RSA-2048 roots from Mozilla's bundle, one per file as /usr/share/ca-certificates keeps them; two are self-signed over SHA-1."""
    roots = Path(__file__).parent / "fixtures" / "mozilla-roots"
    found = scan(tmp_path, {f"mozilla/{f.name}": f.read_bytes() for f in roots.iterdir()})
    assert found["RSA-2048"]["tier"] == "low" and "trust store" in found["RSA-2048"]["why"]
    assert found.get("SHA-1", {"tier": "low"})["tier"] == "low"
    assert "Re-sign" not in found["RSA-2048"]["action"]


def test_one_self_signed_server_certificate_is_not_a_trust_store(tmp_path):
    found = scan(tmp_path, {"server.crt": _root("server", hashes.SHA256())})
    assert found["RSA-2048"]["tier"] in ("high", "critical")


def test_a_finding_that_is_weak_only_in_some_places_says_how_many(tmp_path):
    import pcapgen
    c, s = [10, 0, 0, 5], [10, 0, 0, 9]
    frames = []
    for i, (host, group) in enumerate([("pq.example", 0x11EC), ("pq2.example", 0x11EC), ("classical.example", 0x001D)]):
        frames += [pcapgen._eth_ip_tcp(c, s, 50000 + i, 443, 1, pcapgen.client_hello(host, [group])),
                   pcapgen._eth_ip_tcp(s, c, 443, 50000 + i, 1, pcapgen.server_hello(0x1301, group=group))]
    (tmp_path / "c.pcap").write_bytes(pcapgen.pcap(frames))
    from acxelin_readiness import pipeline
    tls13 = next(a for a in pipeline.run(tmp_path, "p", captures=[str(tmp_path / "c.pcap")]).assets if a.variant == "TLS 1.3")
    assert tls13.tier == "high" and "1 of 3 places" in tls13.why
