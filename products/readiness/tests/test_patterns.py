"""Security patterns: every rule fires on its case in each language it covers, and stays quiet on its traps."""
import textwrap

from acxelin_readiness import pipeline
from acxelin_readiness.detectors.patterns import scan_text

FIRES = {
    "ACX-P001": [("python", "requests.get(url, verify=False)"), ("python", "ctx = ssl._create_unverified_context()"),
               ("python", "ctx.check_hostname = False"), ("python", "ctx.verify_mode = ssl.CERT_NONE"),
               ("js", "https.request({ host, rejectUnauthorized: false })"), ("js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
               ("go", "cfg := &tls.Config{InsecureSkipVerify: true}"), ("java", "conn.setHostnameVerifier((h, s) -> true);"),
               ("java", "public void checkServerTrusted(X509Certificate[] c, String a) {}"),
               ("csharp", "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;"),
               ("c", "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);"), ("c", "curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);"),
               ("rust", "let c = Client::builder().danger_accept_invalid_certs(true);")],
    "ACX-P002": [("python", 'SECRET_KEY = "f8Kd02mZq1LwPa9x"'), ("python", 'db.connect(password="Tr0ub4dor&3")'),
               ("js", "const apiKey = 'AKIAIOSFODNN7EXAMPLF';"), ("java", 'private static final String CLIENT_SECRET = "9fhQ2kLz01mNbV";'),
               ("go", 'signingKey := "n4Hq8Zr2vW0pLx"')],
    "ACX-P003": [("python", "session_token = random.getrandbits(128)"), ("js", "const resetToken = Math.random().toString(36);"),
               ("java", "byte[] key = new byte[16]; new Random().nextBytes(key);")],
    "ACX-P004": [("python", 'jwt.decode(t, options={"verify_signature": False})'), ("python", 'jwt.decode(t, k, algorithms=["none"])'),
               ("js", "jwt.verify(t, k, { algorithms: ['none'] })"), ("go", "return jwt.UnsafeAllowNoneSignatureType, nil")],
    "ACX-P005": [("python", 'iv = b"0123456789abcdef"'), ("js", "const iv = Buffer.alloc(16, 0);"),
               ("java", "Cipher.getInstance(t).init(1, k, new IvParameterSpec(new byte[16]));")],
}
TRAPS = [
    ("python", "requests.get(url, verify=True)"), ("python", "# requests.get(url, verify=False)"),
    ("python", 'print("never pass verify=False in production")'), ("python", 'password = os.environ["DB_PASSWORD"]'),
    ("python", 'password = "changeme"'), ("python", 'SECRET_KEY_FILE = "/etc/app/secret.key"'), ("python", 'password_field = "user_password_input"'),
    ("python", 'api_key = "${API_KEY}"'), ("python", 'secret = "API_SECRET_NAME"'), ("python", 'if password == "hunter22hunter":'),
    ("python", "jitter = random.random() * delay"), ("python", "token = secrets.token_hex(16)"), ("js", "const delay = Math.random() * 100;"),
    ("python", 'crypto_secretbox_PRIMITIVE = "xsalsa20poly1305"'), ("js", 'describe("totp with secret = \'1234567890abcdef\'", f)'),
    ("go", "n := rand.Intn(10)"), ("python", "iv = os.urandom(16)"), ("java", "new IvParameterSpec(iv)"),
]


def test_each_rule_fires_in_every_language_it_covers():
    for rule, cases in FIRES.items():
        for lang, line in cases:
            text = ('import "math/rand"\n' if lang == "go" else "") + line + "\n"
            assert rule in {p.rule for p in scan_text("app/x", text, lang)}, (rule, lang, line)


def test_traps_stay_quiet():
    for lang, line in TRAPS:
        assert scan_text("app/x", line + "\n", lang) == [], (lang, line)


def test_test_code_ranks_low_and_ignore_comment_and_switch(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_client.py").write_text("requests.get(u, verify=False)\n")
    (tmp_path / "app.py").write_text(textwrap.dedent("""
        import requests
        requests.get(u, verify=False)
        requests.get(u, verify=False)  # acxelin:ignore (a pinned internal probe)
    """))
    r = pipeline.run(tmp_path, "p")
    assert [(p.file, p.line, p.severity) for p in r.patterns] == [("app.py", 3, "high"), ("tests/test_client.py", 1, "low")]


def test_patterns_reach_sarif_with_cwe_tags(tmp_path):
    import json
    from acxelin_readiness import report
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import hashlib, requests\nhashlib.md5(b'')\nrequests.get(u, verify=False)\n")
    out = tmp_path / "out"
    out.mkdir()
    report.write_results(out, "p", pipeline.run(tmp_path / "src", "p"))
    rules = {r["id"]: r for r in json.loads((out / "readiness.sarif").read_text())["runs"][0]["tool"]["driver"]["rules"]}
    assert "external/cwe/cwe-295" in rules["ACX-P001"]["properties"]["tags"]
    assert "external/cwe/cwe-328" in rules["ACX-MD5"]["properties"]["tags"]
    assert json.loads((out / "findings.json").read_text())["patterns"][0]["rule"] == "ACX-P001"


def test_secret_values_are_redacted_from_every_output():
    [p] = scan_text("app/settings.py", 'SECRET_KEY = "f8Kd02mZq1LwPa9x"\n', "python")
    assert "f8Kd02mZq1LwPa9x" not in p.snippet and "<redacted>" in p.snippet
