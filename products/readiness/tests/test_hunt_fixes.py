"""What a deep check of Readiness found, each now held by a test: the console following a repository's own settings, an honest
board trend and actions list, findings in files whose names merely contain "test", certificate key names, owners spreadsheets
as Excel and ServiceNow write them, CODEOWNERS folder rules, test-only findings in the before-and-after counts, a damaged
workspace, other tools' line numbers, and the 200-repository limit."""
import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.x509.oid import NameOID

from acxelin_readiness import console as rc, evidence, owners, workspace
from acxelin_readiness.examples import effort
from test_board import KX, MD5, build, scan_all

RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n"


def scan_one(r, i=0):
    r("POST", "/api/projects/scan", {"project": i})
    while r("GET", "/api/projects/status")["running"]:
        pass
    return r("GET", "/api/projects/status")


def test_the_console_follows_the_repositorys_own_settings(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX, "generated/gen.py": RSA, ".acxelin-readiness.toml": 'exclude = ["generated"]\nshelf_life = 1\n'}})
    r("POST", "/api/projects/register", {"name": "shop"})
    last = scan_one(r)["last"]
    assert {a["algorithm"] for a in last["assets"]} == {"X25519"}, "generated/ is excluded"
    assert next(a for a in last["assets"] if a["algorithm"] == "X25519")["tier"] == "medium", "1 year of secrecy, not 10"
    (root / "shop" / ".acxelin-readiness.toml").write_text("colour = 'blue'\n")
    assert "unknown setting" in scan_one(r)["error"]


def test_the_board_trend_compares_the_same_projects_then_and_now(tmp_path):
    root, r = build(tmp_path, {"a": {"m.py": MD5}})
    scan_all(r)
    (root / "b").mkdir()
    (root / "b" / "k.py").write_text(KX)
    board = scan_all(r)
    assert board["change"] == 0, "b joined, nothing changed in a"


def test_nothing_to_change_is_not_an_action(tmp_path):
    root, r = build(tmp_path, {"a": {"tests/test_x.py": MD5}, "b": {"m.py": MD5}})
    board = scan_all(r)
    assert all("Nothing to change" not in a["text"] for a in board["actions"])


def test_a_file_whose_name_contains_test_is_not_a_test():
    assert effort({"tier": "critical", "locations": [["src/attestation.py", 1]]})["level"] == "code"
    assert effort({"tier": "critical", "locations": [["tests/test_keys.py", 1]]}) is None


def cert(key, path, der=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, path.stem)])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90)).sign(key, hashes.SHA256()))
    path.write_bytes(c.public_bytes(serialization.Encoding.DER if der else serialization.Encoding.PEM))


def test_report_certs_names_keys_rightly_and_reads_der_files(tmp_path):
    cert(ec.generate_private_key(ec.SECP384R1()), tmp_path / "p384.pem")
    cert(ec.generate_private_key(ec.SECP384R1()), tmp_path / "p384der.der", der=True)
    cert(dsa.generate_private_key(2048), tmp_path / "old.pem")
    rows = {r["name"]: r for r in evidence.certificates(tmp_path)}
    assert "ECDSA-secp384r1" in rows["p384"]["detail"] and "RSA" not in rows["p384"]["detail"]
    assert "p384der" in rows, "a DER certificate is read too"
    assert "DSA-2048" in rows["old"]["detail"] and rows["old"]["status"] == "action"


def test_owners_spreadsheets_as_excel_and_servicenow_write_them():
    bom = "﻿path,owner\nsrc/,Payments\n".encode("utf-8")
    assert owners.from_csv(owners.decode(bom)) == [("src/", "Payments")]
    latin = "path,owner\nsrc/,José Müller\n".encode("cp1252")
    assert owners.from_csv(owners.decode(latin)) == [("src/", "José Müller")]
    snow = owners.from_csv("path,owner,business criticality\nsrc\\app\\,t,1 - most critical\n./web/,w,4 - not critical\n")
    assert snow == [("src/app/", "t", "", "", "critical"), ("web/", "w", "", "", "low")]
    assert owners.owner_of(snow, "src/app/x.py") == "t" and owners.owner_of(snow, "web/index.js") == "w"


def test_a_folder_star_rule_matches_only_that_folders_own_files():
    rules = [("docs/*", "@docs")]
    assert owners.owner_of(rules, "docs/guide.md") == "@docs"
    assert owners.owner_of(rules, "docs/build-app/troubleshooting.py") is None


def test_findings_only_in_tests_are_not_counted_as_new(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    r("POST", "/api/projects/register", {"name": "shop"})
    scan_one(r)
    (root / "shop" / "tests").mkdir()
    (root / "shop" / "tests" / "test_a.py").write_text(MD5)
    cmp = scan_one(r)["last"]["comparison"]
    assert cmp["new"] == 0 and cmp["new_findings"] == []


def test_a_damaged_workspace_is_kept_aside_and_the_console_still_starts(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    (tmp_path / "home" / "workspace.json").write_text('{"version": 2, "projects": {')
    (tmp_path / "home" / "settings.json").write_text("{}")
    app = rc.build(tmp_path / "home")
    status = app.routes[("GET", "/api/status")]({})[1]
    assert "workspace was damaged" in status["notice"]
    assert list((tmp_path / "home").glob("workspace.json.damaged-*"))


def test_other_tools_line_numbers_are_read_leniently():
    assert [workspace.line_of(v) for v in ("12-14", "7.0", None, "x", 3)] == [12, 7, 0, 0, 3]


def test_a_github_organisation_fills_up_to_the_limit_and_says_how_many_were_left_out(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    from unittest import mock
    links = [f"https://github.com/acme/r{i}" for i in range(205)]
    with mock.patch("acxelin_readiness.remote.organisation", return_value=links):
        out = r("POST", "/api/projects/github-org", {"org": "acme"})
    assert (out["added"], out["left_out"]) == (200, 5)


def test_a_damaged_saved_deadline_choice_does_not_break_the_overview(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    data = json.loads((tmp_path / "home" / "workspace.json").read_text()) if (tmp_path / "home" / "workspace.json").exists() else {"version": 2, "registrations": {}, "projects": {}}
    data["deadlines"] = {"countries": ["xx"]}
    (tmp_path / "home" / "workspace.json").write_text(json.dumps(data))
    o = r("GET", "/api/overview")
    assert o["board"]["next_deadline"]["year"] == 2030
