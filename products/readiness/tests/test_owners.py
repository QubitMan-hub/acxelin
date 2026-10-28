"""Owners from the repository's CODEOWNERS and from a CMDB export: a suggestion with its source; an owner set by hand always wins."""
import pytest

from acxelin_readiness import console as rc
from acxelin_readiness import owners

RULES = [("*", "@everyone"), ("*.py", "@python"), ("/src/", "@src"), ("docs/", "@docs"), ("**/keys/**", "@security"), ("Cargo.toml", "@rust"),
         ("/apps/*/config.yaml", "@ops")]


@pytest.mark.parametrize("path,owner", [
    ("README.md", "@everyone"), ("tools/run.py", "@python"), ("src/main.go", "@src"), ("src/a/b.py", "@src"),
    ("lib/docs/x.md", "@docs"), ("deep/keys/server.pem", "@security"), ("crates/x/Cargo.toml", "@rust"),
    ("apps/web/config.yaml", "@ops"), ("apps/web/sub/config.yaml", "@everyone"), ("other/src/x.go", "@everyone"),
])
def test_codeowners_patterns_match_as_github_reads_them_and_the_last_match_wins(path, owner):
    assert owners.owner_of(RULES, path) == owner


def test_codeowners_is_read_from_github_root_or_docs_in_githubs_order(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/CODEOWNERS").write_text("* @docs-file\n")
    assert owners.codeowners(tmp_path) == [("*", "@docs-file")]
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/CODEOWNERS").write_text("# owners\n\n*.py   @py @team/crypto  # inline\n")
    assert owners.codeowners(tmp_path) == [("*.py", "@py @team/crypto")]


@pytest.mark.parametrize("text,ok", [("path,owner\nsrc/,payments\n", True), ("Pattern;Owner\nsrc/;payments\n", True), ("owner\nx\n", False),
                                      ("path,owner\n" + "a,b\n" * 5001, False), ("path,owner\nsrc/," + "x" * 200 + "\n", False), ("", False)])
def test_a_cmdb_export_needs_path_and_owner_columns_within_limits(text, ok):
    if ok:
        assert owners.from_csv(text) == [("src/", "payments")]
    else:
        with pytest.raises(ValueError):
            owners.from_csv(text)


@pytest.fixture
def scanned(tmp_path):
    root = tmp_path / "repos"
    (root / "shop/src").mkdir(parents=True)
    (root / "shop/src/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "shop/legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (root / "shop/.github").mkdir()
    (root / "shop/.github/CODEOWNERS").write_text("/src/ @payments-team\n")
    app = rc.build(tmp_path / "home")
    r = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    r("POST", "/api/setup", {"directory": str(root)})
    r("POST", "/api/projects/register", {"name": "shop"})
    r("POST", "/api/projects/scan", {"project": 0})
    while r("GET", "/api/projects/status")["running"]:
        pass
    return app, r


def hints(r):
    return {a["name"]: a["owner_hint"] for a in r("GET", "/api/projects/status")["last"]["assets"]}


def test_a_finding_takes_its_owner_from_codeowners_and_one_without_says_none(scanned):
    app, r = scanned
    h = hints(r)
    assert h["RSA-2048"] == {"owner": "@payments-team", "source": "CODEOWNERS"} and h["MD5"] is None


def test_a_cmdb_export_comes_before_codeowners_and_can_be_removed(scanned):
    app, r = scanned
    assert r("POST", "/api/projects/owners", {"project": 0, "csv": "path,owner\n*.py,Platform Security\n"}) == {"rules": 1}
    h = hints(r)
    assert h["RSA-2048"] == {"owner": "Platform Security", "source": "CMDB export"} and h["MD5"]["owner"] == "Platform Security"
    assert r("POST", "/api/projects/owners", {"project": 0, "csv": ""}) == {"rules": 0}
    assert hints(r)["MD5"] is None


def test_an_owner_set_by_hand_wins_over_any_suggestion(scanned):
    app, r = scanned
    rsa = next(a for a in r("GET", "/api/projects/status")["last"]["assets"] if a["name"] == "RSA-2048")
    r("POST", "/api/projects/track", {"project": 0, "finding": rsa["id"], "owner": "alice", "status": "open"})
    rows = r("POST", "/api/projects/csv", {"project": 0})["csv"]
    assert "alice" in rows and "@payments-team" not in rows.split("RSA-2048", 1)[1].split("\n", 1)[0]
