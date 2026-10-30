"""The board summary: one page for directors, built from every project's latest scan. It must not claim more than was checked:
a summary over unscanned projects or thinly read code is marked provisional."""
from acxelin_readiness import console as rc

KX = "from cryptography.hazmat.primitives.asymmetric import x25519\nx25519.X25519PrivateKey.generate()\n"
MD5 = "import hashlib\nhashlib.md5(b'x')\n"


def build(tmp_path, repos):
    root = tmp_path / "repos"
    for name, files in repos.items():
        (root / name).mkdir(parents=True)
        for f, text in files.items():
            (root / name / f).write_text(text)
    app = rc.build(tmp_path / "home")
    r = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    r("POST", "/api/setup", {"directory": str(root)})
    return root, r


def scan_all(r):
    r("POST", "/api/projects/scan-all", {})
    while r("GET", "/api/overview")["scan_all"]["running"]:
        pass
    return r("GET", "/api/overview")["board"]


def test_the_board_summary_gives_the_level_its_trend_the_risks_and_the_top_actions(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX, "old.py": MD5}, "ledger": {"main.py": MD5}})
    first = scan_all(r)
    assert first["projects"] == 2 and first["scanned"] == 2 and first["previous"] is None
    assert first["critical"] >= 1 and first["recordable"] == 1 and first["deadline_findings"] >= 1
    assert 1 <= len(first["actions"]) <= 5 and all(a["text"] and a["projects"] and a["names"] for a in first["actions"])
    assert first["actions"][0]["projects"] == ["ledger", "shop"]  # the same step in two projects is said once, naming both
    (root / "ledger/main.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    second = scan_all(r)
    assert second["previous"] == first["score"] and second["score"] > first["score"]
    assert not second["provisional"]


def test_a_summary_with_unscanned_projects_or_thin_coverage_is_provisional(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    r("POST", "/api/projects/register", {"name": "shop"})
    (root / "later").mkdir()
    (root / "later/a.py").write_text(MD5)
    r("POST", "/api/projects/register", {"name": "later"})
    r("POST", "/api/projects/scan", {"project": 0})
    while r("GET", "/api/projects/status")["running"]:
        pass
    board = r("GET", "/api/overview")["board"]
    assert board["provisional"] and "1 of 2 projects" in board["provisional"]


def test_a_summary_resting_on_code_that_could_not_be_read_is_provisional(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX, "broken.py": "def (:\n", "half.py": "def (:\n"}})
    board = scan_all(r)
    assert board["coverage"] < 80 and "coverage" in board["provisional"]
