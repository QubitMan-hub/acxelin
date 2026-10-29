"""Findings as tickets: a CSV that Jira or ServiceNow imports, one row per finding that needs work, worst first."""
import csv
import io

import pytest

from acxelin_readiness import cli, tickets
from test_owners import scanned  # noqa: F401

FINDINGS = [
    {"name": "AES-256", "algorithm": "AES", "tier": "ok", "action": "", "locations": [["a.py", 1]]},
    {"name": "RSA-2048", "algorithm": "RSA", "tier": "high", "action": "Switch to ML-KEM-768", "locations": [["src/keys.py", 2]],
     "owner": "Payments team", "service": "Card payments", "due": "2027-03-31"},
    {"name": "MD5", "algorithm": "MD5", "tier": "critical", "action": "Use SHA-256", "locations": [["legacy.py", 2]]},
    {"name": "SHA-1", "algorithm": "SHA-1", "tier": "low", "action": "", "why": "Fingerprint only", "locations": [["t.py", 1]], "test_only": True},
    {"name": "3DES", "algorithm": "3DES", "tier": "high", "action": "Use AES-256", "locations": [["old.py", 1]], "status": "fixed"},
]


def rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_jira_rows_are_the_findings_that_need_work_worst_first():
    out = rows(tickets.csv_for(FINDINGS, "jira", "shop"))
    assert [r["Summary"] for r in out] == ["MD5 in shop", "RSA-2048 in shop"]
    rsa = out[1]
    assert (rsa["Priority"], rsa["Assignee"], rsa["Component"], rsa["Due date"]) == ("High", "Payments team", "Card payments", "2027-03-31")
    assert "Switch to ML-KEM-768" in rsa["Description"] and "src/keys.py:2" in rsa["Description"] and rsa["Labels"] == "post-quantum"


def test_servicenow_rows_use_its_field_names_and_numeric_priority():
    out = rows(tickets.csv_for(FINDINGS, "servicenow", "shop"))
    assert list(out[0]) == tickets.HEADERS["servicenow"]
    assert [(r["priority"], r["assignment_group"], r["cmdb_ci"]) for r in out] == [("1", "", ""), ("2", "Payments team", "Card payments")]


def test_a_cell_a_spreadsheet_would_run_as_a_formula_is_neutralised():
    out = tickets.csv_for([dict(FINDINGS[2], owner="=HYPERLINK(1)")], "jira", "shop")
    assert "'=HYPERLINK(1)" in out


def test_an_unknown_ticket_system_is_refused():
    with pytest.raises(ValueError):
        tickets.csv_for(FINDINGS, "trello", "shop")


def test_the_console_downloads_tickets_with_owner_and_service(scanned):  # noqa: F811
    app, r = scanned
    r("POST", "/api/projects/owners", {"project": 0, "csv": "path,owner,service\nsrc/,Payments team,Card payments\n"})
    out = rows(r("POST", "/api/projects/tickets", {"project": 0, "system": "jira"})["csv"])
    rsa = next(x for x in out if x["Summary"].startswith("RSA-2048"))
    assert (rsa["Assignee"], rsa["Component"]) == ("Payments team", "Card payments")
    with pytest.raises(ValueError):
        r("POST", "/api/projects/tickets", {"project": 0, "system": "x"})


def test_a_scan_writes_tickets_with_owners_from_a_cmdb_file(tmp_path):
    (tmp_path / "repo/src").mkdir(parents=True)
    (tmp_path / "repo/src/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (tmp_path / "owners.csv").write_text("path,owner,service\nsrc/,Payments team,Card payments\n")
    out = tmp_path / "out"
    assert cli.main(["scan", str(tmp_path / "repo"), "-o", str(out), "-q", "--tickets", "servicenow", "--owners", str(tmp_path / "owners.csv")]) == 0
    rsa = next(x for x in rows((out / "tickets.csv").read_text()) if x["short_description"].startswith("RSA-2048"))
    assert (rsa["assignment_group"], rsa["cmdb_ci"]) == ("Payments team", "Card payments")
