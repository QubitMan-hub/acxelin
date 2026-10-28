"""Exports: CSV that a spreadsheet cannot turn into a formula, reports that print to PDF, and each evidence row's framework controls."""
import csv
import io
import time
from unittest.mock import patch

import pytest

from acxelin_readiness import console as rc
from acxelin_readiness import evidence
from acxelin_readiness.brand import page


@pytest.mark.parametrize("cell", ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_a_cell_a_spreadsheet_would_run_as_a_formula_is_kept_as_text(cell):
    rows = list(csv.reader(io.StringIO(evidence.csv_text(["a"], [[cell]]))))
    assert rows == [["a"], ["'" + cell]]


def test_ordinary_cells_are_left_alone():
    assert list(csv.reader(io.StringIO(evidence.csv_text(["a", "b"], [["RSA-2048", 3], ["a, b", None]])))) == [["a", "b"], ["RSA-2048", "3"], ["a, b", ""]]


def test_every_report_has_a_print_button_that_print_hides():
    html = page("t", "k", "h", "s", "<p>x</p>", "f")
    assert "Print or save as PDF" in html and 'class="tools"' in html and "@media print{.tools{display:none" in html


def endpoint(grade):
    return {"target": "a.example:443", "grade": grade, "protocol": "tls", "accepts": ["X25519"], "negotiated": "X25519", "legacy": [],
            "certificate": {"key": "RSA-2048", "expires": "2027-01-01", "issuer": "CN=CA", "days_left": 60, "quantum_safe": False}}


def test_evidence_rows_name_the_framework_controls_they_support_and_say_it_is_not_a_verdict():
    rows = evidence.endpoints([endpoint("C")])
    assert rows[0]["frameworks"] == {"NIST CSF 2.0": "PR.DS-02", "DORA": "Delegated Regulation (EU) 2024/1774 Art. 6", "NIS2": "Art. 21(2)(h)"}
    html = evidence.to_html(evidence.report(rows))
    assert "PR.DS-02" in html and "not a compliance verdict" in html
    table = list(csv.DictReader(io.StringIO(evidence.to_csv(evidence.report(rows)))))
    assert table[0]["Asset"] == "a.example:443" and table[0]["NIST CSF 2.0"] == "PR.DS-02" and table[0]["NIS2"] == "Art. 21(2)(h)"


def test_the_report_command_writes_a_csv_next_to_the_html(tmp_path):
    from acxelin_readiness import cli
    with patch("acxelin_readiness.endpoints.scan", return_value=[endpoint("B")]):
        assert cli.main(["report", "--targets", "a.example:443", "--out", str(tmp_path)]) == 0
    assert next(csv.DictReader((tmp_path / "assessment.csv").open(encoding="utf-8")))["Asset"] == "a.example:443"


def test_the_console_exports_a_projects_findings_and_the_endpoint_grades_as_csv(tmp_path):
    (tmp_path / "repos/shop").mkdir(parents=True)
    (tmp_path / "repos/shop/k.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    app = rc.build(tmp_path / "home")
    route = lambda path, body=None, method="POST": app.routes[(method, path)](body or {})[1]
    route("/api/setup", {"directory": str(tmp_path / "repos")})
    route("/api/projects/register", {"name": "shop"})
    route("/api/projects/scan", {"project": 0})
    while route("/api/projects/status", method="GET")["running"]:
        time.sleep(0.05)
    rows = list(csv.DictReader(io.StringIO(route("/api/projects/csv", {"project": 0})["csv"])))
    assert rows[0]["Asset"] == "MD5" and rows[0]["Places"] == "k.py:2"
    with pytest.raises(ValueError):
        app.routes[("POST", "/api/endpoints/csv")]({})
    with patch("acxelin_readiness.console.endpoints.scan", return_value=[endpoint("C")]):
        route("/api/endpoints/scan", {"targets": "a.example:443"})
        while route("/api/endpoints/status", method="GET")["running"]:
            time.sleep(0.02)
    grades = list(csv.DictReader(io.StringIO(route("/api/endpoints/csv")["csv"])))
    assert grades == [{"Endpoint": "a.example:443", "Grade": "C", "Negotiated": "X25519", "Certificate key": "RSA-2048", "Expires": "2027-01-01", "Issuer": "CN=CA"}]
