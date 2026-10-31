"""The held-out evaluation's arithmetic and plumbing, on a tiny synthetic stand-in (the real set is GPL-2.0 and is never copied into this repository)."""
import json
import math

import pytest

from acxelin_readiness import heldout


def test_the_wilson_interval_matches_known_values():
    low, high = heldout.wilson(8, 10)
    assert (round(low, 3), round(high, 3)) == (0.490, 0.943)  # the standard textbook example
    assert heldout.wilson(0, 10)[0] == 0.0 and heldout.wilson(10, 10)[1] == 1.0
    low, high = heldout.wilson(50, 100)
    assert math.isclose((low + high) / 2, 0.5, abs_tol=0.01) and low < 0.5 < high
    assert heldout.wilson(0, 0) is None


def test_the_confusion_matrix_counts_every_pair_once():
    pairs = [(True, True)] * 5 + [(True, False)] * 2 + [(False, True)] * 3 + [(False, False)] * 7
    assert heldout.confusion(pairs) == {"tp": 5, "fn": 2, "fp": 3, "tn": 7}


def test_rates_have_intervals_and_say_when_they_are_undefined():
    r = heldout.rates({"tp": 5, "fn": 2, "fp": 3, "tn": 7})
    assert round(r["precision"]["value"], 3) == round(5 / 8, 3) and round(r["recall"]["value"], 3) == round(5 / 7, 3)
    assert round(r["accuracy"]["value"], 3) == round(12 / 17, 3) and r["precision"]["ci95"][0] < r["precision"]["value"] < r["precision"]["ci95"][1]
    none = heldout.rates({"tp": 0, "fn": 0, "fp": 0, "tn": 4})
    assert none["precision"] is None and none["recall"] is None and none["accuracy"]["value"] == 1.0


def write_csv(path, rows):
    path.write_text("# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1\n" + "".join(",".join(map(str, r)) + "\n" for r in rows), encoding="utf-8")


def test_only_the_chosen_categories_are_loaded(tmp_path):
    write_csv(tmp_path / "e.csv", [("BenchmarkTest00001", "sqli", "true", 89), ("BenchmarkTest00002", "crypto", "true", 327), ("BenchmarkTest00003", "hash", "false", 328),
                                   ("BenchmarkTest00004", "weakrand", "true", 330)])
    assert heldout.load_expected(tmp_path / "e.csv") == {"BenchmarkTest00002": ("crypto", True), "BenchmarkTest00003": ("hash", False)}


def checkout(tmp_path, names):
    code = tmp_path / "bm" / "src/main/java/org/owasp/benchmark/testcode"
    code.mkdir(parents=True)
    for n in names:
        (code / f"{n}.java").write_text("class X { void f() throws Exception { javax.crypto.Cipher.getInstance(\"DES/ECB/PKCS5Padding\"); } }\n", encoding="utf-8")
    return tmp_path / "bm"


def test_the_neutral_layout_hides_every_name_the_original_layout_has(tmp_path):
    bm = checkout(tmp_path, ["BenchmarkTest00002", "BenchmarkTest00003"])
    files = heldout.materialize(bm, tmp_path / "n", ["BenchmarkTest00002", "BenchmarkTest00003"], "neutral")
    assert files == {"BenchmarkTest00002": "src/case_00002.java", "BenchmarkTest00003": "src/case_00003.java"}
    assert all((tmp_path / "n" / f).is_file() for f in files.values()) and "Test" not in " ".join(files.values())
    files = heldout.materialize(bm, tmp_path / "o", ["BenchmarkTest00002"], "original")
    assert files == {"BenchmarkTest00002": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java"}
    with pytest.raises(ValueError, match="layout"):
        heldout.materialize(bm, tmp_path / "x", [], "other")


def test_a_missing_test_file_is_an_error_not_a_silent_skip(tmp_path):
    with pytest.raises(FileNotFoundError, match="BenchmarkTest00009"):
        heldout.materialize(checkout(tmp_path, []), tmp_path / "n", ["BenchmarkTest00009"], "neutral")


def assets(*items):
    return [{"tier": t, "locations": [(f, 1)]} for f, t in items]


def test_the_prediction_rules_are_the_registered_ones():
    files = {"a": "src/a.java", "b": "src/b.java", "c": "src/c.java", "d": "src/d.java"}
    found = assets(("src/a.java", "critical"), ("src/b.java", "high"), ("src/c.java", "low"), ("src/c.java", "ok"))
    assert heldout.predict(found, files, "strict") == {"a": True, "b": False, "c": False, "d": False}
    assert heldout.predict(found, files, "broad") == {"a": True, "b": True, "c": False, "d": False}
    with pytest.raises(ValueError, match="rule"):
        heldout.predict(found, files, "lenient")


def test_the_whole_evaluation_on_the_stand_in_records_what_a_reader_needs(tmp_path):
    bm = checkout(tmp_path, ["BenchmarkTest00002", "BenchmarkTest00003"])
    write_csv(bm / "expectedresults-1.2.csv", [("BenchmarkTest00002", "crypto", "true", 327), ("BenchmarkTest00003", "hash", "false", 328)])
    out = heldout.evaluate(bm, layouts=("neutral",))
    assert out["population"] == {"crypto": 1, "hash": 1}
    assert out["results"]["neutral"]["strict"]["overall"]["confusion"] == {"tp": 1, "fn": 0, "fp": 1, "tn": 0}  # DES/ECB is found in both stand-in files, one of which is labelled safe
    for key in ("readiness_version", "readiness_commit", "benchmark_commit", "rules", "layouts", "protocol"):
        assert key in out
    json.dumps(out)
