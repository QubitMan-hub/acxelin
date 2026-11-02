"""The performance harness: its arithmetic is right, its comparison is direction-aware, and every number it reports comes from samples it kept."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import perf  # noqa: E402
from acxelin_core import openssl  # noqa: E402

needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL); ACXELIN_REQUIRE_OPENSSL turns that into a failure in CI")


def test_median_and_percentiles_are_the_textbook_ones():
    assert perf.median([3, 1, 2]) == 2
    assert perf.median([4, 1, 3, 2]) == 2.5
    xs = list(range(1, 101))
    assert (perf.percentile(xs, 50), perf.percentile(xs, 95), perf.percentile(xs, 99)) == (50, 95, 99)  # nearest rank
    assert perf.percentile([7], 99) == 7
    with pytest.raises(ValueError):
        perf.median([])


def test_a_metric_keeps_its_samples_and_its_summary_comes_from_them():
    m = perf.metric("handshakes_per_s", "1/s", "higher", [100.0, 120.0, 110.0])
    assert m["samples"] == [100.0, 120.0, 110.0] and m["median"] == 110.0 and (m["min"], m["max"]) == (100.0, 120.0)


def result(**metrics):
    return {"environment": {"cpu": "x", "cores": 4, "python": "3.13", "openssl": "OpenSSL 3.5.9"},
            "suites": {"s": {"metrics": {k: perf.metric(k, u, b, [v]) for k, (u, b, v) in metrics.items()}}}}


def test_a_slower_rate_and_a_longer_time_are_both_regressions_but_the_opposites_are_not():
    base = result(rate=("1/s", "higher", 100.0), latency=("ms", "lower", 10.0))
    worse = perf.compare(base, result(rate=("1/s", "higher", 70.0), latency=("ms", "lower", 14.0)), 15)
    assert {r["metric"]: r["verdict"] for r in worse["rows"]} == {"s/rate": "regression", "s/latency": "regression"}
    better = perf.compare(base, result(rate=("1/s", "higher", 140.0), latency=("ms", "lower", 6.0)), 15)
    assert {r["verdict"] for r in better["rows"]} == {"improvement"}
    same = perf.compare(base, result(rate=("1/s", "higher", 105.0), latency=("ms", "lower", 10.5)), 15)
    assert {r["verdict"] for r in same["rows"]} == {"within noise"}


def test_metrics_missing_on_one_side_are_listed_not_dropped():
    out = perf.compare(result(a=("1/s", "higher", 1.0)), result(b=("1/s", "higher", 1.0)), 15)
    assert out["only_in_baseline"] == ["s/a"] and out["only_in_current"] == ["s/b"] and out["rows"] == []


def test_a_different_machine_is_said_to_be_not_comparable():
    a, b = result(r=("1/s", "higher", 1.0)), result(r=("1/s", "higher", 1.0))
    b["environment"]["cores"] = 64
    assert perf.compare(a, b, 15)["warnings"] and not perf.compare(a, a, 15)["warnings"]


def test_the_environment_block_names_what_a_reader_needs_to_judge_a_number():
    env = perf.environment()
    for key in ("cpu", "cores", "python", "openssl", "platform", "commit", "load_average"):
        assert key in env


@needs_openssl
def test_the_ca_suite_runs_and_reports_only_what_it_measured():
    out = perf.run(["ca"], quick=True, runs=1)
    metrics = out["suites"]["ca"]["metrics"]
    assert {"issue_ml_dsa_65_per_s", "crl_sign_ms_1000_revoked", "crl_check_first_ms", "crl_check_cached_us"} <= set(metrics)
    for m in metrics.values():
        assert m["samples"] and all(s > 0 for s in m["samples"]) and m["median"] == perf.median(m["samples"])
    json.dumps(out)  # serialisable as it is


def test_an_unknown_suite_is_an_error_and_a_missing_product_is_reported_not_hidden():
    with pytest.raises(ValueError, match="unknown suite"):
        perf.run(["nope"], quick=True, runs=1)
    assert "skipped" in perf.run([], quick=True, runs=1)


@needs_openssl
def test_the_markdown_lists_every_metric_with_its_samples_count_and_the_machine():
    out = perf.run(["ca"], quick=True, runs=1)
    text = perf.markdown(out)
    for name in out["suites"]["ca"]["metrics"]:
        assert name in text
    assert out["environment"]["cpu"] in text and "not a claim" in text.lower()
