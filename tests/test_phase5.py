import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from eval import evaluate, render
from vfde.pipeline import run
from vfde.reporting import build_report

LOGS = os.path.join(ROOT, "sample_logs")
RULES = os.path.join(ROOT, "rules.yaml")


def _result():
    return run(LOGS, RULES, 2025)


def test_pipeline_matches_cli_numbers():
    r = _result()
    assert r.truth_path and len(r.alerts) >= len(r.kept) > 0 and r.incidents
    assert all(a.verdict in ("Confirmed", "Likely", "Attempted", "Noise") for a in r.alerts)


def test_evaluate_is_consistent():
    m = evaluate(_result())
    raw, ver = m["raw"], m["verified"]
    assert raw["alerts"] == raw["tp"] + raw["fp"] and ver["alerts"] == ver["tp"] + ver["fp"]
    assert ver["fp"] <= raw["fp"] and ver["precision"] >= raw["precision"]
    assert ver["recall"] <= raw["recall"]          # verification can only drop alerts
    assert sum(t["episodes"] for t in m["per_technique"].values()) == m["episodes"]
    assert "Raw rules vs verified" in render(m)


def test_report_is_self_contained_and_complete():
    r = _result()
    html = build_report(r, evaluate(r))
    assert html.startswith("<!doctype html>")
    assert "<script" not in html.lower()             # no JS at all
    assert "http://" not in html and "https://" not in html   # no external assets
    assert html.count('class="card incident"') == len(r.incidents)


def test_report_escapes_log_derived_text():
    r = _result()
    inc = r.incidents[0]
    payload = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    inc.alerts[0].evidence = [payload]
    inc.alerts[0].reason = payload
    html = build_report(r)
    assert payload not in html
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html
