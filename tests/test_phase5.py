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


def _write_truth(text):
    import tempfile
    d = tempfile.mkdtemp(dir=ROOT)            # inside the project folder, removed by the caller
    path = os.path.join(d, "ground_truth.csv")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return d, path


def test_truth_loader_accepts_foreign_labels_and_window_mode():
    import shutil
    from vfde.truth import load_truth, resolve_mode
    d, path = _write_truth("IP,Attack_Type,Start_Time,End_Time\n"
                           "203.0.113.9,probe,2025-03-14T01:00:00Z,2025-03-14T01:05:00\n")
    try:
        rows = load_truth(path)
        assert rows[0]["src_ip"] == "203.0.113.9" and rows[0]["technique"] == "probe"
        assert rows[0]["start_dt"].tzinfo is not None and rows[0]["end_dt"].tzinfo is not None
        assert resolve_mode(rows) == "window"
        try:
            resolve_mode(rows, "rules")
            assert False, "rules mode must need expected_rules"
        except ValueError:
            pass
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_truth_loader_names_missing_columns():
    import shutil
    from vfde.truth import load_truth
    d, path = _write_truth("foo,bar\n1,2\n")
    try:
        load_truth(path)
        assert False, "should have raised"
    except ValueError as exc:
        assert "src_ip" in str(exc) and "foo" in str(exc)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_window_mode_matches_rules_mode_on_bundled_labels():
    r = _result()
    rules_m = evaluate(r, "rules")
    window_m = evaluate(r, "window")
    assert rules_m["match_mode"] == "rules" and window_m["match_mode"] == "window"
    assert window_m["verified"]["recall"] >= rules_m["verified"]["recall"]   # window is more lenient
    assert window_m["verified"]["precision"] == rules_m["verified"]["precision"]


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
