"""Full evaluation (Phase 5): the numbers the README / CV are allowed to quote.

Usage:
    python eval.py --logs sample_logs                 # one dataset
    python eval.py --logs sample_logs --seeds 1 2 3   # + robustness on fresh synthetic seeds
    python eval.py --logs sample_logs --write docs/results.md

    python eval.py --logs external_logs --match window   # labels written by someone else

Matching rules (stated so they can be challenged in an interview):
  * an ALERT is a true positive if its source IP belongs to a labelled episode;
  * an EPISODE is detected if a non-Noise alert fires from its IP between
    start-5s and end+10min. In `rules` mode the alert's rule must also be one of
    the episode's expected_rules; in `window` mode any rule counts. `auto` picks
    `rules` when every label has expected_rules, else `window`;
  * time-to-detect = that first alert's timestamp minus the episode start.
"""
import argparse
import os
import shutil
import statistics
import subprocess
import sys
from datetime import timedelta

from vfde.pipeline import run
from vfde.truth import load_truth, resolve_mode

SLACK_BEFORE, SLACK_AFTER = timedelta(seconds=5), timedelta(minutes=10)


def _alert_stats(alerts, bad_ips):
    tp = sum(a.src_ip in bad_ips for a in alerts)
    return dict(alerts=len(alerts), tp=tp, fp=len(alerts) - tp,
                precision=tp / len(alerts) if alerts else 0.0)


def _matching(alerts, t, mode):
    """Alerts that count as detecting episode `t` under the given matching mode."""
    lo, hi = t["start_dt"] - SLACK_BEFORE, t["end_dt"] + SLACK_AFTER
    return [a for a in alerts if a.src_ip == t["src_ip"] and lo <= a.ts <= hi
            and (mode == "window" or a.rule_id in t["rules"])]


def _episode_hits(alerts, truth, mode):
    """Return {episode index: first matching alert or None}."""
    hits = {}
    for i, t in enumerate(truth):
        match = _matching(alerts, t, mode)
        hits[i] = min(match, key=lambda a: a.ts) if match else None
    return hits


def evaluate(result, match="auto"):
    truth = load_truth(result.truth_path)
    mode = resolve_mode(truth, match)
    bad_ips = {t["src_ip"] for t in truth}
    raw, kept = result.alerts, result.kept

    raw_s, ver_s = _alert_stats(raw, bad_ips), _alert_stats(kept, bad_ips)
    raw_hits, ver_hits = _episode_hits(raw, truth, mode), _episode_hits(kept, truth, mode)
    for s, hits in ((raw_s, raw_hits), (ver_s, ver_hits)):
        s["recall"] = sum(h is not None for h in hits.values()) / len(truth)
        p, r = s["precision"], s["recall"]
        s["f1"] = 2 * p * r / (p + r) if p + r else 0.0

    per_tech = {}
    for i, t in enumerate(truth):
        row = per_tech.setdefault(t["technique"], dict(episodes=0, detected=0, ttd=[], verdicts=[]))
        row["episodes"] += 1
        h = ver_hits[i]
        if h is not None:
            row["detected"] += 1
            row["ttd"].append((h.ts - t["start_dt"]).total_seconds())
            best = max(_matching(kept, t, mode),
                       key=lambda a: ("Attempted", "Likely", "Confirmed").index(a.verdict))
            row["verdicts"].append(best.verdict)

    ttd_all = [x for r in per_tech.values() for x in r["ttd"]]
    inc = result.incidents
    return dict(
        events=len(result.events), episodes=len(truth), raw=raw_s, verified=ver_s, match_mode=mode,
        fp_reduction=(raw_s["fp"] - ver_s["fp"]) / raw_s["fp"] if raw_s["fp"] else 0.0,
        alert_reduction=1 - len(kept) / len(raw) if raw else 0.0,
        per_technique=per_tech,
        mttd=statistics.median(ttd_all) if ttd_all else None,
        incidents=len(inc),
        false_incidents=sum(i.src_ip not in bad_ips for i in inc),
        multi_stage=sum(len(i.stages) > 1 for i in inc),
        alerts_per_incident=len(raw) / len(inc) if inc else 0.0,
        episodes_in_incidents=sum(t["src_ip"] in {i.src_ip for i in inc} for t in truth),
        confirmed_precision=_alert_stats([a for a in raw if a.verdict == "Confirmed"],
                                         bad_ips)["precision"],
    )


def seed_sweep(seeds, rules, year):
    """Generate fresh datasets inside the project folder, evaluate, clean up."""
    rows, tmp = [], os.path.join(os.path.dirname(os.path.abspath(__file__)), "_eval_seeds")
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generators", "synthetic_logs.py")
    try:
        for s in seeds:
            out = os.path.join(tmp, f"seed{s}")
            subprocess.run([sys.executable, gen, "--out", out, "--seed", str(s),
                            "--year", str(year)], check=True, capture_output=True)
            m = evaluate(run(out, rules, year))
            rows.append((s, m))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rows


def pct(x):
    return f"{x:.1%}"


def render(m, sweep=None, dataset="sample_logs", note=None, allowlist_entries=0):
    r, v = m["raw"], m["verified"]
    out = [f"# Evaluation results", "",
           f"Dataset: `{dataset}` ({m['events']} events, {m['episodes']} labelled episodes). "
           f"Matching mode: `{m['match_mode']}`. "
           + (note or "Labelled data (synthetic unless stated otherwise): a controlled "
                      "benchmark, not real-world performance."),
           "",
           (f"Operator allowlist applied: {allowlist_entries} authorised source(s)."
            if allowlist_entries else "No operator allowlist applied."), "",
           "## Raw rules vs verified alerts", "",
           "| Metric | Raw rules | Verified |", "|---|---|---|",
           f"| Alerts | {r['alerts']} | {v['alerts']} |",
           f"| False positives | {r['fp']} | {v['fp']} |",
           f"| Alert precision | {pct(r['precision'])} | {pct(v['precision'])} |",
           f"| Episode recall | {pct(r['recall'])} | {pct(v['recall'])} |",
           f"| F1 (alert precision x episode recall) | {pct(r['f1'])} | {pct(v['f1'])} |", "",
           f"- False-positive reduction: **{pct(m['fp_reduction'])}**",
           f"- Alert volume reduction: **{pct(m['alert_reduction'])}**",
           f"- Precision of `Confirmed` alerts: {pct(m['confirmed_precision'])}",
           f"- Median time to detect (verified): {m['mttd']:.0f}s" if m["mttd"] is not None
           else "- Median time to detect: n/a", "",
           "## Per technique (verified)", "",
           "| Technique | Episodes | Detected | Median TTD | Verdicts |", "|---|---|---|---|---|"]
    for tech, row in sorted(m["per_technique"].items()):
        ttd = f"{statistics.median(row['ttd']):.0f}s" if row["ttd"] else "-"
        vc = ", ".join(f"{k} x{row['verdicts'].count(k)}" for k in
                       ("Confirmed", "Likely", "Attempted") if k in row["verdicts"]) or "-"
        out.append(f"| {tech} | {row['episodes']} | {row['detected']} | {ttd} | {vc} |")
    out += ["", "## Incidents", "",
            f"- {r['alerts']} raw alerts -> **{m['incidents']} incidents** "
            f"({m['alerts_per_incident']:.1f} raw alerts per incident)",
            f"- Labelled episodes inside an incident: {m['episodes_in_incidents']}/{m['episodes']}",
            f"- False incidents: {m['false_incidents']}",
            f"- Multi-stage incidents: {m['multi_stage']}"]
    if sweep:
        out += ["", "## Robustness across fresh synthetic seeds", "",
                "| Seed | Raw precision | Verified precision | Recall | FP reduction | False incidents |",
                "|---|---|---|---|---|---|"]
        for s, sm in sweep:
            out.append(f"| {s} | {pct(sm['raw']['precision'])} | {pct(sm['verified']['precision'])} | "
                       f"{pct(sm['verified']['recall'])} | {pct(sm['fp_reduction'])} | "
                       f"{sm['false_incidents']} |")
    out += ["", "## How these numbers are computed", "",
            "- Alert = true positive if its source IP belongs to a labelled episode.",
            ("- Episode detected = a non-Noise alert of one of its expected rules from its IP, "
             "between start-5s and end+10min." if m["match_mode"] == "rules" else
             "- Episode detected = any non-Noise alert from its IP between start-5s and "
             "end+10min (`window` mode: the labels carry no expected rules)."),
            "- Time to detect is measured in log time (batch analysis): it shows how far into "
            "an episode the first verified alert lands, not wall-clock latency. Pattern rules "
            "fire on the first matching request, hence 0s; brute force needs N failures first.",
            "- The verifier never reads the ground truth; only this script does.",
            "- Labels are written by the dataset's author. A dataset produced together with "
            "the verifier shares its assumptions, so expect lower numbers on real logs."]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="sample_logs")
    ap.add_argument("--rules", default="rules.yaml")
    ap.add_argument("--year", type=int, default=2025)
    ap.add_argument("--seeds", type=int, nargs="*", default=[])
    ap.add_argument("--match", choices=["auto", "rules", "window"], default="auto",
                    help="how an alert is matched to a labelled episode (default: auto)")
    ap.add_argument("--write", help="write markdown results to this path (inside the project)")
    ap.add_argument("--no-allowlist", action="store_true",
                    help="ignore <logs>/allowlist.yaml (measure without operator context)")
    ap.add_argument("--note", help="replace the dataset sentence in the results header")
    a = ap.parse_args()

    result = run(a.logs, a.rules, a.year, use_allowlist=not a.no_allowlist)
    if not result.truth_path:
        sys.exit(f"no ground_truth.csv in {a.logs}: nothing to evaluate against")
    try:
        m = evaluate(result, a.match)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    sweep = seed_sweep(a.seeds, a.rules, a.year) if a.seeds else None
    text = render(m, sweep, a.logs, a.note, len(result.rules.get("allowlist") or []))
    print(text)
    if a.write:
        os.makedirs(os.path.dirname(a.write) or ".", exist_ok=True)
        with open(a.write, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[out] wrote {a.write}")


if __name__ == "__main__":
    main()
