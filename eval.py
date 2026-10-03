"""Full evaluation (Phase 5): the numbers the README / CV are allowed to quote.

Usage:
    python eval.py --logs sample_logs                 # one dataset
    python eval.py --logs sample_logs --seeds 1 2 3   # + robustness on fresh synthetic seeds
    python eval.py --logs sample_logs --write docs/results.md

Matching rules (stated so they can be challenged in an interview):
  * an ALERT is a true positive if its source IP belongs to a labelled episode;
  * an EPISODE is detected if a non-Noise alert whose rule is one of the episode's
    expected rules fires from its IP between start-5s and end+10min;
  * time-to-detect = that first alert's timestamp minus the episode start.
"""
import argparse
import csv
import os
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timedelta

from vfde.pipeline import run

SLACK_BEFORE, SLACK_AFTER = timedelta(seconds=5), timedelta(minutes=10)


def load_truth(path):
    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["start_dt"] = datetime.fromisoformat(r["start"])
        r["end_dt"] = datetime.fromisoformat(r["end"])
        r["rules"] = set(r["expected_rules"].split("|"))
    return rows


def _alert_stats(alerts, bad_ips):
    tp = sum(a.src_ip in bad_ips for a in alerts)
    return dict(alerts=len(alerts), tp=tp, fp=len(alerts) - tp,
                precision=tp / len(alerts) if alerts else 0.0)


def _episode_hits(alerts, truth):
    """Return {episode index: first matching alert or None}."""
    hits = {}
    for i, t in enumerate(truth):
        lo, hi = t["start_dt"] - SLACK_BEFORE, t["end_dt"] + SLACK_AFTER
        match = [a for a in alerts if a.src_ip == t["src_ip"] and a.rule_id in t["rules"]
                 and lo <= a.ts <= hi]
        hits[i] = min(match, key=lambda a: a.ts) if match else None
    return hits


def evaluate(result):
    truth = load_truth(result.truth_path)
    bad_ips = {t["src_ip"] for t in truth}
    raw, kept = result.alerts, result.kept

    raw_s, ver_s = _alert_stats(raw, bad_ips), _alert_stats(kept, bad_ips)
    raw_hits, ver_hits = _episode_hits(raw, truth), _episode_hits(kept, truth)
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
            best = max((a for a in kept if a.src_ip == t["src_ip"] and a.rule_id in t["rules"]),
                       key=lambda a: ("Attempted", "Likely", "Confirmed").index(a.verdict))
            row["verdicts"].append(best.verdict)

    ttd_all = [x for r in per_tech.values() for x in r["ttd"]]
    inc = result.incidents
    return dict(
        events=len(result.events), episodes=len(truth), raw=raw_s, verified=ver_s,
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


def render(m, sweep=None, dataset="sample_logs"):
    r, v = m["raw"], m["verified"]
    out = [f"# Evaluation results", "",
           f"Dataset: `{dataset}` ({m['events']} events, {m['episodes']} labelled episodes). "
           "Synthetic, labelled data: a controlled benchmark, not real-world performance.", "",
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
            "- Episode detected = a non-Noise alert of one of its expected rules from its IP, "
            "between start-5s and end+10min.",
            "- Time to detect is measured in log time (batch analysis): it shows how far into "
            "an episode the first verified alert lands, not wall-clock latency. Pattern rules "
            "fire on the first matching request, hence 0s; brute force needs N failures first.",
            "- The verifier never reads the ground truth; only this script does.",
            "- Generator, look-alike benign traffic and verifier were written together, "
            "so expect lower numbers on real logs."]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="sample_logs")
    ap.add_argument("--rules", default="rules.yaml")
    ap.add_argument("--year", type=int, default=2025)
    ap.add_argument("--seeds", type=int, nargs="*", default=[])
    ap.add_argument("--write", help="write markdown results to this path (inside the project)")
    a = ap.parse_args()

    result = run(a.logs, a.rules, a.year)
    if not result.truth_path:
        sys.exit(f"no ground_truth.csv in {a.logs}: nothing to evaluate against")
    m = evaluate(result)
    sweep = seed_sweep(a.seeds, a.rules, a.year) if a.seeds else None
    text = render(m, sweep, a.logs)
    print(text)
    if a.write:
        os.makedirs(os.path.dirname(a.write) or ".", exist_ok=True)
        with open(a.write, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[out] wrote {a.write}")


if __name__ == "__main__":
    main()
