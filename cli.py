"""Usage:
    python cli.py analyze --logs sample_logs [--rules rules.yaml] [--year 2025] [--json out.json]
    python cli.py report  --logs sample_logs [--out reports/incident_report.html]
"""
import argparse
import json
import os
import sys
from collections import Counter

from vfde.detections import load_rules, run_detections
from vfde.pipeline import load_events


def cmd_analyze(args):
    rules = load_rules(args.rules)
    events, _ = load_events(args.logs, args.year)
    alerts = run_detections(events, rules)
    args.verify = args.verify or args.correlate     # correlation needs verdicts
    truth = os.path.join(args.logs, "ground_truth.csv")
    if args.verify:
        from vfde.verification import verify_alerts
        verify_alerts(alerts, events, rules)

    print(f"\n[detect] {len(alerts)} raw alerts from {len(events)} events")
    by_rule = Counter(a.rule_id for a in alerts)
    for rule, n in by_rule.most_common():
        print(f"  {rule:<24} {n}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([{**a.__dict__, "ts": a.ts.isoformat()} for a in alerts], fh, indent=2)
        print(f"[out] wrote {args.json}")

    if os.path.exists(truth):
        from eval_baseline import baseline_report, before_after_report
        baseline_report(alerts, truth)
        if args.verify:
            before_after_report(alerts, truth)

    if args.correlate:
        from vfde.correlation import correlate, timeline
        incidents = correlate(alerts, rules)
        if os.path.exists(truth):
            from eval_baseline import incident_report
            incident_report(alerts, incidents, truth)
        print(f"\n=== INCIDENTS ({len(incidents)}) ===")
        for inc in incidents:
            print(f"\n{inc.id}  [{inc.severity}]  {inc.summary}")
            print(f"   window : {inc.start:%H:%M:%S} - {inc.end:%H:%M:%S}   "
                  f"confidence {inc.confidence:.2f}")
            print("   MITRE  : " + ", ".join(f"{t[0]} {t[1]}" for t in inc.techniques))
            if args.show:
                for ts, stage, rule, verdict, reason in timeline(inc):
                    print(f"     {ts:%H:%M:%S}  {stage:<17} {rule:<22} {verdict:<9} {reason[:70]}")
                print("   ISO 27001: " + "; ".join(inc.iso_controls))
                print("   RBI areas: " + "; ".join(inc.rbi_areas))
                for n, r in enumerate(inc.recommendations, 1):
                    print(f"   fix {n}  : {r}")

    if args.verify:
        print("\nverdicts:", dict(Counter(a.verdict for a in alerts)))
        if args.show:
            for a in alerts:
                if a.verdict != "Noise":
                    print(f"  [{a.verdict:<9} {a.confidence:.2f}] {a.src_ip:<15} "
                          f"{a.rule_id:<22} {a.reason}")


def cmd_report(args):
    from vfde.pipeline import run
    from vfde.reporting import write_report
    result = run(args.logs, args.rules, args.year, log=print)
    metrics = None
    if result.truth_path:
        from eval import evaluate
        metrics = evaluate(result)
    path = write_report(result, args.out, metrics)
    print(f"[report] {len(result.incidents)} incidents -> {path}")
    print("         open it in a browser; Print -> Save as PDF for a PDF copy")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("report", help="write the HTML incident report")
    rp.add_argument("--logs", default="sample_logs")
    rp.add_argument("--rules", default="rules.yaml")
    rp.add_argument("--year", type=int, default=2025)
    rp.add_argument("--out", default="reports/incident_report.html")
    rp.set_defaults(fn=cmd_report)
    an = sub.add_parser("analyze")
    an.add_argument("--logs", default="sample_logs")
    an.add_argument("--rules", default="rules.yaml")
    an.add_argument("--year", type=int, default=2025)
    an.add_argument("--json")
    an.add_argument("--verify", action="store_true", help="run the verification layer")
    an.add_argument("--correlate", action="store_true",
                    help="group verified alerts into kill-chain incidents (implies --verify)")
    an.add_argument("--show", action="store_true",
                    help="with --verify/--correlate: print alert and incident detail")
    an.set_defaults(fn=cmd_analyze)
    args = ap.parse_args()
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
