"""Baseline (raw rules) evaluation against ground_truth.csv.

An alert is a TRUE positive if its source IP appears in the ground truth.
Any alert from an IP that is not in the ground truth is a FALSE positive.
An episode is DETECTED if at least one alert came from its IP.
Phase 5's eval.py will extend this with per-technique metrics and compare
against the verified alerts.
"""
from collections import Counter

from vfde.truth import load_truth  # tolerant loader shared with eval.py


def baseline_report(alerts, truth_path):
    truth = load_truth(truth_path)
    bad_ips = {t["src_ip"] for t in truth}

    tp = [a for a in alerts if a.src_ip in bad_ips]
    fp = [a for a in alerts if a.src_ip not in bad_ips]
    detected_ips = {a.src_ip for a in tp}
    detected = [t for t in truth if t["src_ip"] in detected_ips]

    precision = len(tp) / len(alerts) if alerts else 0.0
    recall = len(detected) / len(truth) if truth else 0.0

    print("\n=== BASELINE (raw rules, before verification) ===")
    print(f"alerts total        : {len(alerts)}")
    print(f"true positives      : {len(tp)}")
    print(f"false positives     : {len(fp)}")
    print(f"alert precision     : {precision:.1%}")
    print(f"episode recall      : {len(detected)}/{len(truth)} = {recall:.1%}")

    if fp:
        print("\nfalse positives by rule:")
        for rule, n in Counter(a.rule_id for a in fp).most_common():
            print(f"  {rule:<24} {n}")

    missed = [t for t in truth if t["src_ip"] not in detected_ips]
    if missed:
        print("\nmissed episodes:")
        for t in missed:
            print(f"  {t['src_ip']}  {t['technique']}")
    return dict(alerts=len(alerts), tp=len(tp), fp=len(fp),
                precision=precision, recall=recall)


def incident_report(raw_alerts, incidents, truth_path):
    """Incident-level view: how much analyst workload shrinks and whether every
    labelled episode ends up inside an incident."""
    truth = load_truth(truth_path)
    bad_ips = {t["src_ip"] for t in truth}
    inc_ips = {i.src_ip for i in incidents}
    false_inc = [i for i in incidents if i.src_ip not in bad_ips]
    covered = [t for t in truth if t["src_ip"] in inc_ips]

    print("\n=== INCIDENT LEVEL ===")
    print(f"raw alerts           : {len(raw_alerts)}")
    print(f"incidents            : {len(incidents)}  "
          f"({len(raw_alerts) / len(incidents):.1f} raw alerts per incident)" if incidents
          else "incidents            : 0")
    print(f"episodes covered     : {len(covered)}/{len(truth)}")
    print(f"false incidents      : {len(false_inc)}")
    multi = [i for i in incidents if len(i.stages) > 1]
    print(f"multi-stage incidents: {len(multi)}")
    for i in false_inc[:5]:
        print(f"  false incident {i.id}: {i.summary}")
    return dict(incidents=len(incidents), covered=len(covered), false_incidents=len(false_inc))


def _stats(alerts, truth):
    bad_ips = {t["src_ip"] for t in truth}
    tp = [a for a in alerts if a.src_ip in bad_ips]
    detected = {a.src_ip for a in tp}
    return dict(
        alerts=len(alerts), tp=len(tp), fp=len(alerts) - len(tp),
        precision=len(tp) / len(alerts) if alerts else 0.0,
        recall=sum(t["src_ip"] in detected for t in truth) / len(truth) if truth else 0.0,
    )


def before_after_report(alerts, truth_path):
    """Compare raw rules vs verified alerts (verdict != Noise). Needs verify_alerts() first."""
    truth = load_truth(truth_path)
    raw = _stats(alerts, truth)
    kept = [a for a in alerts if a.verdict != "Noise"]
    ver = _stats(kept, truth)
    conf = _stats([a for a in alerts if a.verdict == "Confirmed"], truth)

    print("\n=== BEFORE vs AFTER VERIFICATION ===")
    print(f"{'':<22}{'raw rules':>12}{'verified':>12}")
    print(f"{'alerts':<22}{raw['alerts']:>12}{ver['alerts']:>12}")
    print(f"{'false positives':<22}{raw['fp']:>12}{ver['fp']:>12}")
    print(f"{'alert precision':<22}{raw['precision']:>12.1%}{ver['precision']:>12.1%}")
    print(f"{'episode recall':<22}{raw['recall']:>12.1%}{ver['recall']:>12.1%}")
    cut = (raw["fp"] - ver["fp"]) / raw["fp"] if raw["fp"] else 0.0
    print(f"\nfalse-positive reduction : {cut:.1%}")
    print(f"'Confirmed' alerts       : {conf['alerts']} (precision {conf['precision']:.1%})")

    bad_ips = {t["src_ip"] for t in truth}
    fp_left = [a for a in kept if a.src_ip not in bad_ips]
    if fp_left:
        print("\nremaining false positives (verdict, rule, reason):")
        for a in fp_left[:10]:
            print(f"  {a.verdict:<9} {a.rule_id:<22} {a.reason[:90]}")
    suppressed_bad = [a for a in alerts if a.verdict == "Noise" and a.src_ip in bad_ips]
    if suppressed_bad:
        print(f"\nattack alerts wrongly suppressed as Noise: {len(suppressed_bad)}")
        for a in suppressed_bad[:10]:
            print(f"  {a.rule_id:<22} {a.reason[:90]}")
    return dict(raw=raw, verified=ver, confirmed=conf, fp_reduction=cut)
