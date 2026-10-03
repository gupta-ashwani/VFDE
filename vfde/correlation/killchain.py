"""Group verified alerts into incidents: one attacker story per source IP.

Alerts judged Noise are excluded. Alerts from one IP are split into separate
incidents whenever the gap between consecutive alerts exceeds
correlation.gap_seconds. Each incident lists the kill-chain stages it spans,
the MITRE techniques, the governance controls the evidence relates to, and
deduplicated response recommendations.
"""
from collections import defaultdict
from datetime import timedelta

from ..mapping import load_compliance, load_mitre
from ..models import Incident

SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
VERDICT_RANK = {"Attempted": 1, "Likely": 2, "Confirmed": 3}


def _dedupe(items):
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _severity(alerts, stages, cfg):
    sev = max(SEV_RANK[a.severity] for a in alerts)
    if not any(a.verdict in ("Confirmed", "Likely") for a in alerts):
        sev = min(sev, SEV_RANK[cfg["attempted_only_severity_cap"]])
    if len(stages) >= cfg["multi_stage_bump_at"]:
        sev = min(4, sev + 1)
    return RANK_SEV[sev]


def _build(idx, ip, group, mitre, compliance, cfg):
    stage_of = lambda a: mitre[a.rule_id]["stage"]
    order = cfg["stages"]
    present = {stage_of(a) for a in group}
    stages = [s for s in order if s in present]

    best = max(group, key=lambda a: (VERDICT_RANK[a.verdict], a.confidence))
    techniques = _dedupe((mitre[a.rule_id]["technique"], mitre[a.rule_id]["name"],
                          mitre[a.rule_id]["tactic"]) for a in group)
    iso = _dedupe(c for a in group for c in compliance[a.rule_id]["iso27001_2022"])
    rbi = _dedupe(c for a in group for c in compliance[a.rule_id]["rbi_csf_areas"])
    iso += [c for c in compliance["incident"]["iso27001_2022"] if c not in iso]
    rbi += [c for c in compliance["incident"]["rbi_csf_areas"] if c not in rbi]
    recs = _dedupe(mitre[a.rule_id]["recommendation"] for a in group)
    # Order recommendations so the most advanced stage is handled first.
    recs.sort(key=lambda r: -max(order.index(stage_of(a)) for a in group
                                 if mitre[a.rule_id]["recommendation"] == r))

    inc = Incident(
        id=f"INC-{idx:03d}", src_ip=ip, start=group[0].ts, end=group[-1].ts,
        stages=stages, alerts=group, severity=_severity(group, stages, cfg),
        verdict=best.verdict, confidence=best.confidence, techniques=techniques,
        iso_controls=iso, rbi_areas=rbi, recommendations=recs,
    )
    inc.summary = (f"{ip}: " + " -> ".join(stages) +
                   f" ({len(group)} alerts, {best.verdict}, {inc.severity})")
    return inc


def correlate(alerts, rules):
    """Return incidents sorted by severity (desc) then start time."""
    cfg = rules["correlation"]
    mitre, compliance = load_mitre(), load_compliance()
    gap = timedelta(seconds=cfg["gap_seconds"])

    by_ip = defaultdict(list)
    for a in sorted(alerts, key=lambda a: a.ts):
        if a.verdict in cfg["include_verdicts"]:
            by_ip[a.src_ip].append(a)

    groups = []
    for ip, ip_alerts in by_ip.items():
        current = [ip_alerts[0]]
        for a in ip_alerts[1:]:
            if a.ts - current[-1].ts > gap:
                groups.append((ip, current))
                current = []
            current.append(a)
        groups.append((ip, current))

    groups.sort(key=lambda g: g[1][0].ts)
    incidents = [_build(i, ip, grp, mitre, compliance, cfg)
                 for i, (ip, grp) in enumerate(groups, 1)]
    # Re-number after sorting so INC-001 is the most severe.
    incidents.sort(key=lambda i: (-SEV_RANK[i.severity], i.start))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:03d}"
    return incidents


def timeline(incident, mitre=None):
    """Return [(ts, stage, rule_id, verdict, reason)] for display / reports."""
    mitre = mitre or load_mitre()
    return [(a.ts, mitre[a.rule_id]["stage"], a.rule_id, a.verdict, a.reason)
            for a in incident.alerts]
