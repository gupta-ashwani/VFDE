"""Verification layer: turns a raw pattern/threshold match into an evidence-backed verdict.

Verdicts
  Confirmed  evidence shows the activity succeeded or had impact
  Likely     strong signs of malicious activity, impact not proven
  Attempted  malicious-looking activity, no sign it worked
  Noise      matches a rule but behaves like legitimate traffic (suppressed)

Every verdict carries a reason string. Limitation (by design): reflected XSS
cannot be confirmed from server logs alone, so XSS is capped at Attempted.
"""
from collections import defaultdict
from datetime import timedelta
from posixpath import splitext

from .baselines import Baselines

VERDICTS = ("Confirmed", "Likely", "Attempted", "Noise")
BASE_CONF = {"Confirmed": 0.95, "Likely": 0.75, "Attempted": 0.50, "Noise": 0.10}
PATTERN_RULES = {"sqli_pattern", "xss_pattern", "path_traversal"}


class _Ctx:
    """Shared lookups so each verdict can inspect the surrounding activity."""

    def __init__(self, events, alerts, cfg):
        self.cfg = cfg
        self.base = Baselines(events, alerts, cfg)
        self.raw = {e.raw: e for e in events}
        self.events_by_ip = defaultdict(list)
        for e in events:
            self.events_by_ip[e.src_ip].append(e)
        self.alerts_by_ip = defaultdict(list)
        for a in alerts:
            self.alerts_by_ip[a.src_ip].append(a)

    def evidence_events(self, alert):
        return [self.raw[r] for r in alert.evidence if r in self.raw]

        self.corroborate = True        # pass 1 runs with this off
        self.dismissed = set()         # id() of alerts judged Noise in pass 1

    def other_rules(self, alert, exclude=()):
        """Rules from the same IP that can corroborate this alert. Alerts already
        judged Noise never corroborate anything (a suppressed signal is not evidence)."""
        if not self.corroborate:
            return set()
        return {a.rule_id for a in self.alerts_by_ip[alert.src_ip]
                if a.rule_id != alert.rule_id and a.rule_id not in exclude
                and id(a) not in self.dismissed}


def _result(verdict, reason, bonus=0.0):
    return verdict, reason, round(min(0.99, BASE_CONF[verdict] + bonus), 2)


def _impact(ev, ctx):
    """Return a string describing impact evidence in one web event, or None."""
    c = ctx.cfg
    if ev.status is not None and ev.status >= c["impact_status"]:
        return f"HTTP {ev.status} on injected input"
    if ev.rt is not None and ev.rt >= c["impact_rt_seconds"]:
        return f"response took {ev.rt:.1f}s (>= {c['impact_rt_seconds']}s, time-based behaviour)"
    if ev.status == 200 and ev.bytes is not None:
        limit, scope = ctx.base.size_limit(ev.path)
        if limit and ev.bytes > limit * c["impact_size_multiplier"]:
            return (f"response {ev.bytes}B vs clean {scope} p"
                    f"{c['baseline_size_percentile']} {limit}B (x{ev.bytes / limit:.1f})")
    return None


# ---------- per-rule verifiers ----------

def verify_pattern(alert, ctx):
    c = ctx.cfg
    window = timedelta(seconds=c["cluster_window_seconds"])
    burst = [a for a in ctx.alerts_by_ip[alert.src_ip]
             if a.rule_id in PATTERN_RULES and abs(a.ts - alert.ts) <= window]
    n = len(burst)
    impacts = []
    for a in burst:
        for ev in ctx.evidence_events(a):
            why = _impact(ev, ctx)
            if why:
                impacts.append(why)
    corroborating = ctx.other_rules(alert, exclude=PATTERN_RULES | {"off_hours_login"})
    extra = (f"; same IP also tripped {sorted(corroborating)}" if corroborating else "")

    if alert.rule_id == "xss_pattern":
        if n >= c["cluster_attempted"]:
            return _result("Attempted",
                           f"{n} XSS probes in {c['cluster_window_seconds']}s; reflected XSS "
                           f"cannot be confirmed from server logs{extra}")
        return _result("Noise", "single XSS-like string, no repeated probing; could be a "
                                "user discussing markup")

    if impacts and n >= c["cluster_attempted"]:
        return _result("Confirmed", f"{n} probes in burst and impact evidence: {impacts[0]}{extra}",
                       min(0.04, 0.01 * len(impacts)))
    if impacts:
        return _result("Likely", f"single probe with impact evidence: {impacts[0]}{extra}")
    if n >= c["cluster_likely"]:
        return _result("Likely", f"{n} probes in {c['cluster_window_seconds']}s from one IP, "
                                 f"no impact evidence yet{extra}")
    if n >= c["cluster_attempted"] or corroborating:
        return _result("Attempted", f"{n} probe(s), responses look normal{extra}")
    return _result("Noise", "isolated match; status/size/time within clean baseline and no "
                            "other suspicious activity from this IP")


def _auth_profile(events, cfg):
    users = {e.user for e in events if e.action in ("failed_login", "invalid_user")}
    times = sorted(e.ts for e in events if e.action == "failed_login")
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    avg = sum(gaps) / len(gaps) if gaps else None
    automated = (len(users) >= cfg["min_distinct_users"]
                 or (avg is not None and avg < cfg["automated_interval_seconds"]))
    return users, avg, automated


def verify_brute_force(alert, ctx):
    c = ctx.cfg
    evs = ctx.evidence_events(alert)
    users, avg, automated = _auth_profile(evs, c)
    succeeded = any(a.rule_id == "success_after_failures" and a.ts >= alert.ts
                    for a in ctx.alerts_by_ip[alert.src_ip])
    pace = f"{avg:.1f}s apart" if avg is not None else "n/a"
    if not automated:
        return _result("Noise", f"{len(evs)} failures for {len(users)} user(s), {pace}: "
                                f"human-paced, consistent with typos")
    if succeeded:
        return _result("Confirmed", f"scripted guessing ({len(users)} usernames, {pace}) "
                                    f"followed by a successful login from the same IP")
    return _result("Attempted", f"scripted guessing ({len(users)} usernames, {pace}); "
                                f"no successful login seen")


def verify_success_after_failures(alert, ctx):
    c = ctx.cfg
    evs = ctx.evidence_events(alert)
    fails = [e for e in evs if e.action == "failed_login"]
    accept = next((e for e in reversed(evs) if e.action == "accepted_login"), None)
    users, avg, automated = _auth_profile(fails, c)
    same_user = accept is not None and users == {accept.user}
    if (not automated and same_user and len(fails) <= c["max_user_typo_failures"]):
        return _result("Noise", f"{len(fails)} failures then success, all for user "
                                f"'{accept.user}', human-paced: user typo / forgotten password")
    pace = f"{avg:.1f}s apart" if avg is not None else "n/a"
    return _result("Confirmed", f"success for '{accept.user if accept else '?'}' after "
                                f"{len(fails)} failures across {len(users)} usernames ({pace}): "
                                f"likely account compromise", 0.03)


def verify_scan_404(alert, ctx):
    c = ctx.cfg
    evs = ctx.evidence_events(alert)
    statics = set(c["static_extensions"])
    if evs and all(splitext(e.path or "")[1].lower() in statics for e in evs):
        return _result("Noise", f"{len(evs)} 404s but every path is a static asset: "
                                f"broken page, not enumeration")
    if "scanner_user_agent" in ctx.other_rules(alert):
        return _result("Likely", f"{len(evs)} 404s on non-asset paths with a known scanner "
                                 f"user-agent from the same IP")
    return _result("Attempted", f"{len(evs)} 404s on non-asset paths; enumeration pattern")


def verify_scanner_ua(alert, ctx):
    c = ctx.cfg
    web = [e for e in ctx.events_by_ip[alert.src_ip] if e.source == "web"]
    paths = {e.path for e in web}
    errors = [e for e in web if e.status is not None and e.status >= 400]
    others = ctx.other_rules(alert, exclude={"off_hours_login"})
    if others:
        return _result("Likely", f"scanner user-agent and same IP tripped {sorted(others)}")
    if len(paths) <= c["healthcheck_max_paths"] and not errors:
        return _result("Noise", f"tool-like user-agent but only {len(paths)} path(s) requested, "
                                f"no errors: looks like a health-check monitor")
    return _result("Attempted", f"scanner user-agent across {len(paths)} paths, "
                                f"{len(errors)} error responses")


def verify_off_hours(alert, ctx):
    others = ctx.other_rules(alert, exclude={"off_hours_login"})
    if others:
        return _result("Likely", f"off-hours login and same IP tripped {sorted(others)}")
    return _result("Noise", "off-hours login with no failures or other alerts from this IP; "
                            "kept as informational only")


def verify_sudo(alert, ctx):
    return _result("Attempted", f"{len(alert.evidence)} sudo failures; no evidence of "
                                f"successful escalation in these logs")


VERIFIERS = {
    "sqli_pattern": verify_pattern,
    "xss_pattern": verify_pattern,
    "path_traversal": verify_pattern,
    "brute_force": verify_brute_force,
    "success_after_failures": verify_success_after_failures,
    "scan_404": verify_scan_404,
    "scanner_user_agent": verify_scanner_ua,
    "off_hours_login": verify_off_hours,
    "sudo_failures": verify_sudo,
}


def verify_alerts(alerts, events, rules):
    """Annotate each alert with verdict / reason / confidence (in place) and return them."""
    cfg = rules["verification"]
    ctx = _Ctx(events, alerts, cfg)

    def run_pass():
        for a in alerts:
            fn = VERIFIERS.get(a.rule_id)
            if fn is None:
                a.verdict, a.reason, a.confidence = "Attempted", "no verifier for this rule", 0.5
            else:
                a.verdict, a.reason, a.confidence = fn(a, ctx)

    ctx.corroborate = False            # pass 1: each alert judged on its own evidence
    run_pass()
    ctx.dismissed = {id(a) for a in alerts if a.verdict == "Noise"}
    ctx.corroborate = True             # pass 2: corroborate only with non-Noise alerts
    run_pass()
    return alerts
