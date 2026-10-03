"""Rule-based detections. Raw alerts produced here are the BASELINE that the
verification layer (Phase 3) is later measured against.

Detectors are written event-at-a-time with sliding windows (deque) so the same
logic can be reused for a real-time mode later.
"""
import re
from collections import defaultdict, deque
from datetime import timedelta

import yaml

from ..models import Alert


def load_rules(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _sev(rule):
    return rule["severity"]


# ---------- windowed detectors ----------

def _windowed(events, pick, threshold, window_s, cooldown_s=0):
    """Yield (ts, ip, evidence) when `threshold` picked events from one IP fall
    inside `window_s`. At most one hit per IP per cooldown."""
    buckets = defaultdict(deque)
    last_alert = {}
    window = timedelta(seconds=window_s)
    cooldown = timedelta(seconds=cooldown_s)
    for ev in events:
        if not pick(ev):
            continue
        dq = buckets[ev.src_ip]
        dq.append(ev)
        while dq and ev.ts - dq[0].ts > window:
            dq.popleft()
        if len(dq) >= threshold:
            prev = last_alert.get(ev.src_ip)
            if prev is None or ev.ts - prev >= cooldown:
                last_alert[ev.src_ip] = ev.ts
                yield ev.ts, ev.src_ip, [e.raw for e in dq]


def detect_brute_force(events, rule):
    for ts, ip, ev in _windowed(
        events,
        lambda e: e.source == "auth" and e.action == "failed_login",
        rule["threshold"], rule["window_seconds"], rule.get("cooldown_seconds", 0),
    ):
        yield Alert("brute_force", ts, ip, _sev(rule), rule["mitre"],
                    f"{len(ev)} failed logins within {rule['window_seconds']}s", ev)


def detect_scan_404(events, rule):
    for ts, ip, ev in _windowed(
        events,
        lambda e: e.source == "web" and e.status == 404,
        rule["threshold"], rule["window_seconds"], rule.get("cooldown_seconds", 0),
    ):
        yield Alert("scan_404", ts, ip, _sev(rule), rule["mitre"],
                    f"{len(ev)} HTTP 404 responses within {rule['window_seconds']}s", ev)


def detect_slow_brute_force(events, rule):
    """Low-and-slow guessing: no short burst ever forms, but one IP keeps failing against
    many different usernames across a long window. Needs BOTH volume and username spread,
    so one user who keeps mistyping their own password never fires it."""
    window = timedelta(seconds=rule["window_seconds"])
    cooldown = timedelta(seconds=rule.get("cooldown_seconds", 0))
    buckets, last = defaultdict(deque), {}
    for ev in events:
        if ev.source != "auth" or ev.action != "failed_login":
            continue
        dq = buckets[ev.src_ip]
        dq.append(ev)
        while dq and ev.ts - dq[0].ts > window:
            dq.popleft()
        users = {e.user for e in dq}
        if len(dq) >= rule["min_failures"] and len(users) >= rule["min_distinct_users"]:
            prev = last.get(ev.src_ip)
            if prev is None or ev.ts - prev >= cooldown:
                last[ev.src_ip] = ev.ts
                yield Alert("slow_brute_force", ev.ts, ev.src_ip, _sev(rule), rule["mitre"],
                            f"{len(dq)} failed logins against {len(users)} usernames within "
                            f"{rule['window_seconds'] // 60} min", [e.raw for e in dq])


def detect_sensitive_paths(events, rule):
    """Sweep of DISTINCT sensitive paths that were refused or missing (not served)."""
    compiled = [re.compile(p) for p in rule["patterns"]]
    statuses = set(rule["statuses"])
    window = timedelta(seconds=rule["window_seconds"])
    cooldown = timedelta(seconds=rule.get("cooldown_seconds", 0))
    buckets, last = defaultdict(deque), {}
    for ev in events:
        if ev.source != "web" or ev.status not in statuses:
            continue
        if not any(rx.search(ev.path or "") for rx in compiled):
            continue
        dq = buckets[ev.src_ip]
        dq.append(ev)
        while dq and ev.ts - dq[0].ts > window:
            dq.popleft()
        paths = {e.path for e in dq}
        if len(paths) >= rule["min_paths"]:
            prev = last.get(ev.src_ip)
            if prev is None or ev.ts - prev >= cooldown:
                last[ev.src_ip] = ev.ts
                yield Alert("sensitive_path_probe", ev.ts, ev.src_ip, _sev(rule), rule["mitre"],
                            f"{len(paths)} distinct sensitive paths refused/missing within "
                            f"{rule['window_seconds']}s", [e.raw for e in dq])


def detect_sudo_failures(events, rule):
    for ts, ip, ev in _windowed(
        events,
        lambda e: e.source == "auth" and e.action == "sudo_fail",
        rule["threshold"], rule["window_seconds"], 300,
    ):
        yield Alert("sudo_failures", ts, ip, _sev(rule), rule["mitre"],
                    f"{len(ev)} sudo failures within {rule['window_seconds']}s", ev)


def detect_success_after_failures(events, rule):
    window = timedelta(seconds=rule["window_seconds"])
    fails = defaultdict(deque)
    for ev in events:
        if ev.source != "auth":
            continue
        if ev.action == "failed_login":
            fails[ev.src_ip].append(ev)
        elif ev.action == "accepted_login":
            dq = fails[ev.src_ip]
            while dq and ev.ts - dq[0].ts > window:
                dq.popleft()
            if len(dq) >= rule["min_failures"]:
                evidence = [e.raw for e in dq] + [ev.raw]
                yield Alert("success_after_failures", ev.ts, ev.src_ip, _sev(rule),
                            rule["mitre"],
                            f"Login succeeded for '{ev.user}' after {len(dq)} failures",
                            evidence)
                dq.clear()


# ---------- per-event pattern detectors ----------

def _pattern_detector(rule_id, rule, events, fields=("path", "query")):
    compiled = [re.compile(p) for p in rule["patterns"]]
    for ev in events:
        if ev.source != "web":
            continue
        haystack = " ".join(getattr(ev, f) or "" for f in fields)
        for rx in compiled:
            if rx.search(haystack):
                yield Alert(rule_id, ev.ts, ev.src_ip, _sev(rule), rule["mitre"],
                            f"Request matched pattern /{rx.pattern}/", [ev.raw])
                break


def detect_sqli(events, rule):
    yield from _pattern_detector("sqli_pattern", rule, events)


def detect_xss(events, rule):
    yield from _pattern_detector("xss_pattern", rule, events)


def detect_traversal(events, rule):
    yield from _pattern_detector("path_traversal", rule, events)


def detect_scanner_ua(events, rule):
    agents = [a.lower() for a in rule["agents"]]
    cooldown = timedelta(seconds=rule.get("cooldown_seconds", 0))
    last = {}
    for ev in events:
        if ev.source != "web" or not ev.ua:
            continue
        ua = ev.ua.lower()
        hit = next((a for a in agents if a in ua), None)
        if not hit:
            continue
        prev = last.get(ev.src_ip)
        if prev is None or ev.ts - prev >= cooldown:
            last[ev.src_ip] = ev.ts
            yield Alert("scanner_user_agent", ev.ts, ev.src_ip, _sev(rule),
                        rule["mitre"], f"Known scanner user-agent: {hit}", [ev.raw])


def detect_off_hours(events, rule):
    for ev in events:
        if ev.source == "auth" and ev.action == "accepted_login":
            hour = ev.ts.hour
            if rule["start_hour"] <= hour < rule["end_hour"]:
                yield Alert("off_hours_login", ev.ts, ev.src_ip, _sev(rule),
                            rule["mitre"],
                            f"Login for '{ev.user}' at {hour:02d}:00 UTC", [ev.raw])


DETECTORS = {
    "brute_force": detect_brute_force,
    "slow_brute_force": detect_slow_brute_force,
    "success_after_failures": detect_success_after_failures,
    "scan_404": detect_scan_404,
    "sensitive_path_probe": detect_sensitive_paths,
    "sqli_pattern": detect_sqli,
    "xss_pattern": detect_xss,
    "path_traversal": detect_traversal,
    "scanner_user_agent": detect_scanner_ua,
    "off_hours_login": detect_off_hours,
    "sudo_failures": detect_sudo_failures,
}


def run_detections(events, rules: dict):
    """Run every enabled rule over time-sorted events; return alerts sorted by time."""
    events = sorted(events, key=lambda e: e.ts)
    alerts = []
    for name, fn in DETECTORS.items():
        rule = rules.get(name)
        if rule and rule.get("enabled", True):
            alerts.extend(fn(events, rule))
    return sorted(alerts, key=lambda a: a.ts)
