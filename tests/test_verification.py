import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from vfde.detections import load_rules, run_detections
from vfde.models import Event
from vfde.verification import verify_alerts

RULES = load_rules(os.path.join(os.path.dirname(__file__), "..", "rules.yaml"))
T0 = datetime(2025, 3, 14, 12, 0, 0, tzinfo=timezone.utc)
ATTACKER, USER = "203.0.113.50", "10.0.1.20"


def web(path, ip=ATTACKER, status=200, size=1500, rt=0.1, ua="Mozilla/5.0", off=0.0):
    url_path, _, query = path.partition("?")
    return Event(ts=T0 + timedelta(seconds=off), source="web", src_ip=ip,
                 raw=f"{ip} {path} @{off}", method="GET", path=url_path, query=query,
                 status=status, bytes=size, rt=rt, ua=ua)


def auth(action, user, ip, off):
    return Event(ts=T0 + timedelta(seconds=off), source="auth", src_ip=ip,
                 raw=f"{action} {user} {ip} @{off}", user=user, action=action)


def clean_traffic():
    """Baseline material: clean IPs hitting /p with small responses."""
    return [web("/p", ip=f"10.0.5.{i}", size=1000 + i * 10, off=-1000 - i) for i in range(40)]


def verdicts(events):
    events = events + clean_traffic()
    alerts = verify_alerts(run_detections(events, RULES), events, RULES)
    return {(a.rule_id): a.verdict for a in alerts}, alerts


def test_isolated_sqli_lookalike_is_noise():
    v, _ = verdicts([web("/search?q=union select committee members", ip=USER)])
    assert v["sqli_pattern"] == "Noise"


def test_sqli_burst_with_server_error_is_confirmed():
    evs = [web(f"/products?id=1 union select {i}", status=500 if i == 2 else 200, off=i * 4)
           for i in range(4)]
    v, alerts = verdicts(evs)
    assert v["sqli_pattern"] == "Confirmed"
    assert all(a.reason for a in alerts), "every verdict needs a reason"


def test_time_based_probe_is_impact():
    evs = [web("/p?id=1;select sleep(5)--", rt=5.1, off=0), web("/p?id=2 or 1=1", off=3)]
    v, _ = verdicts(evs)
    assert v["sqli_pattern"] == "Confirmed"


def test_xss_never_confirmed():
    evs = [web(f"/s?q=<script>alert({i})</script>", off=i * 3) for i in range(5)]
    v, _ = verdicts(evs)
    assert v["xss_pattern"] == "Attempted"


def test_user_typo_then_success_is_noise():
    evs = [auth("failed_login", "alice", USER, i * 6) for i in range(6)]
    evs.append(auth("accepted_login", "alice", USER, 40))
    v, _ = verdicts(evs)
    assert v["brute_force"] == "Noise" and v["success_after_failures"] == "Noise"


def test_scripted_guessing_then_success_is_confirmed():
    names = ["root", "admin", "test", "oracle", "ubuntu", "postgres"]
    evs = [auth("failed_login", names[i % 6], ATTACKER, i * 2) for i in range(12)]
    evs.append(auth("accepted_login", "deploy", ATTACKER, 28))
    v, _ = verdicts(evs)
    assert v["brute_force"] == "Confirmed" and v["success_after_failures"] == "Confirmed"


def test_scripted_guessing_without_success_is_only_attempted():
    names = ["root", "admin", "test", "oracle"]
    evs = [auth("failed_login", names[i % 4], ATTACKER, i * 2) for i in range(10)]
    v, _ = verdicts(evs)
    assert v["brute_force"] == "Attempted"


def test_static_asset_404_burst_is_noise_but_enumeration_is_not():
    assets = [web(f"/static/img/m{i}.png", ip=USER, status=404, off=i * 0.8) for i in range(20)]
    v, _ = verdicts(assets)
    assert v["scan_404"] == "Noise"
    enum = [web(f"/admin{i}", status=404, off=i * 0.5) for i in range(20)]
    v, _ = verdicts(enum)
    assert v["scan_404"] in ("Attempted", "Likely")


def test_healthcheck_with_tool_ua_is_noise_scanner_is_not():
    monitor = [web("/health", ip="10.0.9.9", size=15, ua="Nmap Scripting Engine", off=i * 3600)
               for i in range(5)]
    v, _ = verdicts(monitor)
    assert v["scanner_user_agent"] == "Noise"
    scan = [web(f"/x{i}", status=404, ua="sqlmap/1.8", off=i) for i in range(5)]
    v, _ = verdicts(scan)
    assert v["scanner_user_agent"] in ("Attempted", "Likely")


def test_noise_alert_does_not_corroborate_another():
    """A suppressed broken-page 404 burst must not upgrade an isolated SQLi lookalike."""
    evs = [web(f"/static/img/m{i}.png", ip=USER, status=404, off=i * 0.8) for i in range(20)]
    evs.append(web("/search?q=union select committee", ip=USER, off=500))
    v, _ = verdicts(evs)
    assert v["scan_404"] == "Noise" and v["sqli_pattern"] == "Noise"
