import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from vfde.detections import load_rules, run_detections
from vfde.models import Event
from vfde.parsers import parse_auth_line, parse_web_line

RULES = load_rules(os.path.join(os.path.dirname(__file__), "..", "rules.yaml"))
T0 = datetime(2025, 3, 14, 12, 0, 0, tzinfo=timezone.utc)

WEB = ('203.0.113.9 - - [14/Mar/2025:12:00:01 +0000] "GET /products?id=1%27+OR+%271%27%3D%271 '
       'HTTP/1.1" 200 5123 "-" "Mozilla/5.0" rt=0.120')


def web(path, ip="10.0.1.5", status=200, ua="Mozilla/5.0", offset=0):
    return Event(ts=T0 + timedelta(seconds=offset), source="web", src_ip=ip, raw=path,
                 method="GET", path=path.split("?")[0],
                 query=path.split("?", 1)[1] if "?" in path else "", status=status,
                 bytes=100, rt=0.1, ua=ua)


def auth(action, ip="203.0.113.9", user="root", offset=0):
    return Event(ts=T0 + timedelta(seconds=offset), source="auth", src_ip=ip,
                 raw=f"{action} {ip}", user=user, action=action)


def rules_hit(events):
    return {a.rule_id for a in run_detections(events, RULES)}


# ---------- parsers ----------

def test_web_parser_decodes_and_extracts_fields():
    ev = parse_web_line(WEB)
    assert ev.src_ip == "203.0.113.9"
    assert ev.status == 200 and ev.bytes == 5123 and ev.rt == 0.12
    assert "' OR '1'='1" in ev.query


def test_web_parser_rejects_garbage():
    assert parse_web_line("not a log line") is None


def test_auth_parser_events():
    f = parse_auth_line("Mar 14 12:00:01 web01 sshd[10]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", 2025)
    assert f.action == "failed_login" and f.user == "admin" and f.src_ip == "1.2.3.4"
    a = parse_auth_line("Mar  4 02:10:00 web01 sshd[11]: Accepted password for bob from 1.2.3.4 port 22 ssh2", 2025)
    assert a.action == "accepted_login" and a.ts.day == 4 and a.ts.hour == 2


# ---------- detections: positive ----------

def test_brute_force_fires():
    assert "brute_force" in rules_hit([auth("failed_login", offset=i) for i in range(6)])


def test_success_after_failures_fires():
    evs = [auth("failed_login", offset=i) for i in range(4)] + [auth("accepted_login", offset=10)]
    assert "success_after_failures" in rules_hit(evs)


def test_scan_404_fires():
    assert "scan_404" in rules_hit([web(f"/x{i}", status=404, offset=i * 0.5) for i in range(20)])


def test_sqli_xss_traversal_fire():
    assert "sqli_pattern" in rules_hit([web("/p?id=1+UNION+SELECT+a+FROM+b".replace("+", " "))])
    assert "xss_pattern" in rules_hit([web("/s?q=<script>alert(1)</script>")])
    assert "path_traversal" in rules_hit([web("/d?file=../../../../etc/passwd")])


def test_scanner_ua_and_sudo_and_off_hours():
    assert "scanner_user_agent" in rules_hit([web("/", ua="sqlmap/1.8")])
    assert "sudo_failures" in rules_hit([auth("sudo_fail", ip="local", offset=i) for i in range(3)])
    night = Event(ts=T0.replace(hour=2), source="auth", src_ip="1.2.3.4", raw="x",
                  user="bob", action="accepted_login")
    assert "off_hours_login" in rules_hit([night])


# ---------- detections: negative ----------

def test_few_failures_do_not_fire_brute_force():
    assert "brute_force" not in rules_hit([auth("failed_login", offset=i) for i in range(3)])


def test_slow_failures_do_not_fire_brute_force():
    assert "brute_force" not in rules_hit([auth("failed_login", offset=i * 30) for i in range(6)])


def test_normal_requests_do_not_fire():
    assert not rules_hit([web("/products?id=12"), web("/about"), web("/login")])


def test_baseline_has_known_false_positives_on_tricky_benign():
    """These are the false positives the Phase 3 verification layer must remove."""
    assert "sqli_pattern" in rules_hit([web("/search?q=union select committee members")])
    assert "xss_pattern" in rules_hit([web("/search?q=how to use the <script> tag")])
    # ...while plain lookalikes stay quiet
    assert not rules_hit([web("/search?q=union budget 2025"), web("/search?q=O'Brien")])
