"""Tests for the fixes made after the first external (lab_v2) validation:
slow brute force, sensitive-path sweeps, executable-XSS verdicts, scanner list, allowlist."""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from test_verification import ATTACKER, RULES, USER, auth, clean_traffic, verdicts, web  # noqa: E402

from vfde.detections import run_detections  # noqa: E402
from vfde.verification import verify_alerts  # noqa: E402


def rule_ids(events):
    return {a.rule_id for a in run_detections(events, RULES)}


# ---------- slow brute force ----------

def slow_failures(users, gap=300, ip=ATTACKER):
    return [auth("failed_login", users[i % len(users)], ip, i * gap) for i in range(len(users) * 2)]


def test_slow_guessing_across_many_usernames_fires():
    evs = slow_failures(["root", "admin", "test", "deploy", "backup"])    # 10 failures / 45 min
    assert "slow_brute_force" in rule_ids(evs)
    assert "brute_force" not in rule_ids(evs), "no 60s burst ever forms"


def test_one_user_mistyping_slowly_does_not_fire():
    evs = [auth("failed_login", "carol", USER, i * 200) for i in range(10)]
    assert "slow_brute_force" not in rule_ids(evs)


def test_slow_guessing_followed_by_login_is_confirmed():
    evs = slow_failures(["root", "admin", "test", "deploy"]) + [auth("accepted_login", "deploy", ATTACKER, 3000)]
    v, _ = verdicts(evs)
    assert v["slow_brute_force"] == "Confirmed"


def test_slow_guessing_without_login_is_attempted():
    v, _ = verdicts(slow_failures(["root", "admin", "test", "deploy"]))
    assert v["slow_brute_force"] == "Attempted"


# ---------- sensitive path sweeps ----------

def probes(paths, status=404, ip=ATTACKER, ua="Mozilla/5.0"):
    return [web(p, ip=ip, status=status, ua=ua, off=i * 10) for i, p in enumerate(paths)]


def test_three_distinct_sensitive_paths_refused_fires():
    assert "sensitive_path_probe" in rule_ids(probes(["/.git/HEAD", "/admin/", "/backup.zip"]))


def test_two_sensitive_paths_do_not_fire():
    assert "sensitive_path_probe" not in rule_ids(probes(["/.git/HEAD", "/admin/"]))


def test_repeating_one_sensitive_path_does_not_fire():
    assert "sensitive_path_probe" not in rule_ids(probes(["/admin/"] * 6))


def test_admin_pages_that_are_served_do_not_fire():
    """A legitimate admin gets 200s; only refused/missing responses count."""
    evs = probes(["/admin/users", "/admin/settings", "/admin/audit"], status=200, ip=USER)
    assert "sensitive_path_probe" not in rule_ids(evs)


def test_sensitive_sweep_is_attempted_and_with_scanner_ua_likely():
    v, _ = verdicts(probes(["/.git/HEAD", "/admin/", "/backup.zip"]))
    assert v["sensitive_path_probe"] == "Attempted"
    v, _ = verdicts(probes(["/.git/HEAD", "/admin/", "/backup.zip"], ua="dirb 2.22"))
    assert v["sensitive_path_probe"] == "Likely"


def test_dirb_and_feroxbuster_are_scanner_agents():
    for ua in ("dirb 2.22", "feroxbuster/2.10"):
        assert "scanner_user_agent" in rule_ids([web("/x", ua=ua)])


# ---------- executable XSS ----------

def test_single_executable_xss_payload_is_attempted_not_noise():
    v, alerts = verdicts([web("/search?q=<script>alert(1)</script>", ip=USER)])
    assert v["xss_pattern"] == "Attempted"
    assert "executable" in alerts[0].reason


def test_single_markup_discussion_is_still_noise():
    v, _ = verdicts([web("/help?topic=<script> example </script>", ip=USER)])
    assert v["xss_pattern"] == "Noise"


# ---------- allowlist ----------

def test_allowlisted_scanner_is_noise_with_visible_reason():
    rules = copy.deepcopy(RULES)
    rules["allowlist"] = [{"source": "10.10.0.0/24", "reason": "authorised scanner"}]
    evs = [web(f"/products?id=1 union select {i}", ip="10.10.0.5", status=500, off=i * 4)
           for i in range(4)] + clean_traffic()
    alerts = verify_alerts(run_detections(evs, rules), evs, rules)
    assert alerts and all(a.verdict == "Noise" for a in alerts)
    assert all("allowlisted: authorised scanner" in a.reason for a in alerts)


def test_non_allowlisted_source_is_unaffected():
    rules = copy.deepcopy(RULES)
    rules["allowlist"] = [{"source": "10.10.0.5", "reason": "authorised scanner"}]
    evs = [web(f"/products?id=1 union select {i}", status=500, off=i * 4) for i in range(4)] + clean_traffic()
    alerts = verify_alerts(run_detections(evs, rules), evs, rules)
    assert any(a.verdict == "Confirmed" for a in alerts)


def test_allowlist_does_not_break_on_non_ip_sources():
    rules = copy.deepcopy(RULES)
    rules["allowlist"] = [{"source": "10.10.0.5", "reason": "x"}]
    evs = [auth("sudo_fail", "carol", "local", i * 20) for i in range(3)]
    alerts = verify_alerts(run_detections(evs, rules), evs, rules)
    assert alerts and alerts[0].verdict == "Attempted"
