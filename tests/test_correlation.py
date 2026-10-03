import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from vfde.correlation import correlate
from vfde.detections import load_rules
from vfde.detections.engine import DETECTORS
from vfde.mapping import load_compliance, load_mitre
from vfde.models import Alert

RULES = load_rules(os.path.join(os.path.dirname(__file__), "..", "rules.yaml"))
T0 = datetime(2025, 3, 14, 12, 0, 0, tzinfo=timezone.utc)
SEV = {"scan_404": "Medium", "scanner_user_agent": "Medium", "sqli_pattern": "High",
       "brute_force": "High", "success_after_failures": "Critical", "sudo_failures": "High"}


def alert(rule, verdict, off, ip="203.0.113.7"):
    return Alert(rule_id=rule, ts=T0 + timedelta(seconds=off), src_ip=ip,
                 severity=SEV[rule], mitre_id="T0", description="d",
                 verdict=verdict, reason="r", confidence=0.9)


def test_every_rule_has_mitre_and_compliance_mapping():
    mitre, comp = load_mitre(), load_compliance()
    for rule in DETECTORS:
        assert rule in mitre and rule in comp, f"missing mapping for {rule}"
        assert mitre[rule]["stage"] in RULES["correlation"]["stages"]
        assert mitre[rule]["recommendation"]
        assert comp[rule]["iso27001_2022"] and comp[rule]["rbi_csf_areas"]
    assert "incident" in comp


def test_chain_joins_stages_in_killchain_order():
    alerts = [alert("success_after_failures", "Confirmed", 600),
              alert("scan_404", "Likely", 0),
              alert("sqli_pattern", "Confirmed", 200)]
    incs = correlate(alerts, RULES)
    assert len(incs) == 1
    assert incs[0].stages == ["Reconnaissance", "Initial Access", "Compromise"]
    assert incs[0].severity == "Critical" and incs[0].verdict == "Confirmed"
    assert "T1595" in [t[0] for t in incs[0].techniques]


def test_noise_is_never_correlated():
    assert correlate([alert("sqli_pattern", "Noise", 0), alert("scan_404", "Noise", 5)], RULES) == []


def test_large_gap_splits_incidents_and_ips_stay_separate():
    gap = RULES["correlation"]["gap_seconds"]
    alerts = [alert("sqli_pattern", "Confirmed", 0),
              alert("sqli_pattern", "Confirmed", gap + 60),
              alert("sqli_pattern", "Confirmed", 5, ip="203.0.113.8")]
    assert len(correlate(alerts, RULES)) == 3


def test_attempted_only_incident_is_capped():
    incs = correlate([alert("brute_force", "Attempted", 0)], RULES)   # rule severity is High
    assert incs[0].severity == RULES["correlation"]["attempted_only_severity_cap"]


def test_multi_stage_bumps_severity_one_level():
    alerts = [alert("scan_404", "Likely", 0),                       # Medium
              alert("sqli_pattern", "Likely", 100),                 # High
              alert("sudo_failures", "Attempted", 300)]             # Post-Exploitation
    inc = correlate(alerts, RULES)[0]
    assert len(inc.stages) == 3 and inc.severity == "Critical"      # High + bump


def test_incident_carries_controls_and_ordered_recommendations():
    inc = correlate([alert("scan_404", "Likely", 0), alert("success_after_failures", "Confirmed", 60)], RULES)[0]
    assert any(c.startswith("A.5.26") for c in inc.iso_controls)
    assert "Incident response and management" in inc.rbi_areas
    assert "compromised" in inc.recommendations[0]      # most advanced stage first


def test_incidents_sorted_most_severe_first():
    alerts = [alert("scan_404", "Likely", 0, ip="203.0.113.1"),
              alert("success_after_failures", "Confirmed", 0, ip="203.0.113.2")]
    incs = correlate(alerts, RULES)
    assert [i.severity for i in incs] == ["Critical", "Medium"] and incs[0].id == "INC-001"
