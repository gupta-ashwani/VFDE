"""One entry point for the whole pipeline: parse -> detect -> verify -> correlate.

Shared by cli.py, eval.py, the Streamlit dashboard and the HTML report so they
can never disagree about the numbers.
"""
import os
from dataclasses import dataclass, field

from .correlation import correlate
from .detections import load_rules, run_detections
from .parsers import parse_auth_file, parse_web_file
from .verification import verify_alerts


@dataclass
class RunResult:
    events: list
    unparsed: dict
    alerts: list                 # every raw alert, annotated with verdicts
    incidents: list
    rules: dict
    log_dir: str
    truth_path: str = None       # ground_truth.csv if present
    notes: list = field(default_factory=list)

    @property
    def kept(self):
        """Alerts an analyst would actually see (verdict != Noise)."""
        return [a for a in self.alerts if a.verdict != "Noise"]


def load_events(log_dir, year, log=print):
    events, unparsed = [], {}
    for name, parser in (("access.log", parse_web_file),
                         ("auth.log", lambda p: parse_auth_file(p, year))):
        path = os.path.join(log_dir, name)
        if os.path.exists(path):
            evs, bad = parser(path)
            events.extend(evs)
            unparsed[name] = bad
            log(f"[parse] {name}: {len(evs)} events, {bad} unparsed lines")
        else:
            log(f"[parse] {name}: not found, skipped")
    return events, unparsed


def run(log_dir, rules_path="rules.yaml", year=2025, verify=True, do_correlate=True,
        log=lambda *_: None):
    rules = load_rules(rules_path)
    events, unparsed = load_events(log_dir, year, log)
    alerts = run_detections(events, rules)
    incidents = []
    if verify or do_correlate:
        verify_alerts(alerts, events, rules)
    if do_correlate:
        incidents = correlate(alerts, rules)
    truth = os.path.join(log_dir, "ground_truth.csv")
    return RunResult(events, unparsed, alerts, incidents, rules, log_dir,
                     truth if os.path.exists(truth) else None)
