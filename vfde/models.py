from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    ts: datetime
    source: str                      # "web" | "auth"
    src_ip: str
    raw: str
    user: Optional[str] = None
    action: Optional[str] = None     # auth: failed_login | accepted_login | invalid_user | sudo_fail
    method: Optional[str] = None
    path: Optional[str] = None       # decoded path
    query: Optional[str] = None      # decoded query string
    status: Optional[int] = None
    bytes: Optional[int] = None
    rt: Optional[float] = None       # request time in seconds
    ua: Optional[str] = None


@dataclass
class Incident:
    id: str
    src_ip: str
    start: datetime
    end: datetime
    stages: list                     # kill-chain stages seen, in kill-chain order
    alerts: list                     # non-Noise alerts, time-ordered
    severity: str
    verdict: str                     # strongest verdict among the alerts
    confidence: float
    techniques: list = field(default_factory=list)       # [(id, name, tactic)]
    iso_controls: list = field(default_factory=list)
    rbi_areas: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    summary: str = ""


@dataclass
class Alert:
    rule_id: str
    ts: datetime
    src_ip: str
    severity: str                    # Low | Medium | High | Critical
    mitre_id: str
    description: str
    evidence: list = field(default_factory=list)   # raw log lines
    verdict: str = "Unverified"      # Confirmed | Likely | Attempted | Noise (Phase 3)
    reason: str = ""                 # human-readable evidence behind the verdict
    confidence: float = 0.0          # 0..1, set by the verification layer
