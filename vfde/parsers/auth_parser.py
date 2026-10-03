"""Parser for Linux auth.log (syslog) lines: sshd and sudo events.

Syslog timestamps carry no year, so the caller passes one in.
"""
import re
from datetime import datetime, timezone

from ..models import Event

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SUDO_FAIL_RE = re.compile(
    r"(?P<user>\S+) : (?:\d+ incorrect password attempts? ; |user NOT in sudoers ; ).*"
)


def parse_auth_line(line: str, year: int):
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    msg, proc = m["msg"], m["proc"]
    base = dict(ts=ts, source="auth", raw=line.strip())

    if proc.startswith("sshd"):
        if (f := FAILED_RE.search(msg)):
            return Event(src_ip=f["ip"], user=f["user"], action="failed_login", **base)
        if (a := ACCEPTED_RE.search(msg)):
            return Event(src_ip=a["ip"], user=a["user"], action="accepted_login", **base)
        if (i := INVALID_RE.search(msg)):
            return Event(src_ip=i["ip"], user=i["user"], action="invalid_user", **base)
    elif proc == "sudo":
        if (s := SUDO_FAIL_RE.search(msg)):
            return Event(src_ip="local", user=s["user"], action="sudo_fail", **base)
    return None


def parse_auth_file(path: str, year: int):
    """Return (events, unparsed_count). Lines that are valid syslog but irrelevant
    (e.g. session open/close) are not counted as unparsed."""
    events, unparsed = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            ev = parse_auth_line(line, year)
            if ev:
                events.append(ev)
            elif not SYSLOG_RE.match(line.strip()):
                unparsed += 1
    return events, unparsed
