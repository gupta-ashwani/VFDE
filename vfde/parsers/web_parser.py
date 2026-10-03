"""Parser for the custom nginx log format defined in lab/nginx.conf:

$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
"$http_referer" "$http_user_agent" rt=$request_time
"""
import re
from datetime import datetime
from urllib.parse import unquote_plus, urlsplit

from ..models import Event

WEB_RE = re.compile(
    r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"(?: rt=(?P<rt>[\d.]+))?\s*$'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _decode(value: str, rounds: int = 2) -> str:
    """URL-decode repeatedly so double-encoded payloads are also visible."""
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def parse_web_line(line: str):
    """Return an Event, or None if the line does not match the format."""
    m = WEB_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], TS_FORMAT)
    except ValueError:
        return None
    parts = urlsplit(m["url"])
    return Event(
        ts=ts,
        source="web",
        src_ip=m["ip"],
        raw=line.strip(),
        user=None if m["user"] == "-" else m["user"],
        method=m["method"],
        path=_decode(parts.path),
        query=_decode(parts.query),
        status=int(m["status"]),
        bytes=int(m["bytes"]),
        rt=float(m["rt"]) if m["rt"] else None,
        ua=m["ua"],
    )


def parse_web_file(path: str):
    """Return (events, unparsed_count). Unparsed lines are counted, never silently dropped."""
    events, unparsed = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            ev = parse_web_line(line)
            if ev:
                events.append(ev)
            else:
                unparsed += 1
    return events, unparsed
