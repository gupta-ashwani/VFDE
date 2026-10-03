"""Ground-truth loader that tolerates labels written by someone else.

Required columns (any listed alias is accepted): src_ip, start, end.
Optional: technique, mitre, expected_rules.

  * timestamps may end in "Z" or carry no timezone (naive = UTC, matching the
    UTC timestamps the parsers produce);
  * when `expected_rules` is missing or empty for any row, the evaluation uses
    "window" matching: any non-Noise alert from the labelled IP inside the
    episode's time window counts as a detection.
"""
import csv
from datetime import datetime, timezone

ALIASES = {
    "src_ip": ("src_ip", "ip", "source_ip", "attacker_ip", "client_ip"),
    "start": ("start", "start_time", "begin", "first_seen"),
    "end": ("end", "end_time", "stop", "last_seen"),
    "technique": ("technique", "attack_type", "attack", "type", "category"),
    "mitre": ("mitre", "mitre_id", "attack_id"),
    "expected_rules": ("expected_rules", "rules"),
}
REQUIRED = ("src_ip", "start", "end")


def parse_ts(value):
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_truth(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip() for h in (reader.fieldnames or [])]
        lower = {h.lower(): h for h in header}
        col = {}
        for canon, names in ALIASES.items():
            col[canon] = next((lower[n] for n in names if n in lower), None)
        missing = [c for c in REQUIRED if col[c] is None]
        if missing:
            raise ValueError(f"ground truth {path} is missing column(s) {missing}; "
                             f"found {header}. Accepted names: "
                             + "; ".join(f"{c}={ALIASES[c]}" for c in missing))
        rows = []
        for n, raw in enumerate(reader, 2):
            if not any((v or "").strip() for v in raw.values()):
                continue
            get = lambda c, d="": (raw.get(col[c]) or d).strip() if col[c] else d
            try:
                start, end = parse_ts(get("start")), parse_ts(get("end"))
            except ValueError as exc:
                raise ValueError(f"{path} line {n}: bad timestamp ({exc})") from None
            rules = {r for r in get("expected_rules").split("|") if r}
            rows.append(dict(src_ip=get("src_ip"), technique=get("technique", "unknown") or "unknown",
                             mitre=get("mitre"), start=get("start"), end=get("end"),
                             start_dt=start, end_dt=end, rules=rules,
                             expected_rules=get("expected_rules")))
    return rows


def resolve_mode(truth, requested="auto"):
    """'rules' needs expected_rules on every row; otherwise fall back to 'window'."""
    if requested == "rules" and not all(t["rules"] for t in truth):
        raise ValueError("--match rules needs an expected_rules value on every ground-truth row")
    if requested in ("rules", "window"):
        return requested
    return "rules" if truth and all(t["rules"] for t in truth) else "window"
