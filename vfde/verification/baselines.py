"""Response baselines built from CLEAN traffic only.

"Clean" = events from source IPs that no detection rule flagged. The ground
truth is never used, so the baseline is something a real deployment could
compute too. Per-path baselines are used when enough samples exist, otherwise
the global baseline applies.
"""
from collections import defaultdict


def _percentile(values, pct):
    if not values:
        return None
    s = sorted(values)
    k = min(len(s) - 1, max(0, round(pct / 100 * (len(s) - 1))))
    return s[k]


class Baselines:
    def __init__(self, events, alerts, cfg):
        self.min_samples = cfg["baseline_min_samples"]
        pct = cfg["baseline_size_percentile"]
        flagged = {a.src_ip for a in alerts}
        by_path, all_sizes = defaultdict(list), []
        for e in events:
            if e.source != "web" or e.src_ip in flagged:
                continue
            if e.status == 200 and e.bytes is not None:
                by_path[e.path].append(e.bytes)
                all_sizes.append(e.bytes)
        self.global_p = _percentile(all_sizes, pct) or 0
        self.path_p = {p: _percentile(v, pct) for p, v in by_path.items()
                       if len(v) >= self.min_samples}
        self.samples = {p: len(v) for p, v in by_path.items()}

    def size_limit(self, path):
        """Return (p95 size, scope) for this path, falling back to global."""
        if path in self.path_p:
            return self.path_p[path], "path"
        return self.global_p, "global"
