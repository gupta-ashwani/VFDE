"""Self-contained HTML incident report (no external assets, no JS).

Open it in a browser and use Print -> Save as PDF; print styles switch to a
light, ink-friendly layout. Every string that came from a log line is
HTML-escaped: evidence contains attack payloads such as <script> tags.
"""
import os
from datetime import datetime, timezone
from html import escape

from ..correlation import timeline
from ..mapping import load_mitre

STAGE_ORDER = ["Reconnaissance", "Initial Access", "Compromise", "Post-Exploitation"]

CSS = """
:root{
  --bg:#0d1117; --surface:#161b22; --surface-2:#1c2129; --border:#30363d;
  --ink:#e6edf3; --ink-2:#c9d1d9; --muted:#8b949e; --accent:#3d8bfd;
  --raw:#6e7681; --ver:#3d8bfd;
  --v-confirmed:#a5d6ff; --v-likely:#3d8bfd; --v-attempted:#2f5d9e; --v-noise:#30363d;
  --s-critical:#f85149; --s-high:#f0883e; --s-medium:#d29922; --s-low:#8b949e;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.55 "IBM Plex Sans","Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 16px 64px}
.hero{padding:0 0 16px;margin-bottom:8px;border-bottom:1px solid var(--border)}
.hero h1{margin:0 0 4px;font-size:22px;font-weight:600;color:var(--ink)}
.hero p{margin:0;color:var(--muted);font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.chip{background:var(--surface-2);border:1px solid var(--border);color:var(--ink-2);
  padding:1px 8px;border-radius:4px;font-size:11px}
h2{font-size:15px;font-weight:600;margin:28px 0 10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 16px}
.kpi .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.kpi .value{font-size:24px;font-weight:600;margin-top:2px;color:var(--ink)}
.kpi .sub{color:var(--ink-2);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
code,.mono{font-family:"JetBrains Mono",Consolas,monospace;font-size:12px;color:var(--ink-2);
  word-break:break-all}
.bars{display:grid;gap:10px}
.bar-row{display:grid;grid-template-columns:130px 1fr 60px;gap:10px;align-items:center;font-size:13px}
.track{height:12px;background:rgba(255,255,255,.05);border-radius:6px;overflow:hidden}
.fill{height:100%;border-radius:0 4px 4px 0}
.fill.raw{background:var(--raw)} .fill.ver{background:var(--ver)}
.legend{display:flex;gap:16px;font-size:12px;color:var(--ink-2);margin-bottom:8px}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:600;
  border:1px solid currentColor}
.sev-Critical{color:var(--s-critical)} .sev-High{color:var(--s-high)}
.sev-Medium{color:var(--s-medium)} .sev-Low{color:var(--s-low)}
.ver-Confirmed{color:var(--v-confirmed)} .ver-Likely{color:var(--v-likely)}
.ver-Attempted{color:#79a8e8} .ver-Noise{color:var(--muted)}
.incident{margin-bottom:18px}
.inc-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
.inc-head h3{margin:0;font-size:16px}
.chain{display:flex;gap:6px;margin:10px 0 14px;flex-wrap:wrap}
.stage{flex:1;min-width:120px;padding:8px 10px;border-radius:10px;font-size:12px;text-align:center;
  border:1px solid var(--border);color:var(--muted);background:rgba(255,255,255,.02)}
.stage.on{color:var(--ink);border-color:rgba(61,139,253,.55);background:rgba(61,139,253,.12);font-weight:500}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
ul{margin:6px 0 0;padding-left:18px} li{margin:3px 0}
.note{color:var(--muted);font-size:12px}
.footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
@media (max-width:700px){.cols{grid-template-columns:1fr}.bar-row{grid-template-columns:90px 1fr 44px}}
@media print{
  :root{--bg:#fff;--surface:#fff;--surface-2:#f6f8fa;--border:#d0d7de;--ink:#111;--ink-2:#333;--muted:#666;
    --v-confirmed:#0a3069;--v-likely:#0969da;--s-high:#bc4c00;--s-medium:#9a6700;--s-critical:#cf222e}
  body{font-size:12px} .incident{break-inside:avoid}
  .stage.on,.fill{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""


def _e(x):
    return escape(str(x), quote=True)


def _kpi(label, value, sub=""):
    return (f'<div class="card kpi"><div class="label">{_e(label)}</div>'
            f'<div class="value">{_e(value)}</div><div class="sub">{_e(sub)}</div></div>')


def _bars(rows):
    """rows: [(label, raw, verified)] -> paired CSS bars with numbers (never colour alone)."""
    top = max([max(r, v) for _, r, v in rows] + [1])
    out = ['<div class="legend"><span><i class="sw" style="background:var(--raw)"></i>Raw rules</span>'
           '<span><i class="sw" style="background:var(--ver)"></i>Verified</span></div><div class="bars">']
    for label, r, v in rows:
        for kind, n in (("raw", r), ("ver", v)):
            out.append(f'<div class="bar-row"><span>{_e(label) if kind == "raw" else ""}</span>'
                       f'<div class="track"><div class="fill {kind}" style="width:{100 * n / top:.1f}%"></div></div>'
                       f'<span class="mono">{n}</span></div>')
    out.append("</div>")
    return "".join(out)


def _incident(inc, mitre):
    chain = "".join(f'<div class="stage{" on" if s in inc.stages else ""}">{_e(s)}</div>'
                    for s in STAGE_ORDER)
    rows = "".join(
        f"<tr><td class='mono'>{ts:%H:%M:%S}</td><td>{_e(stage)}</td><td>{_e(rule)}</td>"
        f"<td><span class='badge ver-{_e(v)}'>{_e(v)}</span></td><td>{_e(reason)}</td></tr>"
        for ts, stage, rule, v, reason in timeline(inc, mitre))
    techs = "".join(f"<li><b>{_e(t[0])}</b> {_e(t[1])} <span class='note'>({_e(t[2])})</span></li>"
                    for t in inc.techniques)
    recs = "".join(f"<li>{_e(r)}</li>" for r in inc.recommendations)
    iso = "".join(f"<li>{_e(c)}</li>" for c in inc.iso_controls)
    rbi = "".join(f"<li>{_e(c)}</li>" for c in inc.rbi_areas)
    evidence = inc.alerts[0].evidence[:3]
    ev_html = "".join(f"<div><code>{_e(line)}</code></div>" for line in evidence)
    return f"""
<section class="card incident">
  <div class="inc-head">
    <h3>{_e(inc.id)} &middot; <span class="mono">{_e(inc.src_ip)}</span></h3>
    <span class="badge sev-{_e(inc.severity)}">{_e(inc.severity)}</span>
    <span class="badge ver-{_e(inc.verdict)}">{_e(inc.verdict)} &middot; {inc.confidence:.2f}</span>
    <span class="note">{inc.start:%Y-%m-%d %H:%M:%S} &rarr; {inc.end:%H:%M:%S} UTC &middot; {len(inc.alerts)} alerts</span>
  </div>
  <div class="chain" aria-label="Kill-chain stages">{chain}</div>
  <table><thead><tr><th>Time</th><th>Stage</th><th>Rule</th><th>Verdict</th><th>Evidence-based reason</th></tr></thead>
  <tbody>{rows}</tbody></table>
  <div class="cols" style="margin-top:14px">
    <div><b>MITRE ATT&amp;CK</b><ul>{techs}</ul></div>
    <div><b>Recommended response</b> <span class="note">(most advanced stage first)</span><ol>{recs}</ol></div>
    <div><b>ISO/IEC 27001:2022 Annex A</b><ul>{iso}</ul></div>
    <div><b>RBI CSF control areas</b> <span class="note">(names only; verify clauses)</span><ul>{rbi}</ul></div>
  </div>
  <div style="margin-top:12px"><b>Sample evidence</b>{ev_html}</div>
</section>"""


def build_report(result, metrics=None, title="Incident Report"):
    """Return the report as an HTML string. `metrics` is eval.evaluate() output (optional)."""
    mitre = load_mitre()
    kept = result.kept
    by_sev = {s: sum(i.severity == s for i in result.incidents)
              for s in ("Critical", "High", "Medium", "Low")}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    kpis = [_kpi("Events parsed", f"{len(result.events):,}",
                 f"{sum(result.unparsed.values())} unparsed lines"),
            _kpi("Raw alerts", len(result.alerts), "pattern / threshold matches"),
            _kpi("Verified alerts", len(kept), "verdict is not Noise"),
            _kpi("Incidents", len(result.incidents),
                 f"{by_sev['Critical']} critical, {by_sev['High']} high")]
    eval_html = ""
    if metrics:
        r, v = metrics["raw"], metrics["verified"]
        kpis.append(_kpi("FP reduction", f"{metrics['fp_reduction']:.0%}",
                         f"{r['fp']} -> {v['fp']} false positives"))
        eval_html = f"""
<h2>Raw rules vs verification</h2>
<div class="card">{_bars([("Alerts", r["alerts"], v["alerts"]),
                          ("False positives", r["fp"], v["fp"])])}
<table style="margin-top:14px"><thead><tr><th>Metric</th><th>Raw rules</th><th>Verified</th></tr></thead><tbody>
<tr><td>Alert precision</td><td>{r['precision']:.1%}</td><td>{v['precision']:.1%}</td></tr>
<tr><td>Episode recall</td><td>{r['recall']:.1%}</td><td>{v['recall']:.1%}</td></tr>
</tbody></table>
<p class="note">Measured against a labelled synthetic dataset; a controlled benchmark, not real-world performance.</p></div>"""

    summary_rows = "".join(
        f"<tr><td>{_e(i.id)}</td><td class='mono'>{_e(i.src_ip)}</td>"
        f"<td><span class='badge sev-{_e(i.severity)}'>{_e(i.severity)}</span></td>"
        f"<td>{_e(' -> '.join(i.stages))}</td><td>{_e(i.verdict)}</td><td>{len(i.alerts)}</td></tr>"
        for i in result.incidents)
    incidents_html = "".join(_incident(i, mitre) for i in result.incidents) or \
        '<p class="note">No incidents: every alert was judged Noise.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VFDE {_e(title)}</title><style>{CSS}</style></head>
<body><div class="wrap">
<header class="hero">
  <h1>Verification-First Detection Engine</h1>
  <p>{_e(title)} &middot; source <span class="mono" style="color:#fff">{_e(result.log_dir)}</span> &middot; generated {generated}</p>
  <div class="chips"><span class="chip">MITRE ATT&amp;CK mapped</span><span class="chip">Evidence-based verdicts</span>
  <span class="chip">Kill-chain correlation</span><span class="chip">ISO 27001 / RBI CSF context</span></div>
</header>
<h2>Executive summary</h2>
<div class="grid">{''.join(kpis)}</div>
{eval_html}
<h2>Incident overview</h2>
<div class="card"><table><thead><tr><th>ID</th><th>Source</th><th>Severity</th><th>Kill chain</th><th>Verdict</th><th>Alerts</th></tr></thead>
<tbody>{summary_rows}</tbody></table></div>
<h2>Incident details</h2>
{incidents_html}
<h2>Method and limitations</h2>
<div class="card"><ul>
<li>Batch analysis of nginx access logs and Linux auth logs; not a real-time SIEM.</li>
<li>Verdicts use log evidence only (status, size vs clean baseline, response time, probe bursts, login outcome).</li>
<li>Reflected XSS cannot be confirmed from server logs and is capped at <i>Attempted</i>.</li>
<li>Compliance lines show which controls the evidence relates to; they are not a compliance assessment.
RBI CSF entries are control areas only; verify clause numbers against the official circular.</li>
</ul></div>
<div class="footer">VFDE &middot; all testing performed on locally generated logs / an isolated lab</div>
</div></body></html>"""


def write_report(result, path, metrics=None, title="Incident Report"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_report(result, metrics, title))
    return path
