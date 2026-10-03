"""VFDE detection console (Streamlit).

    streamlit run app.py

Reads sample_logs/ by default, or uploaded access.log / auth.log / ground_truth.csv.
All numbers come from vfde.pipeline + eval.evaluate, the same code the CLI uses.

Design: neutral dark console in the style of common SOC tools. One accent
colour (blue) for "verified"; reserved status colours for severity, always
paired with a text label; no gradients.
"""
import hashlib
import os
from collections import Counter
from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from eval import evaluate
from vfde.correlation import timeline
from vfde.mapping import load_mitre
from vfde.pipeline import run
from vfde.reporting import build_report

ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(ROOT, ".uploads")          # uploads stay inside the project folder

# ---------- design tokens ----------
BG, PANEL, PANEL_2, BORDER = "#0d1117", "#161b22", "#1c2129", "#30363d"
INK, INK_2, MUTED = "#e6edf3", "#c9d1d9", "#8b949e"
GRID = "#21262d"
ACCENT = "#3d8bfd"
RAW = "#6e7681"                                   # raw rule output: neutral grey
# Verdicts are ordinal: one blue hue, dim -> bright.
VERDICT = {"Noise": "#30363d", "Attempted": "#2f5d9e", "Likely": "#3d8bfd", "Confirmed": "#a5d6ff"}
# Severity: reserved status palette, never reused for anything else.
SEVERITY = {"Critical": "#f85149", "High": "#f0883e", "Medium": "#d29922", "Low": "#8b949e"}
STAGES = ["Reconnaissance", "Initial Access", "Compromise", "Post-Exploitation"]

CSS = f"""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
html, body, .stApp, .stMarkdown, button, input, textarea, select {{ font-family: 'IBM Plex Sans', system-ui, sans-serif; }}
.stApp {{ background: {BG}; }}
.block-container {{ padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1400px; }}
header[data-testid="stHeader"] {{ background: transparent; height: 0; }}
#MainMenu, footer, .stDeployButton, [data-testid="stAppDeployButton"] {{ display: none !important; }}
[data-testid="stSidebar"] {{ background: {PANEL}; border-right: 1px solid {BORDER}; }}
[data-testid="stSidebarHeader"] {{ height: 2.25rem; padding: .5rem 1rem 0; }}
[data-testid="stSidebarUserContent"] {{ padding-top: 0 !important; }}
[data-testid="stSidebar"] hr {{ margin: 14px 0; border-color: {BORDER}; }}
.side-h {{ font-size: 11px; font-weight: 600; color: {MUTED}; text-transform: uppercase; letter-spacing: .06em;
  margin: 4px 0 8px; }}
.side-kv {{ display: grid; grid-template-columns: 70px 1fr; gap: 4px 8px; font-size: 12px; }}
.side-kv .k {{ color: {MUTED}; }} .side-kv .v {{ color: {INK_2}; word-break: break-all; }}
.empty {{ border: 1px dashed {BORDER}; border-radius: 6px; padding: 28px 28px; background: {PANEL}; }}
.empty h3 {{ margin: 0 0 6px; font-size: 16px; font-weight: 600; color: {INK}; }}
.empty p {{ color: {INK_2}; font-size: 13px; margin: 0 0 14px; }}
.empty .ev {{ font-size: 11.5px; }}
.filter-note {{ font-size: 12px; color: {MUTED}; margin: -4px 0 10px; }}
h1, h2, h3, h4 {{ letter-spacing: 0; }}

.topbar {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap;
  padding: 10px 0 14px; border-bottom: 1px solid {BORDER}; margin-bottom: 16px; }}
.brand {{ display: flex; align-items: center; gap: 10px; }}
.logo {{ width: 28px; height: 28px; border-radius: 6px; background: {ACCENT}; color: #fff; font-weight: 700;
  display: flex; align-items: center; justify-content: center; font-size: 13px; }}
.brand .t {{ font-size: 16px; font-weight: 600; color: {INK}; }}
.brand .s {{ font-size: 12px; color: {MUTED}; }}
.meta {{ display: flex; gap: 18px; flex-wrap: wrap; font-size: 12px; color: {MUTED}; }}
.meta b {{ color: {INK_2}; font-weight: 500; }}
.live {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #3fb950; margin-right: 6px; }}

.kpis {{ display: grid; grid-template-columns: repeat(6, 1fr); border: 1px solid {BORDER}; border-radius: 6px;
  background: {PANEL}; margin-bottom: 16px; }}
.kpi {{ padding: 12px 16px; border-right: 1px solid {BORDER}; }}
.kpi:last-child {{ border-right: 0; }}
.kpi .l {{ font-size: 11px; color: {MUTED}; text-transform: uppercase; letter-spacing: .05em; font-weight: 500; }}
.kpi .v {{ font-size: 24px; font-weight: 600; color: {INK}; margin-top: 2px; font-variant-numeric: tabular-nums; }}
.kpi .d {{ font-size: 12px; color: {MUTED}; margin-top: 1px; }}
.kpi .d.good {{ color: #3fb950; }}
@media (max-width: 1100px) {{ .kpis {{ grid-template-columns: repeat(3, 1fr); }}
  .kpi:nth-child(3) {{ border-right: 0; }} .kpi:nth-child(-n+3) {{ border-bottom: 1px solid {BORDER}; }} }}

.panel {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 14px 16px; margin-bottom: 14px; }}
.ph {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 10px; }}
.ph .t {{ font-size: 13px; font-weight: 600; color: {INK}; }}
.ph .s {{ font-size: 12px; color: {MUTED}; }}

table.q {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
table.q th {{ text-align: left; font-size: 11px; font-weight: 500; color: {MUTED}; text-transform: uppercase;
  letter-spacing: .04em; padding: 6px 10px; border-bottom: 1px solid {BORDER}; }}
table.q td {{ padding: 8px 10px; border-bottom: 1px solid {GRID}; color: {INK_2}; vertical-align: top; }}
table.q tr:last-child td {{ border-bottom: 0; }}
table.q tr:hover td {{ background: {PANEL_2}; }}
.mono {{ font-family: 'IBM Plex Mono', Consolas, monospace; font-size: 12px; }}
.sev {{ display: inline-flex; align-items: center; gap: 6px; font-weight: 500; font-size: 12px; }}
.sev i {{ width: 8px; height: 8px; border-radius: 2px; display: inline-block; }}
.tag {{ display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px; font-weight: 500;
  border: 1px solid {BORDER}; color: {INK_2}; background: {PANEL_2}; margin: 0 4px 2px 0; }}
.vd {{ display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }}

.hb {{ display: grid; grid-template-columns: 130px 1fr 44px; align-items: center; gap: 10px; margin: 7px 0; font-size: 12px; }}
.hb .n {{ color: {INK_2}; }} .hb .c {{ text-align: right; color: {INK}; font-variant-numeric: tabular-nums; }}
.track {{ height: 8px; background: {PANEL_2}; border-radius: 2px; overflow: hidden; }}
.fill {{ height: 100%; border-radius: 0 2px 2px 0; }}

.chain {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin: 4px 0 2px; }}
.stg {{ padding: 8px 10px; font-size: 12px; color: {MUTED}; border: 1px solid {BORDER}; border-right: 0; background: {BG}; }}
.stg:last-child {{ border-right: 1px solid {BORDER}; border-radius: 0 4px 4px 0; }}
.stg:first-child {{ border-radius: 4px 0 0 4px; }}
.stg.on {{ color: {INK}; background: rgba(61,139,253,.12); border-color: rgba(61,139,253,.55); font-weight: 500; }}
.stg .k {{ font-size: 10px; text-transform: uppercase; letter-spacing: .05em; color: {MUTED}; display: block; }}

.kv {{ display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; font-size: 13px; }}
.kv .k {{ color: {MUTED}; }} .kv .v {{ color: {INK_2}; }}
.ev {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 4px; padding: 8px 10px; margin: 6px 0;
  color: {INK_2}; word-break: break-all; }}
ol.r, ul.r {{ margin: 0; padding-left: 18px; font-size: 13px; color: {INK_2}; }}
ol.r li, ul.r li {{ margin: 4px 0; }}
.muted {{ color: {MUTED}; font-size: 12px; }}

.stTabs [data-baseweb="tab-list"] {{ gap: 0; border-bottom: 1px solid {BORDER}; }}
.stTabs [data-baseweb="tab"] {{ padding: 8px 16px; font-size: 13px; color: {MUTED}; background: transparent; }}
.stTabs [aria-selected="true"] {{ color: {INK} !important; }}
.stTabs [data-baseweb="tab-highlight"] {{ background-color: {ACCENT}; height: 2px; }}
.stButton button, .stDownloadButton button {{ border-radius: 6px; border: 1px solid {BORDER};
  background: {PANEL_2}; color: {INK}; font-weight: 500; }}
.stButton button:hover, .stDownloadButton button:hover {{ border-color: {ACCENT}; color: {INK}; }}
</style>"""


# ---------- html helpers (every log-derived value goes through e()) ----------

def e(x):
    return escape(str(x), quote=True)


def sev(s):
    return f'<span class="sev" style="color:{SEVERITY[s]}"><i style="background:{SEVERITY[s]}"></i>{e(s)}</span>'


def vd(v):
    dark_text = v in ("Confirmed", "Likely")
    return (f'<span class="vd" style="background:{VERDICT[v]};color:{"#0d1117" if dark_text else INK}">'
            f'{e(v)}</span>')


def panel(title, body, sub=""):
    return (f'<div class="panel"><div class="ph"><span class="t">{e(title)}</span>'
            f'<span class="s">{e(sub)}</span></div>{body}</div>')


def hbars(rows, color_of, top=None):
    """rows: [(label, count)] -> labelled horizontal bars (count always shown as text)."""
    top = top or max([n for _, n in rows] + [1])
    return "".join(
        f'<div class="hb"><span class="n">{e(label)}</span><div class="track"><div class="fill" '
        f'style="width:{100 * n / top:.1f}%;background:{color_of(label)}"></div></div>'
        f'<span class="c">{n}</span></div>' for label, n in rows)


def html(s):
    # Single-line HTML only: markdown would turn indented lines into code blocks.
    st.markdown(s, unsafe_allow_html=True)


def chart(fig, height=300):
    fig.update_layout(
        height=height, paper_bgcolor=PANEL, plot_bgcolor=PANEL,
        margin=dict(l=12, r=12, t=12, b=8),
        font=dict(family="IBM Plex Sans, system-ui, sans-serif", color=MUTED, size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0, bgcolor="rgba(0,0,0,0)",
                    font=dict(color=INK_2)),
        hoverlabel=dict(bgcolor=PANEL_2, bordercolor=BORDER, font=dict(color=INK, size=12)),
        bargap=0.25,
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=BORDER, tickcolor=BORDER)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=BORDER, tickcolor=BORDER)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def chart_title(title, sub=""):
    html(f'<div class="ph" style="margin:2px 0 6px"><span class="t">{e(title)}</span>'
         f'<span class="s">{e(sub)}</span></div>')


# ---------- data ----------

def _save_uploads(files):
    blob = b"".join(f.getvalue() for f in files.values() if f)
    folder = os.path.join(UPLOADS, hashlib.sha256(blob).hexdigest()[:12])
    os.makedirs(folder, exist_ok=True)
    for name, f in files.items():
        if f:
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(f.getvalue())
    return folder


@st.cache_resource(show_spinner="Analysing logs…")
def analyse(log_dir, year, stamp):
    """`stamp` (file mtimes) busts the cache when logs or rules change."""
    result = run(log_dir, os.path.join(ROOT, "rules.yaml"), year)
    metrics = evaluate(result) if result.truth_path else None
    return result, metrics


def stamp_of(log_dir):
    paths = [os.path.join(log_dir, n) for n in ("access.log", "auth.log", "ground_truth.csv")]
    paths.append(os.path.join(ROOT, "rules.yaml"))
    return tuple(os.path.getmtime(p) if os.path.exists(p) else 0 for p in paths)


# ---------- page ----------

st.set_page_config(page_title="VFDE Detection Console", page_icon="🛡️", layout="wide")
html(CSS)

def topbar(status, meta=""):
    html(f'<div class="topbar"><div class="brand"><div class="logo">V</div><div><div class="t">Detection Console</div>'
         f'<div class="s">Verification-First Detection Engine</div></div></div>'
         f'<div class="meta">{status}{meta}</div></div>')


SAMPLE_WEB = ('203.0.113.9 - - [14/Mar/2025:12:00:01 +0000] "GET /products?id=12 HTTP/1.1" '
              '200 5123 "-" "Mozilla/5.0" rt=0.120')
SAMPLE_AUTH = "Mar 14 12:00:01 web01 sshd[1021]: Failed password for root from 203.0.113.9 port 4022 ssh2"
SAMPLE_TRUTH = "src_ip,technique,mitre,start,end,expected_rules"

log_dir, year = None, 2025
with st.sidebar:
    html('<div class="side-h">Data source</div>')
    source = st.radio("Data source", ["Sample dataset", "Upload logs"], label_visibility="collapsed")
    if source == "Upload logs":
        up = {"access.log": st.file_uploader("nginx access.log", help="vfde log format, see main panel"),
              "auth.log": st.file_uploader("auth.log", help="Linux sshd / sudo syslog"),
              "ground_truth.csv": st.file_uploader("ground_truth.csv (optional)",
                                                   help="enables the Evaluation tab")}
        year = st.number_input("Year for auth.log", 2000, 2100, 2025,
                               help="syslog timestamps carry no year")
        if up["access.log"] or up["auth.log"]:
            log_dir = _save_uploads(up)
    else:
        log_dir = os.path.join(ROOT, "sample_logs")

# ---------- empty states (main area, never a blank page) ----------
if source == "Upload logs" and log_dir is None:
    topbar('<span>Waiting for logs</span>')
    html('<div class="empty"><h3>Upload logs to start the analysis</h3>'
         '<p>Use the uploaders in the sidebar. At least one of <span class="mono">access.log</span> or '
         '<span class="mono">auth.log</span> is required; <span class="mono">ground_truth.csv</span> is optional '
         'and only unlocks the Evaluation tab.</p>'
         '<div class="side-h">access.log: nginx line with request time</div>'
         f'<div class="ev mono">{e(SAMPLE_WEB)}</div>'
         '<div class="side-h" style="margin-top:14px">auth.log: sshd / sudo syslog</div>'
         f'<div class="ev mono">{e(SAMPLE_AUTH)}</div>'
         '<div class="side-h" style="margin-top:14px">ground_truth.csv header</div>'
         f'<div class="ev mono">{e(SAMPLE_TRUTH)}</div>'
         '<p style="margin:14px 0 0" class="muted">Uploads are stored in .uploads/ inside the project folder. '
         'Switch back to “Sample dataset” to explore the built-in data.</p></div>')
    st.stop()
if not os.path.exists(os.path.join(log_dir, "access.log")) and not os.path.exists(os.path.join(log_dir, "auth.log")):
    topbar('<span>No data</span>')
    html('<div class="empty"><h3>sample_logs/ is empty</h3><p>Generate the sample dataset, then reload:</p>'
         '<div class="ev mono">python generators/synthetic_logs.py --out sample_logs --seed 7 --year 2025</div></div>')
    st.stop()

result, metrics = analyse(log_dir, int(year), stamp_of(log_dir))
alerts, kept, incidents = result.alerts, result.kept, result.incidents
mitre = load_mitre()

times = [ev.ts for ev in result.events]
span = f"{min(times):%Y-%m-%d %H:%M} → {max(times):%Y-%m-%d %H:%M} UTC" if times else "no events"
src_label = "sample_logs" if source == "Sample dataset" else "uploaded logs"

with st.sidebar:
    st.divider()
    html('<div class="side-h">Dataset</div>'
         f'<div class="side-kv"><span class="k">Source</span><span class="v">{e(src_label)}</span>'
         f'<span class="k">Events</span><span class="v">{len(result.events):,}</span>'
         f'<span class="k">From</span><span class="v mono">{min(times):%Y-%m-%d %H:%M}</span>'
         f'<span class="k">To</span><span class="v mono">{max(times):%Y-%m-%d %H:%M}</span>'
         f'<span class="k">Truth</span><span class="v">{"loaded" if metrics else "not loaded"}</span></div>'
         if times else '<div class="side-h">Dataset</div><div class="muted">No events parsed.</div>')
    st.divider()
    html('<div class="side-h">Report</div>')
    st.download_button("Download incident report", build_report(result, metrics),
                       file_name="vfde_incident_report.html", mime="text/html",
                       use_container_width=True)
    st.caption("HTML file. Open in a browser and print to PDF.")

# ---------- top bar ----------
topbar('<span><span class="live"></span>Analysis complete</span>',
       f'<span>Source <b>{e(src_label)}</b></span><span>Window <b class="mono">{e(span)}</b></span>'
       f'<span>Events <b>{len(result.events):,}</b></span>')

# ---------- KPI strip ----------
sev_count = Counter(i.severity for i in incidents)
suppressed = len(alerts) - len(kept)
conf_n = sum(a.verdict == "Confirmed" for a in alerts)
if metrics:
    last = (f'<div class="kpi"><div class="l">Alert precision</div><div class="v">{metrics["verified"]["precision"]:.1%}</div>'
            f'<div class="d good">from {metrics["raw"]["precision"]:.1%} raw · FP −{metrics["fp_reduction"]:.0%}</div></div>')
else:
    last = '<div class="kpi"><div class="l">Alert precision</div><div class="v">—</div><div class="d">no ground truth loaded</div></div>'
html('<div class="kpis">'
     f'<div class="kpi"><div class="l">Events parsed</div><div class="v">{len(result.events):,}</div>'
     f'<div class="d">{sum(result.unparsed.values())} unparsed lines</div></div>'
     f'<div class="kpi"><div class="l">Raw alerts</div><div class="v">{len(alerts)}</div><div class="d">rule matches</div></div>'
     f'<div class="kpi"><div class="l">Verified alerts</div><div class="v">{len(kept)}</div>'
     f'<div class="d good">{suppressed} suppressed as noise</div></div>'
     f'<div class="kpi"><div class="l">Confirmed</div><div class="v">{conf_n}</div><div class="d">impact evidence found</div></div>'
     f'<div class="kpi"><div class="l">Incidents</div><div class="v">{len(incidents)}</div>'
     f'<div class="d"><span style="color:{SEVERITY["Critical"]}">{sev_count["Critical"]} critical</span> · '
     f'<span style="color:{SEVERITY["High"]}">{sev_count["High"]} high</span></div></div>'
     f'{last}</div>')

tab_over, tab_inc, tab_alerts, tab_cov, tab_eval = st.tabs(
    ["Overview", f"Incidents ({len(incidents)})", f"Alerts ({len(alerts)})", "Detection coverage", "Evaluation"])


def queue_table(items):
    if not items:
        return '<div class="muted">No incidents match the current filters.</div>'
    rows = "".join(
        f'<tr><td class="mono">{e(i.id)}</td><td>{sev(i.severity)}</td><td>{vd(i.verdict)}</td>'
        f'<td class="mono">{e(i.src_ip)}</td>'
        f'<td>{"".join(f"<span class=tag>{e(s)}</span>" for s in i.stages)}</td>'
        f'<td>{e(", ".join(t[0] for t in i.techniques))}</td>'
        f'<td class="mono">{i.start:%m-%d %H:%M:%S}</td><td style="text-align:right">{len(i.alerts)}</td></tr>'
        for i in items)
    return ('<table class="q"><thead><tr><th>ID</th><th>Severity</th><th>Verdict</th><th>Source</th>'
            '<th>Kill-chain stages</th><th>MITRE</th><th>First seen</th><th style="text-align:right">Alerts</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')


# ---------- Overview ----------
with tab_over:
    left, right = st.columns([2, 1], gap="medium")
    with left:
        chart_title("Alert volume by hour", "verified alerts by verdict · grey line = raw rule output")
        hour = lambda a: a.ts.replace(minute=0, second=0, microsecond=0)
        hours = sorted({hour(a) for a in alerts})
        fig = go.Figure()
        for v in ("Attempted", "Likely", "Confirmed"):
            c = Counter(hour(a) for a in alerts if a.verdict == v)
            fig.add_trace(go.Bar(x=hours, y=[c.get(h, 0) for h in hours], name=v,
                                 marker=dict(color=VERDICT[v], line=dict(color=PANEL, width=1)),
                                 hovertemplate="%{y} " + v + "<extra></extra>"))
        c_raw = Counter(hour(a) for a in alerts)
        fig.add_trace(go.Scatter(x=hours, y=[c_raw.get(h, 0) for h in hours], name="Raw alerts",
                                 mode="lines+markers", line=dict(color=RAW, width=2, dash="dot"),
                                 marker=dict(size=6, color=RAW),
                                 hovertemplate="%{y} raw<extra></extra>"))
        fig.update_layout(barmode="stack", hovermode="x unified")
        fig.update_xaxes(tickformat="%H:%M")
        chart(fig, 300)
    with right:
        funnel = [("Raw alerts", len(alerts)), ("Verified", len(kept)),
                  ("Likely + Confirmed", sum(a.verdict in ("Likely", "Confirmed") for a in alerts)),
                  ("Confirmed", conf_n), ("Incidents", len(incidents))]
        colors = {"Raw alerts": RAW, "Verified": VERDICT["Attempted"], "Likely + Confirmed": VERDICT["Likely"],
                  "Confirmed": VERDICT["Confirmed"], "Incidents": ACCENT}
        html(panel("Triage funnel", hbars(funnel, colors.get), "raw output → analyst workload"))
        sev_rows = [(s, sev_count.get(s, 0)) for s in SEVERITY]
        html(panel("Incidents by severity", hbars(sev_rows, SEVERITY.get)))

    html(panel("Incident queue", queue_table(incidents[:8]),
               f"top {min(8, len(incidents))} of {len(incidents)} · most severe first"))

# ---------- Incidents ----------
with tab_inc:
    f1, f2, f3 = st.columns([2, 2, 3])
    sev_f = f1.multiselect("Severity", list(SEVERITY), default=list(SEVERITY), key="inc_sev")
    ver_f = f2.multiselect("Verdict", ["Confirmed", "Likely", "Attempted"],
                           default=["Confirmed", "Likely", "Attempted"], key="inc_ver")
    ip_q = f3.text_input("Source IP contains", key="inc_ip", placeholder="e.g. 203.0.113")
    shown = [i for i in incidents if i.severity in sev_f and i.verdict in ver_f and ip_q.strip() in i.src_ip]
    html(panel("All incidents", queue_table(shown), f"{len(shown)} of {len(incidents)} shown"))
    if shown:
        opts = {f"{i.id}  ·  {i.severity}  ·  {i.src_ip}": i for i in shown}
        inc = opts[st.selectbox("Open incident", list(opts))]
        dur = (inc.end - inc.start).total_seconds()
        chain = "".join(f'<div class="stg{" on" if s in inc.stages else ""}"><span class="k">Stage {n}</span>{e(s)}</div>'
                        for n, s in enumerate(STAGES, 1))
        summary = (f'<div class="kv"><span class="k">Severity</span><span class="v">{sev(inc.severity)}</span>'
                   f'<span class="k">Verdict</span><span class="v">{vd(inc.verdict)} '
                   f'<span class="muted">confidence {inc.confidence:.2f}</span></span>'
                   f'<span class="k">Source IP</span><span class="v mono">{e(inc.src_ip)}</span>'
                   f'<span class="k">Window</span><span class="v mono">{inc.start:%Y-%m-%d %H:%M:%S} → {inc.end:%H:%M:%S} UTC ({dur:.0f}s)</span>'
                   f'<span class="k">Alerts</span><span class="v">{len(inc.alerts)}</span></div>'
                   f'<div style="margin-top:12px">{chain}</div>')
        html(panel(f"{inc.id} · {inc.summary.split(': ', 1)[-1]}", summary))

        c1, c2 = st.columns([3, 2], gap="medium")
        with c1:
            rows = "".join(
                f'<tr><td class="mono">{ts:%H:%M:%S}</td><td>{e(stage)}</td><td class="mono">{e(rule)}</td>'
                f'<td>{vd(v)}</td><td>{e(reason)}</td></tr>'
                for ts, stage, rule, v, reason in timeline(inc, mitre))
            html(panel("Timeline", '<table class="q"><thead><tr><th>Time</th><th>Stage</th><th>Rule</th>'
                                   f'<th>Verdict</th><th>Why</th></tr></thead><tbody>{rows}</tbody></table>'))
            ev = "".join(f'<div class="ev mono">{e(l)}</div>' for l in inc.alerts[0].evidence[:5])
            html(panel("Raw evidence", ev, "first alert · up to 5 log lines"))
        with c2:
            recs = "".join(f"<li>{e(r)}</li>" for r in inc.recommendations)
            html(panel("Recommended response", f'<ol class="r">{recs}</ol>', "most advanced stage first"))
            techs = "".join(f'<li><span class="mono">{e(t[0])}</span> {e(t[1])} '
                            f'<span class="muted">· {e(t[2])}</span></li>' for t in inc.techniques)
            html(panel("MITRE ATT&CK", f'<ul class="r">{techs}</ul>'))
            iso = "".join(f"<li>{e(c)}</li>" for c in inc.iso_controls)
            rbi = "".join(f"<li>{e(c)}</li>" for c in inc.rbi_areas)
            html(panel("Control mapping",
                       f'<div class="muted" style="margin-bottom:4px">ISO/IEC 27001:2022 Annex A</div><ul class="r">{iso}</ul>'
                       f'<div class="muted" style="margin:10px 0 4px">RBI CSF control areas (names only; verify clauses)</div>'
                       f'<ul class="r">{rbi}</ul>'))

# ---------- Alerts ----------
with tab_alerts:
    f1, f2, f3, f4 = st.columns([2, 2, 2, 2])
    verdict_f = f1.multiselect("Verdict", ["Confirmed", "Likely", "Attempted", "Noise"],
                               default=["Confirmed", "Likely", "Attempted"], key="al_ver",
                               help="Add 'Noise' to see the alerts the verifier suppressed and why")
    sev_f = f2.multiselect("Severity", list(SEVERITY), default=list(SEVERITY), key="al_sev")
    all_rules = sorted({a.rule_id for a in alerts})
    rule_f = f3.multiselect("Rule", all_rules, default=all_rules, key="al_rule")
    q = f4.text_input("Search IP or reason", key="al_q", placeholder="e.g. 203.0.113 or baseline")
    ql = q.strip().lower()
    rows = [dict(Time=a.ts.strftime("%Y-%m-%d %H:%M:%S"), Severity=a.severity, Verdict=a.verdict,
                 Confidence=a.confidence, Rule=a.rule_id, MITRE=a.mitre_id, Source=a.src_ip, Reason=a.reason)
            for a in alerts if a.verdict in verdict_f and a.severity in sev_f and a.rule_id in rule_f
            and (not ql or ql in a.src_ip.lower() or ql in a.reason.lower())]
    df = pd.DataFrame(rows)
    top_l, top_r = st.columns([4, 1])
    top_l.caption(f"{len(rows)} of {len(alerts)} alerts match the filters above")
    if df.empty:
        st.info("No alerts match the filters.")
    else:
        top_r.download_button("Export CSV", df.to_csv(index=False), file_name="vfde_alerts.csv",
                              mime="text/csv", use_container_width=True)
        st.dataframe(df, use_container_width=True, hide_index=True, height=520,
                     column_config={"Confidence": st.column_config.ProgressColumn(
                         "Confidence", min_value=0.0, max_value=1.0, format="%.2f"),
                         "Reason": st.column_config.TextColumn("Reason", width="large")})

# ---------- Detection coverage ----------
with tab_cov:
    left, right = st.columns([1, 1], gap="medium")
    with left:
        chart_title("Detections by rule", "how each rule's raw alerts were judged")
        rules = [r for r, _ in Counter(a.rule_id for a in alerts).most_common()][::-1]
        fig = go.Figure()
        for v in ("Confirmed", "Likely", "Attempted", "Noise"):
            fig.add_trace(go.Bar(y=rules, x=[sum(a.rule_id == r and a.verdict == v for a in alerts) for r in rules],
                                 name=v, orientation="h",
                                 marker=dict(color=VERDICT[v], line=dict(color=PANEL, width=1)),
                                 hovertemplate="%{y}: %{x} " + v + "<extra></extra>"))
        fig.update_layout(barmode="stack")
        chart(fig, 340)
    with right:
        rows = "".join(
            f'<tr><td class="mono">{e(m["technique"])}</td><td>{e(m["name"])}</td><td>{e(m["stage"])}</td>'
            f'<td class="mono">{e(rule)}</td>'
            f'<td style="text-align:right">{sum(a.rule_id == rule for a in alerts)}</td>'
            f'<td style="text-align:right">{sum(a.rule_id == rule and a.verdict != "Noise" for a in alerts)}</td></tr>'
            for rule, m in mitre.items())
        html(panel("MITRE ATT&CK coverage",
                   '<table class="q"><thead><tr><th>Technique</th><th>Name</th><th>Stage</th><th>Rule</th>'
                   '<th style="text-align:right">Raw</th><th style="text-align:right">Verified</th></tr></thead>'
                   f'<tbody>{rows}</tbody></table>', f"{len(mitre)} rules"))

# ---------- Evaluation ----------
with tab_eval:
    if not metrics:
        st.info("Load a ground_truth.csv to see precision, recall and false-positive reduction.")
    else:
        r, v = metrics["raw"], metrics["verified"]
        html('<div class="kpis" style="grid-template-columns:repeat(4,1fr)">'
             f'<div class="kpi"><div class="l">Precision</div><div class="v">{v["precision"]:.1%}</div>'
             f'<div class="d">raw rules {r["precision"]:.1%}</div></div>'
             f'<div class="kpi"><div class="l">Episode recall</div><div class="v">{v["recall"]:.0%}</div>'
             f'<div class="d">raw rules {r["recall"]:.0%}</div></div>'
             f'<div class="kpi"><div class="l">False positives</div><div class="v">{r["fp"]} → {v["fp"]}</div>'
             f'<div class="d good">−{metrics["fp_reduction"]:.1%}</div></div>'
             f'<div class="kpi"><div class="l">Alerts per incident</div><div class="v">{metrics["alerts_per_incident"]:.1f}</div>'
             f'<div class="d">{metrics["episodes_in_incidents"]}/{metrics["episodes"]} episodes in an incident</div></div></div>')
        left, right = st.columns([1, 1], gap="medium")
        with left:
            chart_title("Raw rules vs verified", "same labelled dataset")
            cats = ["Alerts", "True positives", "False positives"]
            fig = go.Figure()
            for name, s, color in (("Raw rules", r, RAW), ("Verified", v, ACCENT)):
                vals = [s["alerts"], s["tp"], s["fp"]]
                fig.add_trace(go.Bar(x=cats, y=vals, name=name, text=vals, textposition="outside",
                                     textfont=dict(color=INK_2), marker=dict(color=color),
                                     hovertemplate="%{x}: %{y}<extra>" + name + "</extra>"))
            fig.update_layout(barmode="group", bargap=0.35, bargroupgap=0.08)
            chart(fig, 320)
        with right:
            rows = ""
            for t, row in sorted(metrics["per_technique"].items()):
                ttd = sorted(row["ttd"])[len(row["ttd"]) // 2] if row["ttd"] else None
                vc = " ".join(f'{vd(k)} <span class="muted">×{row["verdicts"].count(k)}</span>'
                              for k in ("Confirmed", "Likely", "Attempted") if k in row["verdicts"])
                rows += (f'<tr><td class="mono">{e(t)}</td><td style="text-align:right">{row["episodes"]}</td>'
                         f'<td style="text-align:right">{row["detected"]}</td>'
                         f'<td style="text-align:right">{"—" if ttd is None else f"{ttd:.0f}s"}</td><td>{vc}</td></tr>')
            html(panel("Per technique",
                       '<table class="q"><thead><tr><th>Technique</th><th style="text-align:right">Episodes</th>'
                       '<th style="text-align:right">Detected</th><th style="text-align:right">Median TTD</th>'
                       f'<th>Best verdicts</th></tr></thead><tbody>{rows}</tbody></table>',
                       "TTD in log time (batch)"))
        st.caption("Labelled synthetic dataset: a controlled benchmark, not real-world performance. "
                   "The verifier never reads the ground truth; only the evaluation does.")
