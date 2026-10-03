# Verification-First Detection Engine (VFDE)

Defensive SOC-style log analysis: rule-based detection, an evidence-based
verification layer that suppresses false positives, kill-chain correlation
into incidents, MITRE ATT&CK and ISO 27001 / RBI CSF mapping, a Streamlit
dashboard, an HTML/PDF incident report and a reproducible evaluation.

> All testing is performed on locally generated logs / an isolated local lab.

## Screenshots

<!-- Add after running `streamlit run app.py`:
![Overview](docs/screenshots/overview.png)
![Incident detail](docs/screenshots/incident.png)
-->

## Quick start

```bash
pip install -r requirements.txt
python generators/synthetic_logs.py --out sample_logs --seed 7
python cli.py analyze --logs sample_logs --year 2025
pytest -q
```

The generator writes `access.log`, `auth.log` and `ground_truth.csv`
(simulated episodes from documentation-range IPs, plus benign traffic that
includes tricky look-alikes such as a search for `O'Brien`).
`cli.py analyze` prints raw alerts plus a baseline precision / recall report
against the ground truth: this is the number Phase 3 must improve.

## Layout

| Path | Purpose |
|---|---|
| `generators/synthetic_logs.py` | Labelled benign + simulated-suspicious log generator |
| `lab/` | Optional Docker lab (nginx with custom log format, practice app, ssh) |
| `vfde/parsers/` | nginx-format web parser, sshd/sudo auth parser |
| `vfde/detections/engine.py` | 9 rules with sliding windows, MITRE-mapped |
| `rules.yaml` | Thresholds, patterns, MITRE IDs |
| `vfde/verification/` | Phase 3: baselines + per-rule verifiers (verdict, reason, confidence) |
| `vfde/correlation/` | Phase 4: kill-chain incidents, severity, timelines |
| `vfde/mapping/` | MITRE ATT&CK mapping + ISO 27001 / RBI CSF control mapping (YAML) |
| `eval_baseline.py` | Raw-rule precision/recall, raw-vs-verified, incident-level report |
| `vfde/pipeline.py` | One entry point (parse -> detect -> verify -> correlate) shared by CLI, eval, dashboard, report |
| `eval.py` | Full evaluation, per-technique table, seed sweep -> `docs/results.md` |
| `vfde/reporting/` | Self-contained HTML incident report (print to PDF) |
| `app.py`, `.streamlit/` | Streamlit SOC dashboard and theme |
| `tests/` | pytest: positive and negative case per rule and per verifier |

## Detections (raw baseline)

brute force (T1110), success after failures (T1078), 404 scanning (T1595),
SQLi / XSS patterns (T1190), path traversal (T1083), scanner user-agent
(T1595), off-hours login (T1078), sudo failures (T1068).

## Phase 3: Verification layer

```bash
python cli.py analyze --logs sample_logs --year 2025 --verify --show
```

Each raw alert gets a verdict, a confidence score and a human-readable reason,
using only log evidence (the ground truth is never read by the verifier):

| Verdict | Meaning |
|---|---|
| Confirmed | evidence shows success / impact (HTTP 5xx on injected input, slow time-based response, response far above clean baseline, login success after scripted guessing) |
| Likely | strong signs of malicious activity, impact not proven |
| Attempted | malicious-looking, no sign it worked |
| Noise | matches a rule but behaves like legitimate traffic; suppressed |

Key ideas: baselines built from clean (unflagged) IPs only; probe *bursts* per
IP rather than single matches; human-paced single-user failures treated as
typos; static-asset 404 bursts treated as a broken page; tool-like user-agents
hitting one health endpoint treated as a monitor; and a **two-pass** design so
an alert already judged Noise can never corroborate another alert.

Result on the synthetic dataset (seed 7, 18 labelled episodes; seeds 1, 2, 3,
11, 42 give 98-100% FP reduction with 100% episode recall):

| | raw rules | verified |
|---|---|---|
| alerts | 162 | 59 |
| false positives | 104 | 1 |
| precision | 35.8% | 98.3% |
| episode recall | 100% | 100% |

**Read these numbers with care.** The dataset, its benign look-alikes and the
verifier were all written by the same person, so this is a controlled
benchmark, not evidence of real-world performance. Validate on logs from a real
lab before claiming more. Known limits: reflected XSS cannot be confirmed from
server logs (capped at Attempted); a legitimate request that happens to return
HTTP 500 still survives as a false positive (the one remaining FP above).

## Phase 4: Kill-chain correlation + MITRE / compliance mapping

```bash
python cli.py analyze --logs sample_logs --year 2025 --correlate --show
```

Verified alerts (never Noise) are grouped per source IP into **incidents**; a
gap longer than `correlation.gap_seconds` starts a new incident. Each incident
lists the kill-chain stages it spans (Reconnaissance -> Initial Access ->
Compromise -> Post-Exploitation), MITRE ATT&CK techniques, related governance
controls, a time-ordered alert timeline, and de-duplicated recommendations
(most advanced stage first).

Severity: strongest alert severity; capped at `attempted_only_severity_cap`
when no alert is Confirmed/Likely; bumped one level when the incident spans 3+
stages. All thresholds live in `rules.yaml`.

| | seed 7 |
|---|---|
| raw alerts | 162 |
| incidents | 15 (10.8 raw alerts per incident) |
| labelled episodes covered | 18/18 |
| false incidents | 1 (the HTTP-500 look-alike) |
| multi-stage incidents | 3 |

The generator includes two multi-stage attacker journeys (scan -> SQLi probes
-> credential guessing -> login) so correlation has real chains to join; the
other episodes are single-technique.

**Compliance mapping caveat.** `vfde/mapping/compliance.yaml` links each
detection to ISO/IEC 27001:2022 Annex A controls and to RBI Cyber Security
Framework control *areas by name only*. No RBI clause numbers are cited on
purpose: verify them against the official RBI circular before quoting any
number. The mapping shows what evidence the tool can support; it does not claim
anyone is compliant.

## Phase 5: Dashboard, incident report, evaluation

```bash
pip install -r requirements.txt
streamlit run app.py                                    # SOC dashboard
python cli.py report --logs sample_logs                 # reports/incident_report.html
python eval.py --logs sample_logs --seeds 1 2 3 11 42 --write docs/results.md
```

**Dashboard (`app.py`).** Violet / indigo / blue theme. Five tabs:
Overview (alerts per hour raw vs verified, verdict mix per rule, top
incidents), Incidents (kill-chain stepper, timeline with evidence-based
reasons, MITRE, recommendations, ISO/RBI context), Alerts (filterable table,
CSV export), Coverage (MITRE technique per rule), Evaluation (precision,
recall, FP reduction, per-technique table). Logs can be uploaded; uploads are
saved under `.uploads/` inside the project.

**Incident report.** Self-contained HTML (no JS, no external assets): executive
summary, raw-vs-verified comparison, every incident with its kill chain,
timeline, controls and fixes, plus method and limitations. Print -> Save as PDF
gives a light, print-friendly PDF. All log-derived text is HTML-escaped (the
evidence contains attack payloads).

**Evaluation (`eval.py`).** Full results are in [docs/results.md](docs/results.md).
Headline on seed 7: 162 raw alerts -> 59 verified, false positives 104 -> 1,
precision 35.8% -> 98.3%, 18/18 episodes detected, 15 incidents. The script
states its matching rules so they can be questioned.

## Resume line (numbers from docs/results.md)

> Built a verification-first detection engine in Python that parses web and
> SSH auth logs, detects 9 attack patterns mapped to MITRE ATT&CK, verifies
> alerts against response-evidence baselines and correlates them into
> kill-chain incidents; on a labelled synthetic dataset it cut false positives
> by 99% (precision 36% -> 98%) with 100% episode recall, presented in a
> Streamlit SOC dashboard with HTML/PDF incident reports and ISO 27001 /
> RBI CSF control mapping.

Keep the words "labelled synthetic dataset" unless you re-run on real lab logs.

## Future work

Real-time mode (log tailing, sliding-window state, alert lifecycle), Sigma rule
import, real lab validation with the `lab/` Docker setup, GeoIP / reputation
enrichment.
