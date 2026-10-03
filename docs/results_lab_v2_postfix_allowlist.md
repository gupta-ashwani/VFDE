# Evaluation results: lab_v2 (after fixes, with operator allowlist)

Dataset: `external_logs/lab_v2` (12155 events, 31 labelled episodes). Matching mode: `window`. Author-labelled logs from attack scenarios run in a local lab (labels and benign 'gotchas' written by the author); a small dataset, not production traffic.

Operator allowlist applied: 1 authorised source(s).

## Raw rules vs verified alerts

| Metric | Raw rules | Verified |
|---|---|---|
| Alerts | 101 | 89 |
| False positives | 12 | 0 |
| Alert precision | 88.1% | 100.0% |
| Episode recall | 93.5% | 93.5% |
| F1 (alert precision x episode recall) | 90.8% | 96.7% |

- False-positive reduction: **100.0%**
- Alert volume reduction: **11.9%**
- Precision of `Confirmed` alerts: 100.0%
- Median time to detect (verified): 0s

## Per technique (verified)

| Technique | Episodes | Detected | Median TTD | Verdicts |
|---|---|---|---|---|
| dir_enumeration | 8 | 7 | 0s | Confirmed x1, Likely x4, Attempted x2 |
| injection_probe | 5 | 4 | 0s | Confirmed x4 |
| ssh_password_guessing | 10 | 10 | 12s | Confirmed x5, Attempted x5 |
| traversal_probe | 4 | 4 | 0s | Likely x4 |
| xss_probe | 4 | 4 | 0s | Attempted x4 |

## Incidents

- 101 raw alerts -> **28 incidents** (3.6 raw alerts per incident)
- Labelled episodes inside an incident: 29/31
- False incidents: 0
- Multi-stage incidents: 6

## How these numbers are computed

- Alert = true positive if its source IP belongs to a labelled episode.
- Episode detected = any non-Noise alert from its IP between start-5s and end+10min (`window` mode: the labels carry no expected rules).
- Time to detect is measured in log time (batch analysis): it shows how far into an episode the first verified alert lands, not wall-clock latency. Pattern rules fire on the first matching request, hence 0s; brute force needs N failures first.
- The verifier never reads the ground truth; only this script does.
- Labels are written by the dataset's author. A dataset produced together with the verifier shares its assumptions, so expect lower numbers on real logs.
