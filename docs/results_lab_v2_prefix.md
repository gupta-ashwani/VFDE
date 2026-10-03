# Evaluation results: lab_v2 (BEFORE fixes, frozen hold-out run)

Dataset: `external_logs/lab_v2` (12155 events, 31 labelled episodes). Matching mode: `window`. Labelled data (synthetic unless stated otherwise): a controlled benchmark, not real-world performance.

## Raw rules vs verified alerts

| Metric | Raw rules | Verified |
|---|---|---|
| Alerts | 79 | 72 |
| False positives | 11 | 5 |
| Alert precision | 86.1% | 93.1% |
| Episode recall | 71.0% | 67.7% |
| F1 (alert precision x episode recall) | 77.8% | 78.4% |

- False-positive reduction: **54.5%**
- Alert volume reduction: **8.9%**
- Precision of `Confirmed` alerts: 89.7%
- Median time to detect (verified): 0s

## Per technique (verified)

| Technique | Episodes | Detected | Median TTD | Verdicts |
|---|---|---|---|---|
| dir_enumeration | 8 | 4 | 0s | Confirmed x1, Likely x1, Attempted x2 |
| injection_probe | 5 | 4 | 0s | Confirmed x4 |
| ssh_password_guessing | 10 | 6 | 10s | Confirmed x3, Attempted x3 |
| traversal_probe | 4 | 4 | 0s | Likely x4 |
| xss_probe | 4 | 3 | 0s | Attempted x3 |

## Incidents

- 79 raw alerts -> **19 incidents** (4.2 raw alerts per incident)
- Labelled episodes inside an incident: 23/31
- False incidents: 1
- Multi-stage incidents: 6

## How these numbers are computed

- Alert = true positive if its source IP belongs to a labelled episode.
- Episode detected = any non-Noise alert from its IP between start-5s and end+10min (`window` mode: the labels carry no expected rules).
- Time to detect is measured in log time (batch analysis): it shows how far into an episode the first verified alert lands, not wall-clock latency. Pattern rules fire on the first matching request, hence 0s; brute force needs N failures first.
- The verifier never reads the ground truth; only this script does.
- Generator, look-alike benign traffic and verifier were written together, so expect lower numbers on real logs.
