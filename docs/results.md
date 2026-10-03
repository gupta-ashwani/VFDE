# Evaluation results

Dataset: `sample_logs` (3434 events, 18 labelled episodes). Matching mode: `rules`. Labelled data (synthetic unless stated otherwise): a controlled benchmark, not real-world performance.

No operator allowlist applied.

## Raw rules vs verified alerts

| Metric | Raw rules | Verified |
|---|---|---|
| Alerts | 167 | 64 |
| False positives | 104 | 1 |
| Alert precision | 37.7% | 98.4% |
| Episode recall | 100.0% | 100.0% |
| F1 (alert precision x episode recall) | 54.8% | 99.2% |

- False-positive reduction: **99.0%**
- Alert volume reduction: **61.7%**
- Precision of `Confirmed` alerts: 100.0%
- Median time to detect (verified): 0s

## Per technique (verified)

| Technique | Episodes | Detected | Median TTD | Verdicts |
|---|---|---|---|---|
| dir_enumeration | 5 | 5 | 0s | Likely x5 |
| sqli | 5 | 5 | 0s | Confirmed x5 |
| ssh_brute_force | 5 | 5 | 8s | Confirmed x3, Attempted x2 |
| traversal | 1 | 1 | 0s | Confirmed x1 |
| xss | 2 | 2 | 0s | Attempted x2 |

## Incidents

- 167 raw alerts -> **15 incidents** (11.1 raw alerts per incident)
- Labelled episodes inside an incident: 18/18
- False incidents: 1
- Multi-stage incidents: 3

## Robustness across fresh synthetic seeds

| Seed | Raw precision | Verified precision | Recall | FP reduction | False incidents |
|---|---|---|---|---|---|
| 1 | 42.0% | 100.0% | 100.0% | 100.0% | 0 |
| 2 | 40.1% | 100.0% | 100.0% | 100.0% | 0 |
| 3 | 40.7% | 100.0% | 100.0% | 100.0% | 0 |
| 11 | 40.0% | 100.0% | 100.0% | 100.0% | 0 |
| 42 | 37.6% | 97.1% | 100.0% | 98.2% | 2 |

## How these numbers are computed

- Alert = true positive if its source IP belongs to a labelled episode.
- Episode detected = a non-Noise alert of one of its expected rules from its IP, between start-5s and end+10min.
- Time to detect is measured in log time (batch analysis): it shows how far into an episode the first verified alert lands, not wall-clock latency. Pattern rules fire on the first matching request, hence 0s; brute force needs N failures first.
- The verifier never reads the ground truth; only this script does.
- Labels are written by the dataset's author. A dataset produced together with the verifier shares its assumptions, so expect lower numbers on real logs.
