# Evaluation results

Dataset: `sample_logs` (3434 events, 18 labelled episodes). Synthetic, labelled data: a controlled benchmark, not real-world performance.

## Raw rules vs verified alerts

| Metric | Raw rules | Verified |
|---|---|---|
| Alerts | 162 | 59 |
| False positives | 104 | 1 |
| Alert precision | 35.8% | 98.3% |
| Episode recall | 100.0% | 100.0% |
| F1 (alert precision x episode recall) | 52.7% | 99.1% |

- False-positive reduction: **99.0%**
- Alert volume reduction: **63.6%**
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

- 162 raw alerts -> **15 incidents** (10.8 raw alerts per incident)
- Labelled episodes inside an incident: 18/18
- False incidents: 1
- Multi-stage incidents: 3

## Robustness across fresh synthetic seeds

| Seed | Raw precision | Verified precision | Recall | FP reduction | False incidents |
|---|---|---|---|---|---|
| 1 | 40.4% | 100.0% | 100.0% | 100.0% | 0 |
| 2 | 38.3% | 100.0% | 100.0% | 100.0% | 0 |
| 3 | 38.9% | 100.0% | 100.0% | 100.0% | 0 |
| 11 | 38.2% | 100.0% | 100.0% | 100.0% | 0 |
| 42 | 35.8% | 96.9% | 100.0% | 98.2% | 2 |

## How these numbers are computed

- Alert = true positive if its source IP belongs to a labelled episode.
- Episode detected = a non-Noise alert of one of its expected rules from its IP, between start-5s and end+10min.
- The verifier never reads the ground truth; only this script does.
- Generator, look-alike benign traffic and verifier were written together, so expect lower numbers on real logs.
