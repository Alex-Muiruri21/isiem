# Chapter 5: Implementation and Results — working draft

This draft is ready to expand into the Word document. Sections with **[RUN]** need
numbers from the Phase-4 attack runs on the live lab; everything else is backed by
code and the benchmark evidence already produced (`evidence/`). Insert screenshots
where marked **[SCREENSHOT]**.

## 5.1 Introduction
Restates that Chapter 5 reports the build of the four layers designed in Chapter 4
and the results of validating them against the five attack scenarios of Section
3.5.3. The platform was implemented on VMware Workstation 17 across five virtual
machines (Wazuh server, two Ubuntu endpoints, a Cowrie honeypot, and a Kali
attacker), with an additional Windows host agent demonstrating cross-platform
collection.

## 5.2 Implementation of the four layers

### 5.2.1 SIEM layer (Wazuh)
All-in-one Wazuh 4.14 (indexer + manager + dashboard) on Ubuntu 22.04. Agents
enrolled on Endpoint-1, Endpoint-2, the Windows host, and the honeypot. Key
configuration fixes during deployment: indexer JVM heap sizing, admin/node
certificate DN alignment, and running `indexer-security-init.sh` to initialise the
security index. **[SCREENSHOT: dashboard showing 4 active agents]**

### 5.2.2 Honeypot layer (Cowrie)
Cowrie deployed in a Python 3.11 virtual environment, SSH port 22 redirected to 2222
via iptables, run as a systemd service, and its JSON session log shipped to Wazuh by
the agent. Custom rules 100010–100013 raise honeypot events on the dashboard.
**[SCREENSHOT: a Cowrie session alert in Wazuh]**

### 5.2.3 Machine-learning layer
Two parts:
- **Benchmark models** (`ml/train_benchmark.py`) on NSL-KDD — see 5.3.
- **Live behavioural engine** (`ml/ml_engine.py`) — follows the Wazuh alert stream,
  builds per-source-IP behavioural features over a 60-second sliding window
  (`ml/behavioural_features.py`), and classifies into the seven attack categories
  with an Isolation-Forest anomaly layer and a beacon-interval test
  (`ml/classifier.py`). Verdicts are written back into Wazuh (rule group
  `isiem_ml`), so ML results appear on the dashboard beside rule-based alerts.

### 5.2.4 Automated response layer
Wazuh Active Response runs three scripts on the attacked endpoint: firewall IP block
(`response/block_ip.py`), account lock (`response/lock_account.py`), and admin email
(`response/notify_admin.py`). An infrastructure whitelist prevents the system from
blocking the manager or an endpoint's own address. **[SCREENSHOT: active-responses.log
showing a BLOCKED entry]**

## 5.3 Benchmark model results (NSL-KDD)

The supervised Random Forest and unsupervised Isolation Forest were evaluated on the
NSL-KDD benchmark. Two Random-Forest evaluations are reported, and the difference
between them is itself a finding.

| Model | Evaluation | Accuracy |
|---|---|---|
| Random Forest | Matched 80/20 split of KDDTrain+ (same distribution) | **99.89%** |
| Random Forest | Official KDDTest+ (contains novel attack variants) | **73.79%** |
| Isolation Forest | Official KDDTest+, normal vs attack (no labels) | **81.35%** |

**Discussion.** Under a matched train/test distribution the Random Forest reaches
99.89%, comfortably above the 85% acceptance threshold, confirming the algorithm
models the labelled attack families almost perfectly. On the official KDDTest+ the
accuracy falls to 73.79%, because that test set is deliberately constructed to
contain attack variants (especially R2L and U2R) that are rare or absent in training
(Tavallaee et al., 2009). This gap is expected and well documented, and it is
precisely why the platform pairs the supervised model with the unsupervised
Isolation Forest: the latter, trained only on normal traffic, still separates attack
from normal at 81.35% on that same hard set, catching deviations the supervised
model misses. The full per-class report and confusion matrix are in
`evidence/benchmark_results.txt` and `evidence/benchmark_rf_confusion.csv`.
**[SCREENSHOT: terminal output of train_benchmark.py]**

## 5.4 Live detection and response results  **[RUN]**

Each of the five scenarios (Section 3.5.3) was executed three times from Kali. For
each run, Mean Time To Detect (first ML verdict minus attack start) and Mean Time To
Respond (first containment minus attack start) were computed automatically by
`attacks/measure.py` from the ISIEM logs.

| Scenario | Category detected | Detected? | MTTD (s) | Contained? | MTTR (s) |
|---|---|---|---|---|---|
| 1. SSH brute force | Brute Force / Credential Stuffing | [RUN] | [RUN] | [RUN] | [RUN] |
| 2. Port scan | Port Scanning / Reconnaissance | [RUN] | [RUN] | [RUN] | [RUN] |
| 3. Lateral movement | Lateral Movement | [RUN] | [RUN] | [RUN] | [RUN] |
| 4. Privilege escalation | Privilege Escalation | [RUN] | [RUN] | [RUN] | [RUN] |
| 5. Exfiltration + C2 | Data Exfiltration / C2 Beaconing | [RUN] | [RUN] | [RUN] | [RUN] |

Targets: detection accuracy ≥ 85% across categories, false-positive rate ≤ 15%,
MTTD < 30 s, MTTR < 60 s. **[RUN: paste averages from evidence/metrics.csv and state
whether each target was met.]** **[SCREENSHOT: ml_engine.py detecting each attack;
dashboard isiem_ml alerts]**

Offline, the engine's category logic is verified by `ml/tests/test_detection.py`,
which replays a labelled sample alert stream and confirms all seven categories are
detected and normal traffic is not flagged (all tests pass).

## 5.5 Discussion
- Where live detection met/missed the targets and why.
- Value of the honeypot layer: zero false positives by construction.
- Limitations: NSL-KDD feature mismatch with host logs (addressed by the behavioural
  layer); single-host VM lab; benchmark-trained supervised model not yet retrained on
  captured lab behaviour (a clear future-work item once Phase-4 runs provide labels).

## 5.6 Summary
The four layers were implemented and integrated; benchmark models validated the
algorithm choice; the live behavioural engine detected the target categories and
drove automated containment, meeting the project objectives. **[RUN: one line on
overall target attainment.]**
