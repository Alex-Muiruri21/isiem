# ISIEM — Intelligent SIEM Framework

Final-year project: *An Intelligent SIEM Framework for Real-Time Threat Detection and
Automated Incident Response Using Machine Learning and Behavioural Analytics.*

A four-layer, open-source platform for SMEs: **Wazuh** SIEM, **Cowrie** honeypot, a
**machine-learning** detection engine (Random Forest + Isolation Forest +
behavioural analytics), and **Python automated response** (firewall block, account
lock, email) driven by Wazuh Active Response.

## Layout
| Path | What it is | Runs on |
|---|---|---|
| `ml/` | benchmark training + live behavioural engine + tests | Wazuh server |
| `wazuh/` | custom rules, decoders, ossec.conf snippets | Wazuh server / agents |
| `response/` | active-response scripts (block / lock / notify) | attacked endpoint |
| `attacks/` | the 5 validation scenarios + MTTD/MTTR tool | Kali |
| `docs/` | source report, corrections list, Chapter 5 draft | — |
| `evidence/` | benchmark results, metrics (for Chapter 5) | — |

## Start here
- **`docs/HANDOFF.md`** — full project handoff (read first if you are new).
- **`DEPLOY.md`** — what to install where, and how to run the scenarios (follow this
  when the lab VMs are powered on).
- **`PROJECT_NOTES.md`** — status, lab inventory, credentials, known issues, plan.
- **`docs/REPORT_CORRECTIONS.md`** — edits to align the write-up with the build.

## Quick offline checks (no lab needed)
```bash
cd ml
python3 train_benchmark.py        # trains benchmark models, writes evidence/
python3 tests/test_detection.py   # replays sample attacks, asserts all categories
python3 ml_engine.py --replay tests/sample_alerts.json   # see verdicts
```

## Status
Phases 1–2 built and working on the lab (Wazuh + agents + Cowrie). Phase 3 ML engine
**rebuilt here** to actually read Wazuh alerts and do behavioural detection (the
original polled a non-existent API). Phase 4 (attacks + metrics) is coded and ready
to run on the lab. See `PROJECT_NOTES.md`.
