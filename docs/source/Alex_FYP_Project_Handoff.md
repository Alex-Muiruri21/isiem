# Alex Muiruri — FYP Project Handoff Document
**Student:** Alex Muiruri | **ID:** 155361  
**Programme:** BSc Computer Networks and Cyber Security  
**University:** Strathmore University, Nairobi, Kenya  
**Supervisor:** Mr. James Gikera  
**Submission Date:** June 2026  

---

## PROJECT TITLE
**"An Intelligent SIEM Framework for Real-Time Threat Detection and Automated Incident Response Using Machine Learning and Behavioural Analytics"**

> Note: The working/presentation title used is:  
> **"An Integrated Cyber Threat Detection and Automated Response Platform for SMEs Using SIEM, Honeypot Deception, and Machine Learning"**

---

## PROJECT OVERVIEW
A four-layer integrated cybersecurity platform designed for SMEs that cannot afford enterprise security tooling. The platform combines:

1. **Wazuh SIEM** — centralised log collection, normalisation, rule-based detection, Wazuh Dashboard
2. **Cowrie Honeypot** — medium-interaction SSH/Telnet decoy, attacker profiling, zero false positives
3. **ML Engine (Python/scikit-learn)** — Random Forest (supervised) + Isolation Forest (unsupervised anomaly detection)
4. **Python Automated Response** — IP blocking (iptables), account isolation (passwd --lock), email notification (smtplib)

---

## OBJECTIVES

### General Objective
Design, develop, and validate an Integrated Cyber Threat Detection and Response Platform combining SIEM-based log monitoring, honeypot deception, machine learning threat detection, and automated Python-driven incident response into a unified, open-source deployable framework for SMEs.

### Specific Objectives
1. Investigate execution methods and detection signatures of 7 attack categories through peer-reviewed literature
2. Analyse minimum 5 peer-reviewed studies on SIEM, honeypot, and ML IDS — identify technical gaps
3. Design and develop all four platform layers achieving full functional integration
4. Test and validate against 5 simulated attack scenarios using Kali Linux in VirtualBox

---

## 7 TARGET ATTACK CATEGORIES
1. Brute Force and Credential Stuffing (Hydra → SSH)
2. Port Scanning and Network Reconnaissance (Nmap SYN scan)
3. Lateral Movement (SSH between internal hosts — Isolation Forest detects)
4. Privilege Escalation (sudo misconfiguration — Metasploit)
5. Data Exfiltration (DNS tunnelling, abnormal outbound traffic)
6. Command and Control Beaconing (periodic fixed-interval connections)
7. Suspicious Authentication Patterns (off-hours logins, unknown IPs)

---

## ML ENGINE DETAILS
- **Random Forest** → classifies known attack categories (supervised)
- **Isolation Forest** → detects anomalies/novel threats (unsupervised)
- **Training Datasets:** CICIDS2017 + NSL-KDD (preprocessed, min-max scaled, combined)
- **Libraries:** scikit-learn, pandas, numpy, joblib
- **Integration:** Wazuh active response module triggers Python scripts

---

## TEST ENVIRONMENT (5 VMs — VMware Workstation)
| VM | OS | Role |
|---|---|---|
| Wazuh Server | Ubuntu Server 22.04 LTS | SIEM core (Manager + Indexer + Dashboard) |
| Endpoint 1 | Ubuntu Server 22.04 LTS | Monitored machine with Wazuh Agent |
| Endpoint 2 | Ubuntu Server 22.04 LTS | Monitored machine with Wazuh Agent |
| Cowrie Honeypot | Ubuntu Server 22.04 LTS | SSH/Telnet decoy (port 22/23) |
| Kali Linux 2025.x | Kali | Attack machine |

**Attack tools:** Hydra, Nmap, Metasploit, custom Python scripts

---

## NON-FUNCTIONAL REQUIREMENTS / ACCEPTANCE CRITERIA
| Metric | Target |
|---|---|
| Detection Accuracy | ≥ 85% across 7 categories |
| False Positive Rate | ≤ 15% |
| Mean Time to Detect (MTTD) | < 30 seconds |
| Mean Time to Respond (MTTR) | < 60 seconds |
| Hardware | 8 GB RAM, 8 cores, 500 GB storage |
| Cost | 100% open-source, zero licensing |

---

## METHODOLOGY
**Agile Design Science Research (Agile DSR)** — 4 iterative sprints:
- **Sprint 1:** Wazuh SIEM deployment + agent installation + baseline alerting
- **Sprint 2:** Cowrie honeypot deployment + Wazuh custom log source integration
- **Sprint 3:** ML model training (CICIDS2017 + NSL-KDD) + live event stream integration
- **Sprint 4:** Python response playbooks + end-to-end validation (5 attack scenarios × 3 runs each)

---

## REFERENCES (Current — 5 core + 19 new added)

### Core 5
1. Ahmad, Z. et al. (2021). Network intrusion detection system: ML and deep learning approaches. *Transactions on Emerging Telecommunications Technologies, 32*(1). https://doi.org/10.1002/ett.4150
2. Franco, J. et al. (2021). Survey of honeypots and honeynets for IoT. *IEEE Communications Surveys & Tutorials, 23*(4), 2351–2383. https://doi.org/10.1109/COMST.2021.3106669
3. Khraisat, A. & Alazab, A. (2021). Critical review of IDS in IoT. *Electronics, 10*(21), 2633. https://doi.org/10.3390/electronics10212633
4. Sarker, I. H. (2021). Machine learning: Algorithms, applications, research directions. *SN Computer Science, 2*(3), 160. https://doi.org/10.1007/s42979-021-00592-x
5. Vielberth, M. et al. (2021). Security operations center: Systematic study. *IEEE Access, 9*, 119023–119042. https://doi.org/10.1109/ACCESS.2021.3107190

### 19 Additional References Added
6. Al-Shehari, T. et al. (2023). Insider threat detection using Isolation Forest. *IEEE Access, 11*, 118170–118185. https://doi.org/10.1109/ACCESS.2023.3326802
7. Bertoli, G. D. C. et al. (2021). End-to-end ML-based network IDS. *IEEE Access, 9*, 106790–106805. https://doi.org/10.1109/ACCESS.2021.3101188
8. Bridges, R. A. et al. (2023). Testing SOAR tools in use. *Computers & Security, 129*, 103201. https://doi.org/10.1016/j.cose.2023.103201
9. Chen, Z. et al. (2022). ML-enabled IoT security under APTs. *ACM Computing Surveys, 55*(5), 1–37. https://doi.org/10.1145/3530812
10. Doshi, N. et al. (2022). Random Forest for IDS in cyber security. *IEEE ICIBT*. https://doi.org/10.1109/ICIBT52874.2022.9807766
11. Fang, Y. et al. (2022). LMTracker: Lateral movement detection via graph embedding. *Neurocomputing, 474*, 37–47. https://doi.org/10.1016/j.neucom.2021.12.026
12. Gan, C. et al. (2023). APTs and defense in IIoT: A survey. *Mathematics, 11*(14), 3115. https://doi.org/10.3390/math11143115
13. González-Granadillo, G. et al. (2021). SIEM: Analysis, trends, critical infrastructures. *Sensors, 21*(14), 4759. https://doi.org/10.3390/s21144759
14. Ilca, L. F. et al. (2023). Cyber-resilience for SMEs with malware detection. *Sensors, 23*(15), 6757. https://doi.org/10.3390/s23156757
15. King, I. J. & Huang, H. H. (2023). Euler: Lateral movement via temporal link prediction. *ACM TOPS, 26*(3), 1–36. https://doi.org/10.1145/3586084
16. Lagorio, A. et al. (2022). Cybersecurity in SMEs: Challenges and directions. *Computers & Security, 113*, 102584. https://doi.org/10.1016/j.cose.2021.102584
17. Moričić, Z. et al. (2025). Honeypots and deception strategies. *Informatics, 12*(1), 14. https://doi.org/10.3390/informatics12010014
18. Muhammad, A. R. et al. (2023). SIEM with IDS for live ML-based analysis. *Procedia Computer Science, 217*, 1406–1415. https://doi.org/10.1016/j.procs.2022.12.339
19. Nguyen, P. et al. (2023). Smarter SOAR for CPS and IoT. *IEEE CloudCom*, 298–302. https://doi.org/10.1109/CloudCom59040.2023.00055
20. Pethers, M. (2025). Automated incident containment using SOAR. *JDACM, 3*(3). https://doi.org/10.62177/jdacm.v3i3.76
21. Rosay, A. et al. (2022). Network IDS: Comprehensive analysis of CIC-IDS2017. *ICISSP 2022*, 25–36. https://doi.org/10.5220/0010774800003120
22. Schlette, D. et al. (2021). Comparative study on cyber threat intelligence. *IEEE COMST, 23*(4), 2525–2556. https://doi.org/10.1109/COMST.2021.3117338
23. Yüksel, M. et al. (2024). Cowrie honeypot for SSH/Telnet attack analysis. *IEEE*. https://doi.org/10.1109/ICCIT60459.2024.10859786
24. Zhang, P. et al. (2023). Real-time malicious traffic detection with Isolation Forest. *IEEE TIFS, 18*, 2076–2090. https://doi.org/10.1109/TIFS.2023.3234975

---

## DOCUMENT STATUS (Chapters Completed)

### ✅ Chapter 1: Introduction
- Background, Problem Statement, Objectives (4 SMART), Scope & Limitations, Significance
- All citations updated to 2021+, peer-reviewed sources only

### ✅ Chapter 2: Literature Review
- Technology Review (2.2.1–2.2.6): Wazuh, Cowrie, RF+IF, CICIDS2017+NSL-KDD, Python SOAR, VirtualBox/Kali
- Cyber Attack Vulnerability Analysis (2.3.1–2.3.7): All 7 attack types with execution + signatures
- Existing Solutions (2.4.1–2.4.4): Sarker, Franco, Ahmad + research gap
- Conceptual Framework (2.5): 4-layer data flow diagram inserted
- Comparison Table 2.1 included

### ✅ Chapter 3: Design Methodology
- Agile DSR methodology + Figure 3.1 (sprint diagram)
- Functional Requirements (3.3.1)
- Non-Functional Requirements (3.3.2) — with measurable benchmarks
- Hardware Requirements (3.4.1)
- Software Requirements (3.4.2)
- Testing and Validation (3.5.1–3.5.4) — NEW section added
- 5 attack scenarios defined, 4 metrics defined

### 🔄 Chapter 4: System Design — IN PROGRESS
Following the template structure:
- 4.1 Introduction
- 4.2 Black-Box Diagram
- 4.3 System Analysis (Use-Case, Sequence, Activity, ERD, Class Diagrams)
- 4.4 System Design (System Architecture Diagram)

**All 7 diagrams to be built as SVG** — ready to screenshot and insert into Word doc.

---

## DIAGRAMS NEEDED FOR CHAPTER 4
| # | Diagram | Status |
|---|---|---|
| Fig 4.1 | Black-Box Diagram | ⏳ To build |
| Fig 4.2 | Use-Case Diagram | ⏳ To build |
| Fig 4.3 | Sequence Diagram | ⏳ To build |
| Fig 4.4 | Activity Diagram | ⏳ To build |
| Fig 4.5 | ERD | ⏳ To build |
| Fig 4.6 | Class Diagram | ⏳ To build |
| Fig 4.7 | System Architecture Diagram | ⏳ To build |

---

## PROPOSAL PRESENTATION STRUCTURE (10 min)
| Slide | Section | Time |
|---|---|---|
| 1 | Introduction + Conceptual Framework diagram | 1.5 min |
| 2–3 | Literature Review — Networking/Systems/Cloud/Apps/Cybersec mapping | 1.5 min |
| 4–5 | Design & Analysis — Technical design + signaling diagrams | 3 min |
| 6–7 | Implementation — Software stack + system architecture diagram | 2 min |
| 8 | Evaluation — 4 metrics, 5 scenarios, limitations | 2 min |

---

## KEY DESIGN DECISIONS
- Wazuh chosen over Security Onion and OSSIM (native integration, no licensing, active response module)
- Cowrie chosen (medium-interaction, actively maintained, SSH/Telnet focused)
- Random Forest for known attacks (supervised, high accuracy on benchmark data)
- Isolation Forest for novel/slow attacks (unsupervised, no labels needed)
- VMware Workstation for VM management (isolated internal network)
- All components 100% open-source — deployable on commodity hardware

---

## SCOPE BOUNDARIES
**IN scope:** Linux endpoint monitoring, SSH/Telnet honeypot, 7 attack categories, 3 response actions, VM-based testing  
**OUT of scope:** Cloud monitoring, Windows agents, encrypted traffic analysis, Kenya Data Protection Act compliance, production deployment

---

## FORMATTING NOTES
- Font: Times New Roman 12pt
- Line spacing: 1.5
- Paragraph alignment: Justified
- Citation style: APA 7th edition
- Roman numerals: Declaration → Definition of Terms
- Arabic page numbers: Chapter 1 onwards (starting at 1)
- Supervisor: Mr. James Gikera (School of Computing and Engineering Sciences)

---

*This document was generated as a project handoff safety copy. Last updated: Chapter 4 in progress.*
