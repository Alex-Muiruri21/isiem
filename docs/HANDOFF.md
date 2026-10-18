# ISIEM — Full Project Handoff (for any AI assistant or collaborator)

Last updated: 2026-10-18. Read this whole file before doing anything. It explains what
the project is, everything built so far, what was broken and how it was fixed, the
exact state of the lab, and the next steps (Phase 4: the attack runs).

---

## 1. The project in one paragraph

Final-year project (FYP) for **Alex Muiruri, student 155361**, BSc Computer Networks
and Cyber Security, Strathmore University, Nairobi. Supervisor: **Mr. James Gikera**.
Title: *"An Intelligent SIEM Framework for Real-Time Threat Detection and Automated
Incident Response Using Machine Learning and Behavioural Analytics."* (Presentation
title: *"An Integrated Cyber Threat Detection and Automated Response Platform for SMEs
Using SIEM, Honeypot Deception, and Machine Learning."*) It is a four-layer,
open-source security platform for small businesses:

1. **Wazuh SIEM** — collects and normalises logs from monitored machines, rule-based alerts, dashboard.
2. **Cowrie honeypot** — fake SSH/Telnet server; anyone touching it is an attacker by definition.
3. **ML engine (Python, scikit-learn)** — Random Forest (supervised) + Isolation Forest
   (unsupervised) + behavioural analytics on the live alert stream.
4. **Automated response (Python)** — block attacker IP (iptables), lock account
   (`passwd --lock`), email the admin (smtplib), triggered by Wazuh Active Response.

Methodology: Agile Design Science Research, 4 sprints/phases:
1. Wazuh + agents → 2. Cowrie → 3. ML engine → 4. Automated response + validation
(5 attack scenarios × 3 runs, measuring accuracy, false-positive rate, MTTD, MTTR).

**Acceptance targets (from the report):** detection accuracy ≥ 85% across the 7 attack
categories, false-positive rate ≤ 15%, MTTD < 30 s, MTTR < 60 s, 100% open source.

**The 7 attack categories:** brute force/credential stuffing, port scanning/recon,
lateral movement, privilege escalation, data exfiltration, C2 beaconing, suspicious
authentication patterns.

---

## 2. Where everything lives

| What | Where |
|---|---|
| **Code repo (source of truth)** | `~/isiem` on Esborn's Kali laptop (git) |
| **GitHub backup (private)** | https://github.com/Alex-Muiruri21/isiem — push with `cd ~/isiem && git push` |
| **Drive backup** | `/media/esborn/Transcend/isiem` (external 1 TB Transcend, NTFS) |
| **The lab VMs** | On the Transcend, in `VMs\`. They run **only** when the Transcend is plugged into the **Windows laptop** (VMware Workstation 17.6). |
| **Report sources** | `docs/source/` (proposal Ch1-3 PDF, Chapter 4 PDF, original handoff) |

Two laptops are involved:
- **Windows laptop (16 GB)** — runs VMware and the 5 VMs. Has its own Wazuh agent.
- **Esborn's Kali Linux laptop (16 GB)** — where the code was written and tested
  offline, and where the GitHub login lives. Can SSH into the lab only if both laptops
  share a network path to the VMs (VMware NAT is not reachable from other machines by
  default; needs bridged networking or VMware NAT port-forwarding).

---

## 3. The lab (as of 2026-10-18 — all VMs booted, static IPs set)

VMware NAT network **192.168.242.0/24** (VMnet8). Static IPs were set on 2026-10-18,
the server at .130 "and the rest follow suit" — **confirm each with `ip a`**; the
values below are the ones the code assumes.

| VM | OS | IP | Login | Role |
|---|---|---|---|---|
| Wazuh Server | Ubuntu 22.04 | 192.168.242.130 | `wazuh-user` / `wazuh` | Wazuh 4.14.8 all-in-one (indexer, manager, dashboard). Dashboard `https://192.168.242.130`, admin/admin. API user wazuh-wui / wazuh-wui. Runs the ML engine. |
| Endpoint-1 | Ubuntu 22.04 | 192.168.242.201 | `endpoint` / `endpoint123` | Monitored host, Wazuh agent |
| Endpoint-2 | Ubuntu 22.04 (full clone of E-1) | 192.168.242.200 | `endpoint` / `endpoint123` | Monitored host, Wazuh agent (client.keys was reset after cloning) |
| Cowrie-Honeypot | Ubuntu 22.04 | 192.168.242.202 | `honeypot` / `honeypot123` | Cowrie on 2222, iptables redirects 22→2222, systemd `cowrie.service`, Wazuh agent ships `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| Kali 2025.4 | Kali | (NAT, DHCP or static) | — | Attacker. No agent. |
| Windows host | Windows 11 | host IP on VMnet8 | — | Wazuh agent 4.14.9 (extra, outside original scope) |

All lab passwords are lab-only defaults; they are not real-world credentials.

---

## 4. History — what happened, in order

**Apr–Jun 2026 (previous chat):** project idea chosen; proposal (Ch1–3) written;
formatting/reference fixes. Chapter 4 (System Design, 7 UML/architecture figures)
written later.

**Oct 3–8 2026 (previous chat, building the lab on the Windows laptop):**
- Wazuh install fought several problems: VM wouldn't boot (re-imported), copy/paste
  in console (switched to SSH), indexer wouldn't start. Fixes that worked: indexer JVM
  heap set to 1 GB (`/etc/wazuh-indexer/jvm.options`); cert permissions fixed;
  `admin_dn` / `nodes_dn` in `/etc/wazuh-indexer/opensearch.yml` set to match the real
  cert subjects (`CN=admin,O=Wazuh,L=SFO,ST=CA,C=US` and
  `CN=wazuh-indexer,O=Wazuh,L=SFO,ST=CA,C=US`); cert paths pointed at
  `wazuh-indexer.pem` / `wazuh-indexer-key.pem`; ran
  `/usr/share/wazuh-indexer/bin/indexer-security-init.sh` → "Done with success".
  Dashboard API config fixed in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`
  (url = server IP, port 55000, wazuh-wui). Services enabled at boot. Tip: after a
  reboot the indexer needs 2–5 minutes before the dashboard works.
- Moved to a 16 GB laptop; endpoints installed on NAT (host-only VMnet2 had no
  internet for apt). Endpoint-2 cloned from Endpoint-1.
- Windows host agent added (fixed by correcting manager address in ossec.conf).
- Cowrie: needed Python 3.11 (Ubuntu 22.04 ships 3.10); config at
  `src/cowrie/data/etc/cowrie.cfg.dist` copied to `etc/cowrie.cfg`; started with
  `twistd`; systemd unit created. **Phases 1 and 2: done.**
- Phase 3 (on Wazuh server, `~/ml-engine`): NSL-KDD binary models (RF 77.31%,
  IF 78.90%) and an `ml_engine.py` that polled the Wazuh API. Phase 4 had just started
  (a `block_ip.py` and empty metrics table) when that chat ran out.

**Oct 15:** the Windows laptop slept with the Wazuh VM still running off the
Transcend → NTFS corruption + "virtual disk needs repair".

**Oct 16 (this session, on the Kali laptop):**
- Mounted the Transcend, repaired NTFS with `ntfsfix` (SMART health PASSED, disk is
  fine), freed space (now ~188 GB free).
- Read the whole previous chat and the report; **found Phase 3 was broken** (details
  in §5).
- Rebuilt Phase 3 and wrote everything for Phase 4 **offline** (the lab could not run
  while the drive was on the Kali laptop). Created the git repo, README, DEPLOY guide,
  report corrections, Chapter 5 draft. Pushed to private GitHub.

**Oct 18:** drive moved back to the Windows laptop; all VMs booted; static IPs set.
Three more bugs found in review and fixed before deployment (§5, items 6–8).
**Next: deploy and run Phase 4.**

---

## 5. Bugs found and fixed (important — do not reintroduce)

In the original Phase-3/4 code from the previous chat:
1. **ML engine never saw an alert.** It called `GET /alerts` on the Wazuh server API
   (port 55000). That endpoint does not exist; alerts live in the indexer and in
   `/var/ossec/logs/alerts/alerts.json`. It always printed "no new alerts".
   → New engine tails `alerts.json` directly.
2. **Features didn't exist in the data.** It looked for NSL-KDD fields (src_bytes,
   flag…) inside Wazuh alerts; they are never there, so every alert became the same
   vector. → New engine builds behavioural features that Wazuh alerts actually carry.
3. **Blocking hit the wrong machine / own machines.** `block_ip` ran on the manager and
   fell back to the *agent's* IP. → Blocking moved to Wazuh Active Response with an
   infrastructure whitelist.
4. **Binary only** vs the report's 7 categories. → Classifier now names all 7 (+ honeypot).
5. **ML results only printed to a terminal** vs report's "shown on the dashboard".
   → Verdicts written to a JSON log that Wazuh re-ingests (rule group `isiem_ml`).

Found on 2026-10-18 in the rebuilt code, fixed before deployment:
6. `source_ip()` still fell back to the agent IP (operator-precedence slip) → removed.
7. Re-ingested verdicts would feed back into the engine's own features → engine skips
   alerts whose `data.integration == "isiem-ml"`.
8. Active Response used `location=local`, but verdict alerts are generated **on the
   manager**, so containment would have run only on the manager → block/lock now use
   `location=all` (whitelists protect lab infra), email stays `local` (sent once).

---

## 6. Repo map (`~/isiem`)

| Path | What | Runs on |
|---|---|---|
| `ml/train_benchmark.py` | Trains benchmark RF + IF on NSL-KDD, writes `evidence/benchmark_*` | anywhere |
| `ml/behavioural_features.py` | Wazuh alerts → per-source-IP features (12) over a window | Wazuh server |
| `ml/classifier.py` | Features → category + severity (RF if trained, else signatures from Ch 2.3) + Isolation Forest anomaly layer | Wazuh server |
| `ml/ml_engine.py` | Live engine: tails alerts.json, 60 s window, eval every 5 s, beacon-timing check, writes `/var/log/isiem/ml_verdicts.json`. Modes: live, `--once`, `--replay FILE` | Wazuh server |
| `ml/tests/` | `make_sample_alerts.py` + `test_detection.py` (replays all categories; **passes**) | anywhere |
| `ml/data/`, `ml/models/` | NSL-KDD files, trained benchmark models (tracked in git) | — |
| `wazuh/rules/isiem_rules.xml` | Rules 100010–100013 (Cowrie), 100050–100052 (ML verdicts; 100051/100052 trigger AR) | manager `/var/ossec/etc/rules/` |
| `wazuh/config/ossec-manager-snippets.conf` | localfile for verdict log + 3 `<command>` + 3 `<active-response>` blocks | paste into manager ossec.conf |
| `wazuh/config/ossec-agent-cowrie-localfile.xml` | Cowrie log shipping (already applied) | honeypot agent |
| `response/block_ip.py` | AR: iptables DROP attacker (add/delete), whitelist of lab IPs | every agent `/var/ossec/active-response/bin/` |
| `response/lock_account.py` | AR: `passwd --lock` target user, protected accounts list | every agent |
| `response/notify_admin.py` | AR: email via SMTP; reads `/var/ossec/etc/isiem_notify.conf` (not in repo) | manager |
| `attacks/targets.sh` | Lab IPs used by all scenarios — **edit if IPs differ** | Kali |
| `attacks/endpoint_prep.sh` | Enables SYN logging on endpoints so port scans reach Wazuh | each endpoint, once |
| `attacks/scenario1..5_*.sh` | The 5 scenarios (Hydra, Nmap, SSH fan-out, sudo/privesc, beacon+exfil) | Kali |
| `attacks/measure.py` | MTTD/MTTR from verdict log + AR log → `evidence/metrics.csv` | Wazuh server |
| `DEPLOY.md` | **Step-by-step install + run guide** | — |
| `PROJECT_NOTES.md` | Status/inventory notes | — |
| `docs/REPORT_CORRECTIONS.md` | Edits to make the Word report match the build | — |
| `docs/chapter5_draft.md` | Chapter 5 draft; benchmark results filled, `[RUN]` placeholders for Phase 4 | — |

**Live features (per source IP, per 60 s window):** failed_logins, successful_logins,
distinct_users, distinct_dst_hosts, distinct_dst_ports, honeypot_hits,
cowrie_commands, conn_events, off_hours (outside 08–18), new_source,
max_rule_level, event_count.

**Benchmark results (real, in `evidence/`):** RF 99.89% on a matched 80/20 split of
KDDTrain+; RF 73.79% on official KDDTest+ (deliberately contains novel attacks — a
known property of NSL-KDD, worth discussing, not hiding); Isolation Forest 81.35%
normal-vs-attack on KDDTest+. CICIDS2017 was NOT used (too big for the VM); the report
must say NSL-KDD is the training set.

---

## 7. NEXT STEPS — Phase 4 (do these in order; full commands in `DEPLOY.md`)

0. **Confirm IPs** on every VM (`ip a`). If any differ from §3, update
   `attacks/targets.sh` and `WHITELIST` in `response/block_ip.py`.
   **Sync clocks** (MTTD compares Kali's start time with the server's detection time):
   `timedatectl` on Kali and the server should agree to within a second.
1. **Copy the repo to the VMs** (scp from the Windows host, a shared folder, or
   `git clone https://github.com/Alex-Muiruri21/isiem` — private, needs Alex's login).
2. **Manager:** copy rules/decoders, `mkdir -p /var/log/isiem`, paste
   `ossec-manager-snippets.conf` blocks, restart wazuh-manager, check `ossec.log`.
3. **All agents + manager:** install the three AR scripts (chmod 750, root:wazuh).
4. **Endpoints:** run `attacks/endpoint_prep.sh` (SYN logging), then verify one scan
   line decodes with `/var/ossec/bin/wazuh-logtest`.
5. **Manager:** venv, `pip install scikit-learn pandas numpy joblib`, run
   `train_benchmark.py`, then start `ml_engine.py` (live) with sudo.
6. **Kali:** run scenario 1…5. After each, on the manager:
   `python3 attacks/measure.py --start "<START printed>" --ip <kali IP> --scenario "<name>"`.
   Each scenario × 3 runs. Between runs: `sudo iptables -F INPUT` on endpoints (or wait
   the 600 s AR timeout), unlock any locked test user, and **restart ml_engine.py**
   (it reports each IP/category once per process, so a restart re-arms it).
7. Screenshots for Chapter 5 (dashboard agents, Cowrie alert, isiem_ml alerts,
   engine output, active-responses.log BLOCKED lines, metrics.csv).
8. Fill `[RUN]` cells in `docs/chapter5_draft.md`; apply `docs/REPORT_CORRECTIONS.md`.
9. `git add -A && git commit && git push` after every working session.

**Watch-outs:**
- Kali's IP must NOT be in the whitelist, or it will never be blocked.
- The attacker is Kali for every scenario; scenario 3 (lateral) models fan-out from
  Kali unless run from a compromised endpoint.
- Scenarios 4 and 5 depend on events Wazuh may not log by default (sudo attempts are
  logged; outbound beacon connections usually are not). If a category does not show,
  check `alerts.json` for what Wazuh actually recorded, and tune the thresholds in
  `ml/classifier.py` or add logging — then record that honestly in Chapter 5.
- Wazuh rule groups for SSH: failures `authentication_failed`, successes
  `authentication_success` — the feature extractor keys on these.
- Never run VMs off the Transcend while it is attached to the Kali laptop, and always
  shut VMs down before sleeping the Windows laptop or unplugging the drive.

---

## 8. Report status

Chapters 1–4 written (Ch 4 has all 7 figures). Needed:
- Apply `docs/REPORT_CORRECTIONS.md`: VirtualBox → VMware Workstation everywhere;
  datasets = NSL-KDD for training (CICIDS2017 reviewed only, no "combined" claim);
  decide whether the Windows agent is in scope; add the behavioural-analytics paragraph.
- Write Chapter 5 from `docs/chapter5_draft.md` with real Phase-4 numbers.
- Formatting: Times New Roman 12, 1.5 spacing, justified, APA 7; roman numerals up to
  Definition of Terms, arabic from Chapter 1. Verify every citation/DOI before submission.

---

## 9. How to work with the user

Esborn (the user) is driving the build for Alex's project and wants it finished and
polished. He prefers plain, direct steps; one command per code block; says "my guy".
When something needs a password or sudo on his machines, he runs it himself and pastes
the output. Be honest about what is tested vs untested — the Phase-4 numbers in
Chapter 5 must come from real runs, never be invented.
