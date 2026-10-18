# isiem: Intelligent SIEM Framework (FYP)

Full title: *An Intelligent SIEM Framework for Real-Time Threat Detection and Automated
Incident Response Using Machine Learning and Behavioural Analytics*

Student: Alex Muiruri (155361), BSc Computer Networks and Cyber Security, Strathmore.
Supervisor: Mr. James Gikera.
Source documents: `docs/source/` (handoff, proposal Ch1-3, Chapter 4).

## Folder layout

| Folder | Holds |
|---|---|
| `docs/` | Report sources and chapters (`docs/source/` holds the originals as received) |
| `wazuh/` | Custom rules, decoders, `ossec.conf` snippets for manager and agents |
| `cowrie/` | Honeypot config and the agent `localfile` block that ships its JSON log |
| `ml/` | Training code, notebooks, trained models (datasets in `ml/data/`, not in git) |
| `response/` | Active-response scripts: IP block, account lock, email |
| `attacks/` | Scripts and commands for the 5 test scenarios, run from Kali |
| `evidence/` | Screenshots, timings, result tables for Chapter 5 |

## What the previous chat built (read 2026-10-16, chat ran Apr 13 - Oct 8)

Host: Windows laptop, 16 GB, VMware Workstation 17.6. All VMs on **NAT** (192.168.242.0/24, DHCP).

| VM | IP | Login | State |
|---|---|---|---|
| Wazuh Server (all-in-one 4.14.8) | 192.168.242.130 | `wazuh-user` / `wazuh` | Indexer, manager, dashboard running; dashboard admin/admin; API user wazuh-wui/wazuh-wui |
| Endpoint-1 (Ubuntu 22.04) | DHCP (.132 used as target) | `endpoint` / `endpoint123` | Wazuh agent active |
| Endpoint-2 (full clone of Endpoint-1) | DHCP | as above | Agent active (client.keys reset) |
| Windows 11 host | host IP | n/a | Wazuh agent 4.14.9 active (outside original scope) |
| Cowrie-Honeypot (Ubuntu 22.04) | 192.168.242.202 | `honeypot` / `honeypot123` | Cowrie (git, Python 3.11 venv) on 2222, iptables 22→2222, systemd `cowrie.service`, agent reads `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| Kali | NAT | n/a | Attacker, no agent |

Fixes made on the way: indexer JVM heap 1g; cert permissions + `admin_dn`/`nodes_dn` matched to
the cert subjects; cert paths pointed at `wazuh-indexer.pem`; `indexer-security-init.sh` →
"Done with success"; dashboard `wazuh.yml` API url set to the server IP; services enabled at boot.

ML (on Wazuh server, `~/ml-engine`, venv `ml-env`):
- `preprocess.py`: NSL-KDD only (KDDTrain+/KDDTest+ from GitHub mirror), **binary** normal/attack,
  LabelEncoder + StandardScaler. CICIDS2017 dropped (size).
- `train_models.py`: RF 100 trees depth 20 → **77.31%** on KDDTest+; IF trained on normal rows,
  contamination 0.05 → **78.90%**. Both below the 85% target.
- `ml_engine.py`: polls the manager API every 15 s; `block_ip.py` added (iptables DROP on the
  Wazuh server, log to `/var/log/ml_blocks.log`). `metrics.md` table created. No attack run yet.

### Problems found in that ML engine (must fix before Phase 4)
1. It calls `GET /alerts` on port 55000. The Wazuh server API has no alerts endpoint (alerts live in
   the indexer, `wazuh-alerts-*`, and in `/var/ossec/logs/alerts/alerts.json`). So it always prints
   "no new alerts", whatever happens. It has never actually seen an alert.
2. `extract_features` looks for NSL-KDD fields (src_bytes, flag, ...) inside Wazuh alerts. They are
   never there, so every alert becomes the same default vector and gets the same verdict.
3. `block_ip` runs on the Wazuh server, not on the attacked endpoint, and falls back to the
   *agent's* IP, so it would block your own endpoints and cut them off from the manager.
4. Binary only, but the report promises 7 attack categories.
5. ML verdicts are only printed to a terminal; the report says they show on the Wazuh dashboard.

## Status as of 2026-10-16

Report: Chapters 1-3 done, Chapter 4 written with all 7 figures.

Note: the table above is the working lab on the Windows laptop. The list below is only what is
on the Transcend, which looks like an older or partial copy (location of Endpoint-1/2 and Cowrie
still to confirm).

Lab copy on the Transcend (VMware Workstation 17.6, `/media/esborn/Transcend/VMs/`, last run on a Windows host as `D:\VMs`):
- **Wazuh Server**: Ubuntu, 5 GB RAM, 2 vCPU, 46 GB disk. Last run 2026-10-15: the
  host went to sleep at 23:20 UTC with the VM still running, and it was never shut down.
  Earlier that day VMware reported the disk "needs repair". Stale `.lck` folders are
  still present. Needs a careful first boot (see below).
- **Endpoint1**: VM shell created (1 GB RAM), disk is 2 MB, so no OS installed yet.
- **Kali 2025.4**: present (2 GB RAM, 4 vCPU).
- **Endpoint2, Cowrie honeypot**: not created yet.
- All VMs use NAT networking; the design calls for an isolated internal network.

The Transcend's NTFS was damaged by that unclean shutdown; fixed with `ntfsfix` on 2026-10-16.

## Issues to resolve before building further

1. **ML features vs live data.** CICIDS2017 and NSL-KDD contain *network-flow* features
   (packet counts, flow duration, flags). Wazuh produces *host log events*. A model trained
   on flows can't classify a raw Wazuh event. A live flow source is needed, e.g. CICFlowMeter
   or Zeek on the endpoints, so live data has the same features as the training data.
   Behavioural detection (off-hours logins, new source IP, lateral SSH, beaconing) fits
   Isolation Forest on features built from Wazuh auth and network events.
2. **Combining CICIDS2017 + NSL-KDD.** They share almost no features (78 flow features vs
   41 KDD features), so "aligned and combined" is hard to defend. Simpler: train per dataset
   and report both, or use CICIDS2017 only and cite NSL-KDD as a benchmark.
3. **VirtualBox vs VMware.** Ch1 objective iv, Ch3 (3.3.2, 3.4.1, 3.5.2) and Ch4 say
   VirtualBox; the handoff and the actual lab use VMware Workstation. Make the report match.
4. **RAM budget.** The design runs 5 VMs at once. Rough plan: Wazuh 5-6 GB, Endpoint1/2 and
   Cowrie 1 GB each, Kali 2 GB, about 11 GB total. Fits a 16 GB host if little else is open.
5. **Running VMs from a USB NTFS drive.** Slow, and an unplug or host sleep corrupts both the
   VM disk and the NTFS volume (as just happened). Shut VMs down before sleep or unplug.

## Sprint plan (from Ch3)

1. Wazuh server healthy + agents on Endpoint1/2 + baseline alerts
2. Cowrie deployed, its JSON log forwarded into Wazuh, custom decoder/rules
3. ML: train RF + IF, feature pipeline on live data, scores written back into Wazuh alerts
4. Active response (iptables block, `passwd --lock`, smtplib email) + 5 scenarios × 3 runs,
   measuring accuracy, FPR, MTTD (<30 s), MTTR (<60 s)
