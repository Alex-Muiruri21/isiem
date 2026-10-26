# ISIEM — Full Command Cheat-Sheet (every command, in order)

The complete command list for a lab session: bring the system up, then run all
five scenarios three times each, measure every run, and back up the evidence.

Each block says **which machine** to run it on. Commands are copy-paste ready with
the lab's real values. The only thing you ever change per run is the `--start` time
and the `--scenario` name in the measure command.

**Reference values (confirm each session — DHCP drifts):**

| Machine | IP | Login |
|---|---|---|
| Wazuh server | 192.168.242.130 (static) | wazuh-user / wazuh |
| Endpoint-1 | 192.168.242.201 | endpoint1 / endpoint123 |
| Endpoint-2 | 192.168.242.200 | endpoint1 / endpoint123 |
| Cowrie honeypot | 192.168.242.202 | honeypot / honeypot123 |
| Kali (attacker) | 192.168.242.204 | kali |

---

## PART 0 — Session start-up (run once each session)

### 0.1 Confirm IPs (DHCP changes them between boots)
**Kali, both endpoints, server:**
```bash
ip a | grep 'inet 192'
```
If Kali shows two IPs (two NICs on the subnet), pin it to one:
```bash
sudo ip link set eth0 down; ip a | grep 'inet 192'
```
If any IP differs from the table above, use the real one in the commands below.

### 0.2 Confirm the manager and agents are up
**Server:**
```bash
systemctl is-active wazuh-manager
sudo /var/ossec/bin/agent_control -l
ping -c2 github.com
```
Want `active`, all agents `Active`, and ping replies.

### 0.3 Re-add the SYN LOG rule (reboots wipe it — needed for S2/S3/S5)
**Server:**
```bash
sudo bash ~/isiem/attacks/endpoint_prep.sh
```
**Each endpoint:**
```bash
sudo bash /tmp/endpoint_prep.sh
sudo iptables -L INPUT -n --line-numbers | head -4
```
Each should print a `LOG ... "ISIEM-SYN: "` line. If `/tmp/endpoint_prep.sh` is
missing on an endpoint, copy it first — from the **server**:
```bash
scp ~/isiem/attacks/endpoint_prep.sh endpoint1@192.168.242.201:/tmp/
scp ~/isiem/attacks/endpoint_prep.sh endpoint1@192.168.242.200:/tmp/
```

### 0.4 Restore the honeypot redirect if a reboot cleared it
**Honeypot:**
```bash
sudo iptables -t nat -L PREROUTING -n | grep 2222 || sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

### 0.5 Confirm SYN lines become rule 100020 alerts (prove once per session)
**Server:**
```bash
sudo /var/ossec/bin/wazuh-logtest
```
Paste this one line, press Enter, then Ctrl+C:
```
Oct 26 10:00:00 endpoint-1 kernel: ISIEM-SYN: IN=ens33 OUT= MAC=00:0c:29:be:ad:ae:00:0c:29:45:2b:de:08:00 SRC=192.168.242.204 DST=192.168.242.200 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=30143 PROTO=TCP SPT=49329 DPT=7 WINDOW=1024 RES=0x00 SYN URGP=0
```
Phase 3 must show **`id: '100020'`, `level: '3'`**. If it shows 4100, the rule isn't
installed — see PART 6.

---

## PART 1 — The per-run loop (memorise this; every run is these 5 steps)

**STEP A — Reset.** Remove any existing block. Run on the **server, both endpoints,
and the honeypot**:
```bash
sudo iptables -D INPUT -s 192.168.242.204 -j DROP
sudo passwd -u endpoint1
```
("Bad rule" just means there was no block — fine. Never use `iptables -F INPUT`; it
deletes the SYN LOG rule.)

**STEP B — Restart the engine.** In the engine terminal on the **server**, press
Ctrl+C, then:
```bash
cd ~/isiem/ml && source ml-env/bin/activate
sudo -E env "PATH=$PATH" ISIEM_VERDICT_LOG=/var/log/isiem/ml_verdicts.json python3 ml_engine.py
```
Wait for `[info] ISIEM ML engine following ...`.

**STEP C — Run the scenario from Kali** (see PART 2 for the exact script per
scenario). **Copy the `START:` line it prints.**

**STEP D — Refresh endpoint-1's response log** (skip for S2, which never blocks).
On **endpoint-1**:
```bash
sudo cp /var/ossec/logs/active-responses.log /tmp/ep1_ar.log && sudo chmod 644 /tmp/ep1_ar.log
```

**STEP E — Measure.** On the **server**:
```bash
scp endpoint1@192.168.242.201:/tmp/ep1_ar.log /tmp/ep1_ar.log
cd ~/isiem && ISIEM_AR_LOG=/tmp/ep1_ar.log python3 attacks/measure.py \
  --start "YYYY-MM-DD HH:MM:SS" --ip 192.168.242.204 --scenario "<NAME>"
```
Use the START (no milliseconds) from STEP C, and the exact `<NAME>` per scenario
below. Each run appends one row to `evidence/metrics.csv`.

---

## PART 2 — The five scenarios (run each 3 times via the PART 1 loop)

Keep the `--scenario` name identical across a scenario's 3 runs so they group for
averaging.

### Scenario 1 — SSH Brute Force
- **Kali (STEP C):**
```bash
cd ~/isiem/attacks && ./scenario1_bruteforce.sh
```
- Engine should print: `THREAT: 192.168.242.204 -> Brute Force / Credential Stuffing (sev 10 ...)`
- **Measure name:** `"SSH Brute Force"`  ·  Target: MTTD <30s, MTTR <60s

### Scenario 2 — Port Scan  (detection-only, no block by design)
- **Kali (STEP C):**
```bash
cd ~/isiem/attacks && ./scenario2_portscan.sh
```
- Engine should print: `SUSPICIOUS: 192.168.242.204 -> Port Scanning / Reconnaissance (sev 7 ...)`
- **Skip STEP D.** Measure reads n/a for MTTR — that is the correct result.
- **Measure name:** `"Port Scan"`  ·  Target: MTTD <30s (MTTR n/a)

### Scenario 3 — Lateral Movement
- **Kali (STEP C):** (needs sshpass once: `which sshpass || sudo apt install -y sshpass`)
```bash
cd ~/isiem/attacks && ./scenario3_lateral.sh
```
- Engine should print: `THREAT: 192.168.242.204 -> Lateral Movement (sev 12 ...)`
- **Measure name:** `"Lateral Movement"`  ·  Target: MTTD <30s, MTTR <60s

### Scenario 4 — Privilege Escalation (attempt)
- **Kali (STEP C):**
```bash
cd ~/isiem/attacks && ./scenario4_privesc.sh
```
- Engine should print: `THREAT: 192.168.242.204 -> Privilege Escalation (sev 13 ...)`
- **Measure name:** `"Privilege Escalation"`  ·  Target: MTTD <30s, MTTR <60s

### Scenario 5 — Data Exfiltration + C2 Beaconing  (~90s to run)
- **Kali (STEP C):**
```bash
cd ~/isiem/attacks && ./scenario5_exfil_c2.sh
```
- Engine should print: `THREAT: 192.168.242.204 -> Command and Control Beaconing (sev 11 ...)`
- **Measure name:** `"C2 Beaconing"`  ·  Target: MTTR <60s. **MTTD will be ~45s**
  (misses 30s): beacon detection needs ~4 intervals × 10s before it can fire —
  report this as a documented floor, don't tune the threshold after the fact.

**Recommended order:** do both remaining runs of a scenario back-to-back
(S1,S1 → S2,S2 → …). 10 runs left after run 1; ~3 min each.

---

## PART 3 — Check results any time

**Server:**
```bash
cat ~/isiem/evidence/metrics.csv                                   # the timing table
sudo tail -5 /var/log/isiem/ml_verdicts.json                       # engine verdicts
sudo grep -a '"id":"100020"' /var/ossec/logs/alerts/alerts.json | tail -3 | cut -c1-200   # SYN alerts
sudo tail -8 /var/ossec/logs/active-responses.log                  # server-side responses
```
**Endpoint-1 / Endpoint-2** (where blocks actually run):
```bash
sudo tail -8 /var/ossec/logs/active-responses.log
sudo iptables -L INPUT -n | head -4
```

---

## PART 4 — Collect evidence for Chapter 5

Screenshots to grab: dashboard → Agents (all active); a Cowrie honeypot alert; the
`isiem_ml` rule group alerts; the engine terminal THREAT lines; a `BLOCKED` line in
active-responses.log; `evidence/metrics.csv`.

**Server:**
```bash
cp -a ~/isiem/evidence ~/evidence_backup_$(date +%F)     # local safety copy
cat ~/isiem/evidence/metrics.csv
```

---

## PART 5 — Back up to GitHub (when the internet is stable)

**Server:**
```bash
cd ~/isiem
git config user.name "Alex Muiruri"; git config user.email "akrutto100@gmail.com"
git add evidence/metrics.csv
git commit -m "Phase 4: all five scenarios x3 runs (metrics)"
git push origin HEAD:live-lab-fixes
```
Username `Alex-Muiruri21`; password is your fine-grained token (needs
**Contents: Read and write**). If push fails with a TLS/GnuTLS error, just re-run
`git push` — the commit is already saved locally and is safe.

---

## PART 6 — If something's off

- **logtest shows rule 4100 not 100020:** the fixed rule isn't installed.
  ```bash
  cd ~/isiem && git pull
  sudo cp wazuh/rules/isiem_rules.xml /var/ossec/etc/rules/ && sudo chown root:wazuh /var/ossec/etc/rules/isiem_rules.xml
  sudo rm -f /var/ossec/etc/decoders/isiem_decoders.xml
  sudo /var/ossec/bin/wazuh-analysisd -t && echo CONFIG-OK
  sudo systemctl restart wazuh-manager; sleep 30; systemctl is-active wazuh-manager
  ```
- **Engine fired but measure says NOT CONTAINED:** read endpoint-1's log via
  `ISIEM_AR_LOG=/tmp/ep1_ar.log` (STEP E already does this). The endpoint is where
  the real block happens; the manager logs it a bit later.
- **`ml_engine.py: No such file`:** you're in the wrong folder — the engine lives in
  `~/isiem/ml`, so run the full `cd ~/isiem/ml && source ...` line.
- **Kali's IP changed / shows two IPs:** `sudo ip link set eth0 down`, then use
  whatever `ip a | grep 'inet 192'` shows in `--ip`.
- **A scenario shows no detection:** note it, move on, don't debug mid-session.
- **git pull/push TLS error:** internet is flaky, not git — retry, or skip; the lab
  runs don't need the internet.
