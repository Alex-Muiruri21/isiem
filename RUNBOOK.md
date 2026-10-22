# ISIEM — Deployment & Attack Runbook (live lab)

Follow this top to bottom. Each box is a command to run on the machine named in the
heading. Lessons from the first live runs (Oct 21–22) are folded in; the
**"Why"** notes say what went wrong before so it is not repeated.

| VM | IP (check with `ip a`!) | Login |
|---|---|---|
| Wazuh server | 192.168.242.130 (static) | wazuh-user / wazuh |
| Endpoint-1 | .200 or .201 — **DHCP has swapped them** | endpoint1 / endpoint123 |
| Endpoint-2 | .200 or .201 | endpoint1 / endpoint123 |
| Cowrie honeypot | 192.168.242.202 | honeypot / honeypot123 |
| Kali (attacker) | .203 / .204 — **changes between boots** | kali |

> **Why:** on Oct 22 Kali moved .204 → .203 → .204 and the endpoints swapped
> addresses. A wrong `--ip` makes `measure.py` say NOT DETECTED even when the engine
> fired. Run `ip a` on Kali and both endpoints at the start of every session, and set
> `ENDPOINT1` / `ENDPOINT2` in `attacks/targets.sh` (on Kali) to match.

---

## PART A — Wazuh server: rules, decoders, response config, ML engine

### A1. Get the code (git, not scp)
```bash
cd ~ && git clone https://github.com/Alex-Muiruri21/isiem.git   # private: token as password
```
(If `~/isiem` already exists as a plain scp copy, see "Converting an scp copy to git"
at the end.)

### A2. Install rules + decoders + log dir, then TEST before restarting
```bash
sudo cp ~/isiem/wazuh/rules/isiem_rules.xml /var/ossec/etc/rules/
sudo cp ~/isiem/wazuh/decoders/isiem_decoders.xml /var/ossec/etc/decoders/
sudo chown root:wazuh /var/ossec/etc/rules/isiem_rules.xml /var/ossec/etc/decoders/isiem_decoders.xml
sudo mkdir -p /var/log/isiem && sudo chmod 755 /var/log/isiem
sudo /var/ossec/bin/wazuh-analysisd -t && echo CONFIG-OK
```
Only continue if it prints `CONFIG-OK`. If it errors on `isiem_decoders.xml`,
remove that file (`sudo rm /var/ossec/etc/decoders/isiem_decoders.xml`) and send
Claude the error — the rest of the system still works without it.

> **Why pcre2:** rule 100051 matches severity with `type="pcre2"`. The default
> matcher has no `[0-5]` character classes, so before the fix it never matched and
> Active Response never fired.

### A3. Insert response + verdict config into ossec.conf (fresh server only)
```bash
sudo grep -c 'isiem-block-ip' /var/ossec/etc/ossec.conf
```
If that prints **0**, insert the snippets:
```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak && sudo python3 - <<'PY'
conf='/var/ossec/etc/ossec.conf'
snip=open('/home/wazuh-user/isiem/wazuh/config/ossec-manager-snippets.conf').read()
s=open(conf).read()
i=s.rfind('</ossec_config>')
open(conf,'w').write(s[:i]+'\n'+snip+'\n'+s[i:])
print('ossec.conf updated')
PY
```
If it prints **more than 0**, the config is already there — just make sure the
manager-side block exists (needed so `measure.py` sees containment):
```bash
sudo grep -c '<location>server</location>' /var/ossec/etc/ossec.conf
```
If that is 0, add it:
```bash
sudo sed -i '$ i\<active-response>\n  <command>isiem-block-ip</command>\n  <location>server</location>\n  <rules_id>100051,100052</rules_id>\n  <timeout>600</timeout>\n</active-response>' /var/ossec/etc/ossec.conf
```

> **Why:** `location=all` runs the block on the agents only, so BLOCKED lands in each
> endpoint's log and the manager's log stays empty → every run read NOT CONTAINED.
> The `location=server` block makes the manager log it too.
> `<expect>` tags are deprecated since 4.2 and ignored — don't add them.

### A4. Install the 3 active-response scripts on the SERVER
```bash
sudo cp ~/isiem/response/{block_ip,lock_account,notify_admin}.py /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
sudo chown root:wazuh /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
```
> **Why:** wazuh-execd starts scripts with a minimal PATH (no `/usr/sbin`), so the
> old script's bare `iptables` call crashed silently. The new one uses a full PATH,
> logs `received ...` on every call, and logs `CRASH: ...` if anything fails.

### A5. Restart manager, check for errors
```bash
sudo systemctl restart wazuh-manager; sleep 30; systemctl is-active wazuh-manager
sudo grep -iE 'error|critical' /var/ossec/logs/ossec.log | tail -5
```
`active` = good. If `systemctl restart` times out, run `sudo systemctl start
wazuh-manager` and check again — the manager can be slow to stop.

### A6. ML environment + benchmark models (once)
```bash
cd ~/isiem/ml && python3 -m venv ml-env && source ml-env/bin/activate && pip install -q scikit-learn pandas numpy joblib
python3 train_benchmark.py
```
Expect RF ~99.9% (matched) / ~73.8% (official KDDTest+) and IF ~81%.

### A7. Offline self-test of the engine
```bash
python3 tests/test_detection.py
```
Expect: `PASS: all 7 categories detected, normal traffic not flagged`.

---

## PART B — Endpoints + server: response scripts and SYN logging

Run on **Endpoint-1, Endpoint-2 AND the Wazuh server** (the server receives
Scenario 3 logins and Scenario 5 beacons, so it needs the SYN logging too).

### B1. Install the 3 response scripts (endpoints; the server did A4)
```bash
sudo cp ~/isiem/response/{block_ip,lock_account,notify_admin}.py /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
sudo chown root:wazuh /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
```

### B2. Turn on SYN logging (re-run after every reboot)
```bash
sudo bash ~/isiem/attacks/endpoint_prep.sh
sudo iptables -L INPUT -n --line-numbers | head -4     # expect a LOG ... "ISIEM-SYN: " line
```

### B3. Make sure the agent reads the kernel log
```bash
sudo grep -n -A2 'syslog\|journald\|kern.log' /var/ossec/etc/ossec.conf
```
If nothing about syslog/journald/kern.log appears, add the block from
`wazuh/config/ossec-agent-synlog-localfile.xml` and `sudo systemctl restart wazuh-agent`.

### B4. Verify a SYN line becomes an alert (once, the most important check)
From **Kali**: `sudo nmap -sS -p 1-50 <endpoint IP>`. Then on that **endpoint**:
```bash
sudo grep -a ISIEM-SYN /var/log/kern.log | tail -1
sudo journalctl -k | grep ISIEM-SYN | tail -1        # if kern.log printed nothing
```
Copy that line. On the **server**: `sudo /var/ossec/bin/wazuh-logtest`, paste it.
Want: decoder `isiem-syn`, fields `srcip`, `dstip`, `dstport`, and **rule 100020**.
If it shows a different decoder or no rule, paste the logtest output to Claude —
Scenarios 2, 3 and 5 depend on this.

### B5. Confirm the agent is active
```bash
sudo systemctl status wazuh-agent --no-pager | grep Active
```

---

## PART C — Honeypot (.202): verify it's alive

```bash
sudo systemctl status cowrie --no-pager | grep Active
sudo ss -tlnp | grep 2222
sudo systemctl status wazuh-agent --no-pager | grep Active
sudo iptables -t nat -L PREROUTING -n | grep 2222
```
If the REDIRECT is gone (reboots clear it):
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

---

## PART D — Confirm agents report in (server)
```bash
sudo /var/ossec/bin/agent_control -l
```
Expect endpoint-1, endpoint2, cowrie-honeypot **Active**. Note `location=all` sends
responses to **every** listed agent — remove any agent that is not part of this lab.

---

## PART E — Start the live engine (server, its own terminal)
```bash
cd ~/isiem/ml && source ml-env/bin/activate
sudo -E env "PATH=$PATH" ISIEM_VERDICT_LOG=/var/log/isiem/ml_verdicts.json python3 ml_engine.py
```
Wait for `[info] ISIEM ML engine following ...`. Use the **server's VM console**
for the runs: a block also drops Kali→server SSH for 600 s.

Watch containment in a second terminal **on the server** (manager-side block) and,
optionally, on endpoint-1 (agent-side block):
```bash
sudo tail -f /var/ossec/logs/active-responses.log
```

---

## PART F — Run the scenarios from Kali

```bash
ip a | grep 'inet 192'        # Kali's IP for this session -> use it in Part G
cd ~/isiem/attacks && ls
```
Each script prints a banner like:
```
 START: 2026-10-22 12:06:19.524   (record this as the attack start time)
```
**Copy that START line every run** (screenshot the Kali terminal). Run each scenario
3 times.

| # | Command | Expected engine line | Response |
|---|---|---|---|
| 1 | `./scenario1_bruteforce.sh` | Brute Force (sev 10), Honeypot (sev 12) | block |
| 2 | `./scenario2_portscan.sh` | Port Scanning (sev 7) | none — detection-only by design |
| 3 | `./scenario3_lateral.sh` (needs `sudo apt install -y sshpass`) | Lateral Movement (sev 12) | block |
| 4 | `./scenario4_privesc.sh` | Privilege Escalation (sev 13)* | block |
| 5 | `./scenario5_exfil_c2.sh` | C2 Beaconing (sev 11) | block |

\* Scenario 4 relies on Wazuh raising a `sudo`-group alert for the attempted
`sudo` on the endpoint. If the engine stays quiet, run
`sudo grep -a '"sudo"' /var/ossec/logs/alerts/alerts.json | tail -2` on the server
and send Claude the output.

---

## PART G — Measure MTTD / MTTR (server, 2nd terminal)

Put the **real** START (without milliseconds) and Kali's IP in — no `<...>`
placeholders, they make Python crash:
```bash
cd ~/isiem && python3 attacks/measure.py --start "2026-10-22 12:06:19" --ip 192.168.242.204 --scenario "Port Scan"
```
Targets: MTTD < 30 s, MTTR < 60 s. Each run appends a row to `evidence/metrics.csv`.

---

## PART H — Reset between runs

On the attacked **endpoint(s)** and the **server** — remove only the block, keep
the SYN LOG rule:
```bash
sudo iptables -D INPUT -s <KALI-IP> -j DROP 2>/dev/null; sudo iptables -L INPUT -n | head -4
sudo passwd --unlock endpoint1      # only if an account got locked
```
> **Why:** the old reset (`iptables -F INPUT`) also deleted the `ISIEM-SYN` LOG rule,
> which silently blinded Scenarios 2, 3 and 5. If you flushed anyway, re-run
> `sudo bash ~/isiem/attacks/endpoint_prep.sh`.

On the **server**: Ctrl+C the engine and restart it (Part E) — it reports each
IP/category once per process.

---

## PART I — Collect evidence for Chapter 5

Screenshots: dashboard agents (all active) · a Cowrie alert · `isiem_ml` alerts ·
engine THREAT lines · `active-responses.log` BLOCKED lines (server + endpoint) ·
`evidence/metrics.csv`.

```bash
cat ~/isiem/evidence/metrics.csv
cd ~/isiem && git add -A && git commit -m "Phase 4 results" && git push
```
Delete junk rows from `metrics.csv` (placeholder runs, guessed START times, runs
before the containment fix) before averaging.

---

## Known limitations (state these in Chapter 5)
- **Port scan has no automated response** (sev 7 < 10): detection-only by design.
- **Exfiltration volume is not observable**: the features count connections, not
  bytes, so Scenario 5 is detected as C2 beaconing, not as exfiltration.
- **Privilege escalation attribution** links sudo events to the most recent
  successful login on the same host; the manager (agent 000) is excluded so SIEM
  administration over SSH is not scored as an attack.
- **Infrastructure IPs are never scored** (`IGNORE_ACTORS` in `ml/ml_engine.py`):
  Windows host, NAT gateway, manager, loopback.

---

## Converting an scp copy to git (server, one time)
```bash
cp -a ~/isiem ~/isiem.bak                       # safety copy first
cd ~/isiem && git init -q && git remote add origin https://github.com/Alex-Muiruri21/isiem.git
git fetch origin <branch>                       # token as password
git checkout -f -B main origin/<branch>
```
Tracked files take the repo version; untracked/ignored files (the `ml-env` venv,
`ml/data/`, `*.joblib` models, `evidence/metrics.csv`) stay exactly as they were.

## Troubleshooting
- **Dashboard timeout after a reboot:** the indexer needs 2–5 min. Start
  `wazuh-indexer`, wait, then `wazuh-manager`, then `wazuh-dashboard`.
- **Engine fired but NOT CONTAINED:** check the manager log has a `block_ip:
  received ...` line. No line → A3's `location=server` block is missing. A `CRASH:`
  line → send it to Claude.
- **A category doesn't trigger:** `sudo tail -f /var/ossec/logs/alerts/alerts.json`
  during the attack and send Claude a few lines.
- **Kali never gets blocked:** Kali's IP must NOT be in `WHITELIST` in
  `response/block_ip.py`.
- Always shut VMs down before sleeping the laptop or unplugging the drive.
