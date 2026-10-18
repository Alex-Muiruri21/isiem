# ISIEM — Deployment & Attack Runbook (live lab)

Follow this top to bottom. Each box is a command to run on the machine named in the
heading. Paste outputs back to Claude if anything looks wrong. Lab IPs are already
filled in for your setup.

| VM | IP | Login |
|---|---|---|
| Wazuh server | 192.168.242.130 | wazuh-user / wazuh |
| Endpoint-1 | 192.168.242.201 | endpoint1 / endpoint123 |
| Endpoint-2 | 192.168.242.200 | endpoint1 / endpoint123 |
| Cowrie honeypot | 192.168.242.202 | honeypot / honeypot123 |
| Kali (attacker) | (fill in: `hostname -I` on Kali) | kali |

> The code is already copied to the server and both endpoints (`~/isiem`). The
> honeypot needs no code.

---

## PART A — Wazuh server: rules, response config, ML engine

### A1. Verify code + IPs
```bash
ls ~/isiem && grep ENDPOINT1 ~/isiem/attacks/targets.sh
```
Expect the folder list and `ENDPOINT1="192.168.242.201"`.

### A2. Install rules + decoders + log dir
```bash
sudo cp ~/isiem/wazuh/rules/isiem_rules.xml /var/ossec/etc/rules/
```
```bash
sudo cp ~/isiem/wazuh/decoders/isiem_decoders.xml /var/ossec/etc/decoders/
```
```bash
sudo mkdir -p /var/log/isiem && sudo chmod 755 /var/log/isiem
```

### A3. Insert response + verdict config into ossec.conf (backs up first)
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

### A4. Install the 3 active-response scripts on the SERVER
```bash
sudo cp ~/isiem/response/{block_ip,lock_account,notify_admin}.py /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
sudo chown root:wazuh /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
```

### A5. Restart manager, check for errors
```bash
sudo systemctl restart wazuh-manager && sleep 5 && sudo tail -n 15 /var/ossec/logs/ossec.log
```
No `ERROR` lines = good. (A `WARNING` about an empty verdict log is fine.)

### A6. Build the ML Python environment + benchmark models
```bash
cd ~/isiem/ml && python3 -m venv ml-env && source ml-env/bin/activate && pip install -q scikit-learn pandas numpy joblib
```
```bash
python3 train_benchmark.py
```
Expect it to print RF ~99.9% (matched) / ~73.8% (official) and IF ~81%.

### A7. Quick offline self-test of the engine
```bash
python3 tests/test_detection.py
```
Expect: `PASS: all ... categories detected, normal traffic not flagged`.

---

## PART B — Endpoints: response scripts + scan logging

Run on **Endpoint-1 (.201)** AND **Endpoint-2 (.200)**. SSH from the server, or use
the VM console. (SSH from server: `ssh endpoint1@192.168.242.201`.)

### B1. Install the 3 response scripts
```bash
sudo cp ~/isiem/response/{block_ip,lock_account,notify_admin}.py /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
sudo chown root:wazuh /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
```

### B2. Enable scan (SYN) logging so port scans reach Wazuh
```bash
sudo bash ~/isiem/attacks/endpoint_prep.sh
```

### B3. Confirm the agent is active
```bash
sudo systemctl status wazuh-agent --no-pager | grep Active
```

---

## PART C — Honeypot (.202): just verify it's alive (no code needed)

```bash
sudo systemctl status cowrie --no-pager | grep Active
sudo ss -tlnp | grep 2222
sudo systemctl status wazuh-agent --no-pager | grep Active
sudo iptables -t nat -L PREROUTING -n | grep 2222
```
Want: Cowrie active, something on 2222, agent active, a REDIRECT for port 22.
If the REDIRECT is gone (reboots clear it):
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

---

## PART D — Confirm agents report in

On the **server**:
```bash
sudo /var/ossec/bin/agent_control -l
```
Expect Endpoint-1, Endpoint-2, Cowrie (and the Windows host) listed **Active**.
Or check the dashboard at `https://192.168.242.130` (admin / admin) → Agents.

---

## PART E — Start the live engine (keep this terminal open)

On the **server**, in its own terminal:
```bash
cd ~/isiem/ml && source ml-env/bin/activate
sudo -E env "PATH=$PATH" ISIEM_VERDICT_LOG=/var/log/isiem/ml_verdicts.json python3 ml_engine.py
```
It prints `following /var/ossec/logs/alerts/alerts.json ...` and then a line per
detection. Leave it running. (Open a second server terminal for the measure commands.)

Optional watch, in a second server terminal:
```bash
sudo tail -f /var/ossec/logs/active-responses.log
```

---

## PART F — Run the 5 attack scenarios from Kali

First, on **Kali**: copy the code if not already, and get its IP.
```bash
hostname -I            # note Kali's IP for the measure step
cd ~/isiem/attacks && ls
```
If `~/isiem` is missing on Kali, from the Windows laptop:
`scp -r "C:\Users\brian\Downloads\isiem-main" kali@<KALI-IP>:~/isiem`
(start SSH on Kali first: `sudo systemctl start ssh`).

Run each scenario, **note the START time** it prints, run it 3 times.

### Scenario 1 — SSH brute force
```bash
./scenario1_bruteforce.sh
```
### Scenario 2 — port scan
```bash
./scenario2_portscan.sh
```
### Scenario 3 — lateral movement (needs sshpass: `sudo apt install -y sshpass`)
```bash
./scenario3_lateral.sh
```
### Scenario 4 — privilege escalation
```bash
./scenario4_privesc.sh
```
### Scenario 5 — exfiltration + C2 beaconing
```bash
./scenario5_exfil_c2.sh
```

After each run, watch the engine terminal on the server — you should see a
`THREAT:`/`SUSPICIOUS:` line naming the category, and a `BLOCKED` line in the
active-responses tail.

---

## PART G — Measure MTTD / MTTR (on the server, 2nd terminal)

After each scenario run, with the START time it printed and Kali's IP:
```bash
cd ~/isiem && python3 attacks/measure.py \
  --start "2026-10-18 12:00:00" \
  --ip <KALI-IP> \
  --scenario "SSH Brute Force"
```
Replace the time, IP and name each run. It prints MTTD/MTTR and appends a row to
`evidence/metrics.csv`. Targets: MTTD < 30 s, MTTR < 60 s.

---

## PART H — Reset between runs

On the attacked **endpoint**(s):
```bash
sudo iptables -F INPUT              # clear blocks (or wait the 600s auto-timeout)
sudo passwd --unlock endpoint1      # if an account got locked
```
On the **server**: stop the engine with Ctrl+C and restart it (Part E) — it reports
each IP/category once per process, so a restart re-arms it for the next run.

---

## PART I — Collect evidence for Chapter 5

Screenshots to grab:
1. Dashboard → Agents (all active)
2. A Cowrie honeypot alert on the dashboard
3. `isiem_ml` alerts on the dashboard (search the `isiem_ml` rule group)
4. The engine terminal showing each THREAT detection
5. `active-responses.log` with BLOCKED lines
6. `evidence/metrics.csv` (the timing table)

Then:
```bash
cat ~/isiem/evidence/metrics.csv
```
Copy the numbers into `docs/chapter5_draft.md` (`[RUN]` cells), and back up:
```bash
cd ~/isiem && git add -A && git commit -m "Phase 4 results" && git push
```
(git push works from the Kali laptop; on the VMs you can instead scp the evidence
folder back to Windows and commit from the Kali laptop.)

---

## Troubleshooting
- **Dashboard timeout after a reboot:** the indexer needs 2–5 min. On the server:
  `sudo systemctl start wazuh-indexer`, wait, then `wazuh-manager`, then
  `wazuh-dashboard`.
- **A category doesn't trigger:** on the server, look at what Wazuh actually logged:
  `sudo tail -f /var/ossec/logs/alerts/alerts.json` during the attack. If the fields
  differ, the thresholds in `ml/classifier.py` may need a tweak — send Claude a few
  lines of that alerts.json.
- **Kali never gets blocked:** make sure Kali's IP is NOT in the whitelist in
  `response/block_ip.py` (it should not be).
- **scp "permission denied":** wrong VM password — reset with `sudo passwd <user>` on
  that VM's console.
- Always shut VMs down before sleeping the laptop or unplugging the drive.
