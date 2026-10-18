# ISIEM Deployment & Run Guide

This is the one page to follow when the lab is running (VMs powered on, on the
Windows host). It says **which folder goes on which machine** and the commands to
run, in order. Everything here was written and tested offline; this step installs it.

Confirm the IPs first (`ip a` on each VM) and edit them in two places if they differ
from the original build: `attacks/targets.sh` and the `WHITELIST` in
`response/block_ip.py` (and the rule IPs are not hard-coded, so nothing else).

Lab addresses assumed (NAT, from the build):
`Wazuh 192.168.242.130 · Endpoint-1 .132 · Endpoint-2 .133 · Cowrie .135 · Kali attacker`

---

## Step 0 — get the repo onto the machines

Copy the whole `isiem/` folder to each VM that needs part of it (USB, `scp`, or a
shared folder). You only need the relevant subfolder on each, but copying all of it
is simplest.

| Machine | Needs | Why |
|---|---|---|
| Wazuh server | `ml/`, `wazuh/`, `response/` | engine, rules, AR scripts live here |
| Endpoint-1 / 2 | `response/` | AR scripts run on the attacked host |
| Cowrie honeypot | `wazuh/config/ossec-agent-cowrie-localfile.xml` | already applied; for reference |
| Kali | `attacks/` | launch the scenarios |

---

## Step 1 — Wazuh manager: rules, decoders, verdict ingestion

On the **Wazuh server**:

```bash
sudo cp wazuh/rules/isiem_rules.xml      /var/ossec/etc/rules/
sudo cp wazuh/decoders/isiem_decoders.xml /var/ossec/etc/decoders/
sudo mkdir -p /var/log/isiem && sudo chmod 755 /var/log/isiem
```

Open `/var/ossec/etc/ossec.conf` and paste the blocks from
`wazuh/config/ossec-manager-snippets.conf` inside `<ossec_config>`. Then:

```bash
sudo systemctl restart wazuh-manager
sudo tail -n 20 /var/ossec/logs/ossec.log   # confirm no XML/config errors
```

## Step 2 — all endpoints + manager: active-response scripts

On the **Wazuh server AND each endpoint** (.132, .133; honeypot too if you want it
to self-defend):

```bash
sudo cp response/block_ip.py response/lock_account.py response/notify_admin.py \
        /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
sudo chown root:wazuh /var/ossec/active-response/bin/{block_ip,lock_account,notify_admin}.py
```

(Optional) email: create `/var/ossec/etc/isiem_notify.conf` from the template in the
header of `response/notify_admin.py`, `sudo chmod 600` it. Without it, email is
skipped cleanly.

## Step 2b — endpoints: make port scans visible

On **Endpoint-1 and Endpoint-2**: `sudo bash attacks/endpoint_prep.sh`
(logs inbound SYNs so Wazuh sees scans). Verify one logged line decodes with
`sudo /var/ossec/bin/wazuh-logtest` on the manager.

## Step 3 — Wazuh server: the ML engine

```bash
cd ~/isiem/ml            # wherever you copied it
python3 -m venv ml-env && source ml-env/bin/activate
pip install scikit-learn pandas numpy joblib
python3 train_benchmark.py        # builds benchmark models + Chapter 5 evidence
sudo -E env "PATH=$PATH" ISIEM_VERDICT_LOG=/var/log/isiem/ml_verdicts.json \
    python3 ml_engine.py          # live: follows /var/ossec/logs/alerts/alerts.json
```

Leave the engine running in its own terminal. It prints a line per detection and
writes verdicts to `/var/log/isiem/ml_verdicts.json`, which Wazuh re-ingests so the
detections appear on the **dashboard** (search rule groups `isiem_ml`, `cowrie`).

## Step 4 — Kali: run the scenarios and measure

On **Kali**, for each scenario note the START time it prints:

```bash
cd ~/isiem/attacks
./scenario1_bruteforce.sh
./scenario2_portscan.sh
./scenario3_lateral.sh
./scenario4_privesc.sh
./scenario5_exfil_c2.sh
```

Back on the **Wazuh server**, after each run, compute the metrics:

```bash
cd ~/isiem
python3 attacks/measure.py --start "<START time from the script>" \
        --ip <attacker IP> --scenario "SSH Brute Force"
```

Each run appends a row to `evidence/metrics.csv`. **Restart `ml_engine.py` between runs** (it reports each IP/category once per process). Run each scenario **3 times**
(Section 3.5.3) and the averages are your MTTD/MTTR for Chapter 5.

---

## Reset between runs

```bash
# on the attacked endpoint, clear any leftover blocks (AR also auto-expires in 600s)
sudo iptables -F INPUT
# re-enable a locked test account if needed
sudo passwd --unlock <user>
```

## Driving it from the Kali laptop over SSH (optional)

If both laptops are on the same Wi-Fi, add a host-only/bridged path and SSH in:
`ssh wazuh-user@192.168.242.130` (password `wazuh`). Then run Steps 1–3 remotely.
Collecting evidence is the same.

## Safety / housekeeping
- Always **shut the VMs down** before sleeping the laptop or unplugging the drive.
- The attack scripts target only the IPs in `attacks/targets.sh`. Keep it that way.
- `git` history in this repo is the source of truth; back it up to the Transcend
  (and ideally a private GitHub repo) after each session.
