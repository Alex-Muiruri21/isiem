#!/usr/bin/env python3
"""Generate a realistic Wazuh alerts.json (JSON lines) exercising each attack
category, so ml_engine.py can be validated offline without the lab running."""
import json
import sys
from datetime import datetime, timedelta, timezone

OUT = sys.argv[1] if len(sys.argv) > 1 else "sample_alerts.json"
base = datetime(2026, 10, 16, 23, 5, 0, tzinfo=timezone.utc)  # off-hours


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def alert(dt, level, groups, agent, aip, data):
    return {"timestamp": ts(dt), "rule": {"level": level, "groups": groups,
            "description": groups[0]}, "agent": {"name": agent, "ip": aip},
            "data": data}


rows = []

# 1. Brute force: attacker .140 -> endpoint-1, 15 failed SSH logins
for i in range(15):
    rows.append(alert(base + timedelta(seconds=i), 5, ["authentication_failed", "sshd"],
                      "endpoint-1", "192.168.242.132",
                      {"srcip": "192.168.242.140", "srcuser": "root", "dstport": "22"}))

# 2. Port scan: attacker .141 -> many ports on endpoint-2
for p in range(20, 65):
    rows.append(alert(base + timedelta(seconds=p), 6, ["firewall", "recon"],
                      "endpoint-2", "192.168.242.133",
                      {"srcip": "192.168.242.141", "dstip": "192.168.242.133",
                       "dstport": str(p)}))

# 3. Lateral movement: .142 logs in successfully across 4 internal hosts
for h, host in enumerate(["192.168.242.132", "192.168.242.133",
                          "192.168.242.134", "192.168.242.130"]):
    rows.append(alert(base + timedelta(seconds=120 + h * 3), 5,
                      ["authentication_success", "sshd"], "endpoint-1",
                      "192.168.242.132",
                      {"srcip": "192.168.242.142", "srcuser": "admin",
                       "dstip": host, "dstport": "22"}))

# 4. Honeypot interaction: .143 hits Cowrie, runs commands
for i in range(6):
    rows.append(alert(base + timedelta(seconds=130 + i), 10, ["cowrie", "honeypot"],
                      "cowrie-honeypot", "192.168.242.135",
                      {"srcip": "192.168.242.143", "eventid": "cowrie.command.input",
                       "dstport": "22"}))

# 5. C2 beaconing: .144 connects to one host every 10s, evenly spaced
for i in range(8):
    rows.append(alert(base + timedelta(seconds=10 + i * 10), 4, ["firewall", "connection"],
                      "endpoint-1", "192.168.242.132",
                      {"srcip": "192.168.242.144", "dstip": "192.168.242.200",
                       "dstport": "443"}))

# 6. Suspicious auth: .145 single off-hours successful login from new IP
rows.append(alert(base + timedelta(seconds=5), 5, ["authentication_success", "sshd"],
                  "endpoint-2", "192.168.242.133",
                  {"srcip": "192.168.242.145", "srcuser": "backupsvc", "dstport": "22"}))

# 7. Normal: .150 a couple of ordinary connections, business-hours baseline
day = datetime(2026, 10, 16, 11, 0, 0, tzinfo=timezone.utc)
for i in range(2):
    rows.append(alert(day + timedelta(seconds=i * 2), 3, ["firewall", "connection"],
                      "endpoint-1", "192.168.242.132",
                      {"srcip": "192.168.242.150", "dstip": "192.168.242.130",
                       "dstport": "443"}))

rows.sort(key=lambda r: r["timestamp"])
with open(OUT, "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
print(f"wrote {len(rows)} alerts to {OUT}")
