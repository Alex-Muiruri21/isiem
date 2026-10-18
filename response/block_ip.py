#!/usr/bin/env python3
"""
block_ip.py  --  Wazuh Active Response script: firewall-block an attacking IP.

Runs ON the agent Wazuh selects (configured <location>local</location>, i.e. the
host that raised the alert), NOT on the manager. Wazuh passes a JSON object on
stdin; for an "add" command we read the source IP from the alert and insert an
iptables DROP rule, and for "delete" we remove it (Active Response timeout).

Deploy to  /var/ossec/active-response/bin/block_ip.py  on every endpoint, chmod 750,
owner root:wazuh. Registered via the <command>/<active-response> blocks in
ossec-manager-snippets.conf.

Safety: a whitelist of infrastructure IPs (the manager, gateways, the local host)
is never blocked. This is the fix for the earlier script, which could block an
endpoint's own address and sever it from the manager.
"""
import json
import sys
import subprocess
import ipaddress
from datetime import datetime

LOG = "/var/ossec/logs/active-responses.log"

# Never block these. EDIT to match the lab: manager IP, gateway, DNS.
WHITELIST = {
    "192.168.242.130",   # Wazuh manager
    "192.168.242.132",   # Endpoint-1
    "192.168.242.133",   # Endpoint-2
    "192.168.242.135",   # Cowrie honeypot
    "192.168.242.2",     # VMware NAT gateway
    "192.168.242.1",     # Windows host on VMnet8
    "127.0.0.1",
}
# Also never block private-infra ranges you rely on, if any:
WHITELIST_NETS = []  # e.g. [ipaddress.ip_network("10.0.0.0/24")]


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} block_ip: {msg}\n")


def is_whitelisted(ip):
    if ip in WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> refuse to act
    return any(addr in net for net in WHITELIST_NETS)


def run(args):
    return subprocess.run(args, capture_output=True, text=True)


def main():
    raw = sys.stdin.read()
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log(f"could not parse stdin: {raw[:200]}")
        sys.exit(1)

    command = msg.get("command", "")
    alert = msg.get("parameters", {}).get("alert", {})
    src_ip = (alert.get("data", {}).get("srcip")
              or alert.get("data", {}).get("src_ip"))

    if not src_ip:
        log("no source IP in alert; nothing to do")
        sys.exit(0)
    if is_whitelisted(src_ip):
        log(f"refusing to block whitelisted/infra IP {src_ip}")
        sys.exit(0)

    if command == "add":
        # idempotent: check first
        chk = run(["iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"])
        if chk.returncode != 0:
            r = run(["iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"])
            if r.returncode == 0:
                log(f"BLOCKED {src_ip}")
            else:
                log(f"failed to block {src_ip}: {r.stderr.strip()}")
        else:
            log(f"{src_ip} already blocked")
    elif command == "delete":
        r = run(["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"])
        log(f"UNBLOCKED {src_ip}" if r.returncode == 0
            else f"unblock {src_ip}: {r.stderr.strip()}")
    else:
        log(f"unknown command '{command}'")


if __name__ == "__main__":
    main()
