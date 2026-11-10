#!/usr/bin/env python3
"""
block_ip.py  --  Wazuh Active Response script: firewall-block an attacking IP.

Wazuh runs this on every host the <active-response> block targets:
  * location=all     -> every agent (the endpoints do the real containment)
  * location=server  -> the manager too, so measure.py can read a BLOCKED line
                        from the manager's own active-responses.log
Wazuh passes a JSON object on stdin; for "add" we read the source IP from the
alert and insert an iptables DROP rule, and for "delete" we remove it (Active
Response timeout).

Deploy to  /var/ossec/active-response/bin/block_ip.py  on every agent and the
manager, chmod 750, owner root:wazuh.

Lessons from the live lab, fixed here:
  * wazuh-execd starts scripts with a minimal PATH that does not include
    /usr/sbin, so a bare "iptables" call fails with FileNotFoundError. The
    binary is resolved to an absolute path below.
  * An uncaught exception used to leave no trace in the log. Every invocation is
    now logged on arrival, and any crash is logged as "CRASH: ..." before exit.

Safety: a whitelist of infrastructure IPs (the manager, gateways, the endpoints,
the local host) is never blocked, so an endpoint is never cut off from the manager.
"""
import json
import os
import sys
import shutil
import subprocess
import ipaddress
from datetime import datetime

LOG = "/var/ossec/logs/active-responses.log"

# Never block these. EDIT to match the lab: manager IP, gateway, endpoints.
# Both .200 and .201 are listed because DHCP has swapped the two endpoints before.
WHITELIST = {
    "192.168.242.130",   # Wazuh manager
    "192.168.242.201",   # Endpoint (DHCP may swap .200/.201)
    "192.168.242.200",   # Endpoint (DHCP may swap .200/.201)
    "192.168.242.202",   # Cowrie honeypot
    "192.168.242.2",     # VMware NAT gateway
    "192.168.242.1",     # Windows host on VMnet8
    "127.0.0.1",
}
# Also never block private-infra ranges you rely on, if any:
WHITELIST_NETS = []  # e.g. [ipaddress.ip_network("10.0.0.0/24")]

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def iptables_bin():
    found = shutil.which("iptables", path=SAFE_PATH)
    return found or "/usr/sbin/iptables"


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
    env = dict(os.environ, PATH=SAFE_PATH)
    return subprocess.run(args, capture_output=True, text=True, env=env)


def main():
    raw = sys.stdin.readline()  # execd keeps stdin open; read() would hang
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log(f"could not parse stdin: {raw[:200]}")
        sys.exit(1)

    command = msg.get("command", "")
    alert = msg.get("parameters", {}).get("alert", {})
    data = alert.get("data", {}) or {}
    src_ip = data.get("srcip") or data.get("src_ip")
    log(f"received '{command}' for {src_ip} (rule {alert.get('rule', {}).get('id')})")

    if not src_ip:
        log("no source IP in alert; nothing to do")
        sys.exit(0)
    if is_whitelisted(src_ip):
        log(f"refusing to block whitelisted/infra IP {src_ip}")
        sys.exit(0)

    ipt = iptables_bin()
    if command == "add":
        # idempotent: check first
        chk = run([ipt, "-C", "INPUT", "-s", src_ip, "-j", "DROP"])
        if chk.returncode != 0:
            r = run([ipt, "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"])
            if r.returncode == 0:
                log(f"BLOCKED {src_ip}")
            else:
                log(f"failed to block {src_ip}: {r.stderr.strip()}")
        else:
            log(f"{src_ip} already blocked")
    elif command == "delete":
        r = run([ipt, "-D", "INPUT", "-s", src_ip, "-j", "DROP"])
        log(f"UNBLOCKED {src_ip}" if r.returncode == 0
            else f"unblock {src_ip}: {r.stderr.strip()}")
    else:
        log(f"unknown command '{command}'")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # never die silently again
        try:
            log(f"CRASH: {e!r}")
        finally:
            raise
