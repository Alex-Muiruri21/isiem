#!/usr/bin/env python3
"""
lock_account.py  --  Wazuh Active Response: lock a compromised local account.

Runs on the agent Wazuh selects. Reads the Wazuh AR JSON from stdin, takes the
targeted username from the alert, and locks it with `passwd --lock` (add) or
unlocks it (delete). Protects a whitelist of system/service accounts so automated
response can never lock root or the wazuh account out.

Deploy to /var/ossec/active-response/bin/lock_account.py on endpoints, chmod 750.
"""
import json
import os
import sys
import subprocess
from datetime import datetime

LOG = "/var/ossec/logs/active-responses.log"
# wazuh-execd runs scripts with a minimal PATH; give subprocesses a full one.
SAFE_ENV = dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
PROTECTED = {"root", "wazuh", "wazuh-user", "sudo", "sshd", "daemon", "systemd"}


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} lock_account: {msg}\n")


def user_exists(user):
    return subprocess.run(["id", user], capture_output=True, env=SAFE_ENV).returncode == 0


def main():
    try:
        msg = json.loads(sys.stdin.readline() or sys.stdin.read())
    except json.JSONDecodeError:
        log("could not parse stdin")
        sys.exit(1)

    command = msg.get("command", "")
    data = msg.get("parameters", {}).get("alert", {}).get("data", {})
    user = data.get("dstuser") or data.get("srcuser") or data.get("user")

    if not user:
        log("no username in alert; nothing to do")
        sys.exit(0)
    if user in PROTECTED:
        log(f"refusing to lock protected account '{user}'")
        sys.exit(0)
    if not user_exists(user):
        log(f"account '{user}' does not exist locally; nothing to do")
        sys.exit(0)

    flag = "--lock" if command == "add" else "--unlock"
    r = subprocess.run(["passwd", flag, user], capture_output=True, text=True,
                       env=SAFE_ENV)
    verb = "LOCKED" if command == "add" else "UNLOCKED"
    log(f"{verb} {user}" if r.returncode == 0
        else f"{verb.lower()} {user} failed: {r.stderr.strip()}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # never die silently
        try:
            log(f"CRASH: {e!r}")
        finally:
            raise
