#!/usr/bin/env python3
"""
notify_admin.py  --  Wazuh Active Response: email the administrator on a critical
detection, including the ML classification and the containment action taken.

Runs on the agent Wazuh selects. Reads the Wazuh AR JSON from stdin and sends an
email via SMTP using smtplib. Settings are read from a small config file so no
credentials live in code or in the repo:

  /var/ossec/etc/isiem_notify.conf   (INI, mode 600, owner root)
  ------------------------------------------------------------------
  [smtp]
  host = smtp.gmail.com
  port = 587
  user = youraddress@gmail.com
  password = your_app_password      ; Gmail App Password, not the login password
  from = youraddress@gmail.com
  to = admin@example.com
  ------------------------------------------------------------------

Deploy to /var/ossec/active-response/bin/notify_admin.py on the manager (or an
endpoint), chmod 750. If the config file is absent the script logs and exits 0, so
a missing mail setup never breaks the response chain.

NOTE: email is only SENT when the live lab runs with real credentials. The repo
ships no credentials; create the config on the box at deploy time.
"""
import json
import sys
import smtplib
import configparser
import os
from email.message import EmailMessage
from datetime import datetime

LOG = "/var/ossec/logs/active-responses.log"
CONF = "/var/ossec/etc/isiem_notify.conf"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} notify_admin: {msg}\n")


def main():
    try:
        # readline, not read(): wazuh-execd keeps stdin open, so read() waits forever
        msg = json.loads(sys.stdin.readline())
    except json.JSONDecodeError:
        log("could not parse stdin")
        sys.exit(1)
    if msg.get("command") != "add":
        sys.exit(0)

    if not os.path.exists(CONF):
        log(f"no config at {CONF}; skipping email (set it up at deploy time)")
        sys.exit(0)
    cfg = configparser.ConfigParser()
    cfg.read(CONF)
    s = cfg["smtp"]

    alert = msg.get("parameters", {}).get("alert", {})
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    category = data.get("category", rule.get("description", "security event"))
    src_ip = data.get("srcip") or data.get("src_ip", "unknown")
    severity = data.get("severity", rule.get("level", "?"))
    agent = alert.get("agent", {}).get("name", "unknown")

    body = (
        f"ISIEM automated alert\n"
        f"---------------------\n"
        f"Time       : {datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"Category   : {category}\n"
        f"Source IP  : {src_ip}\n"
        f"Severity   : {severity}\n"
        f"On agent   : {agent}\n"
        f"Rule       : {rule.get('description', 'n/a')} (level {rule.get('level','?')})\n\n"
        f"Automated containment has been triggered on the affected endpoint "
        f"(firewall block / account lock as applicable). Review the Wazuh "
        f"Dashboard for full context.\n"
    )

    email = EmailMessage()
    email["Subject"] = f"[ISIEM] {category} from {src_ip}"
    email["From"] = s.get("from")
    email["To"] = s.get("to")
    email.set_content(body)

    try:
        with smtplib.SMTP(s.get("host"), s.getint("port"), timeout=20) as server:
            server.starttls()
            server.login(s.get("user"), s.get("password"))
            server.send_message(email)
        log(f"email sent to {s.get('to')} re {category} from {src_ip}")
    except Exception as e:
        log(f"email failed: {e}")


if __name__ == "__main__":
    main()
