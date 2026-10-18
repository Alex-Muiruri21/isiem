#!/usr/bin/env bash
# Run ONCE on each endpoint (Endpoint-1, Endpoint-2) before the attack runs, as root.
# Makes scans and new connections visible to Wazuh: the kernel logs each new inbound
# TCP SYN with SRC=/DST=/DPT= fields, which Wazuh's built-in iptables decoder parses
# into srcip/dstip/dstport. Rate-limited so a full nmap scan cannot flood the logs.
#
# VERIFY on the manager after a test scan:
#   sudo grep ISIEM /var/ossec/logs/archives/archives.log   (if archives enabled), or
#   paste one kern.log line into  sudo /var/ossec/bin/wazuh-logtest
# and check it decodes with srcip + dstport and hits a firewall-group rule.
set -e
iptables -C INPUT -p tcp --syn -m limit --limit 50/second -j LOG --log-prefix "ISIEM-SYN: " 2>/dev/null \
  || iptables -I INPUT 1 -p tcp --syn -m limit --limit 50/second -j LOG --log-prefix "ISIEM-SYN: "
echo "SYN logging enabled:"; iptables -L INPUT -n --line-numbers | head -5
echo "Wazuh agent must read the kernel log. Ubuntu's default agent config watches"
echo "journald/syslog; confirm with: grep -A2 'journald\|syslog' /var/ossec/etc/ossec.conf"
