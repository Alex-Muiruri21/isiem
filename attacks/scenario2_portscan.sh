#!/usr/bin/env bash
# Scenario 2 - Port scanning / reconnaissance (Nmap SYN + version) against Endpoint-2.
# Expect ISIEM: "Port Scanning / Reconnaissance".
set -u; cd "$(dirname "$0")"; source ./targets.sh
banner "SCENARIO 2: PORT SCAN (Nmap)"
echo "[*] SYN scan + service/version detection -> Endpoint-2 ($ENDPOINT2)"
sudo nmap -sS -sV -T4 -p 1-1000 "$ENDPOINT2" 2>&1 | tail -20
echo "END: $(stamp)"
