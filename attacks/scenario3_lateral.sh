#!/usr/bin/env bash
# Scenario 3 - Lateral movement: from a foothold, SSH outward to several internal
# hosts in a short burst. Expect ISIEM: "Lateral Movement".
# Run this FROM a compromised endpoint if possible; from Kali it still models the
# fan-out pattern. Uses sshpass if available; otherwise prints the commands.
set -u; cd "$(dirname "$0")"; source ./targets.sh
banner "SCENARIO 3: LATERAL MOVEMENT (SSH fan-out)"
HOSTS=("$ENDPOINT1" "$ENDPOINT2" "$WAZUH_SERVER")
USER="${LAT_USER:-endpoint}"; PASS="${LAT_PASS:-endpoint123}"
for h in "${HOSTS[@]}"; do
  echo "[*] $(stamp)  SSH -> $h as $USER"
  if command -v sshpass >/dev/null; then
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      "$USER@$h" "hostname; id" 2>&1 | tail -2
  else
    echo "    (install sshpass, or run manually): ssh $USER@$h"
  fi
  sleep 2
done
echo "END: $(stamp)"
