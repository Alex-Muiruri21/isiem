#!/usr/bin/env bash
# Scenario 4 - Privilege escalation via a known sudo misconfiguration on Endpoint-1.
# The Metasploit path is given for the report; a direct check is included so the
# scenario produces an auth/sudo event even without MSF set up.
# Expect ISIEM: "Privilege Escalation" (or high-level auth) + possible anomaly.
set -u; cd "$(dirname "$0")"; source ./targets.sh
banner "SCENARIO 4: PRIVILEGE ESCALATION"
cat <<'MSF'
[*] Metasploit route (run in msfconsole on Kali):
      use exploit/linux/local/sudo_baron_samedit   # or the lab's seeded misconfig
      set SESSION <meterpreter session on Endpoint-1>
      run
[*] Direct route (on Endpoint-1 after a foothold): attempt sudo to root
      sudo -n true 2>&1 ; sudo -l
MSF
echo "[*] $(stamp)  Simulating repeated sudo attempts via SSH to generate events"
if command -v sshpass >/dev/null; then
  for i in 1 2 3; do
    sshpass -p "${LAT_PASS:-endpoint123}" ssh -o StrictHostKeyChecking=no \
      "${LAT_USER:-endpoint}@$ENDPOINT1" "sudo -n id 2>&1 | head -1" 2>&1 | tail -1
  done
fi
echo "END: $(stamp)"
