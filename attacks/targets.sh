#!/usr/bin/env bash
# Shared lab target configuration for the attack scenarios.
# EDIT these to match the running lab (the IPs below are the NAT addresses from the
# original build; confirm with `ip a` on each VM before a run).
#
# These scripts attack ONLY the lab VMs listed here, from Kali, as the FYP's
# authorised Section 3.5.3 validation. Do not point them at anything else.

export WAZUH_SERVER="192.168.242.130"
export ENDPOINT1="192.168.242.132"
export ENDPOINT2="192.168.242.133"
export HONEYPOT="192.168.242.135"

# A small wordlist is generated if rockyou is not unpacked, to keep runs quick.
export SSH_USER="root"
export WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"

stamp() { date '+%Y-%m-%d %H:%M:%S.%3N'; }

banner() {
  echo "============================================================"
  echo " $1"
  echo " START: $(stamp)   (record this as the attack start time)"
  echo "============================================================"
}
