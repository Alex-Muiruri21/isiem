#!/usr/bin/env python3
"""Regression test: the engine must detect every target category from the sample
alert stream, and must NOT flag the normal actor. Run: python3 tests/test_detection.py
(exit 0 = pass). Also serves as reproducible Chapter 5 evidence."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ML = os.path.dirname(HERE)

EXPECT = {
    "192.168.242.140": "Brute Force / Credential Stuffing",
    "192.168.242.141": "Port Scanning / Reconnaissance",
    "192.168.242.142": "Lateral Movement",
    "192.168.242.143": "Honeypot Interaction",
    "192.168.242.144": "Command and Control Beaconing",
    "192.168.242.145": "Suspicious Authentication",
}
MUST_NOT_FLAG = "192.168.242.150"  # normal baseline traffic


def main():
    sample = os.path.join(HERE, "sample_alerts.json")
    vlog = os.path.join(HERE, "verdicts_test.json")
    if os.path.exists(vlog):
        os.remove(vlog)
    subprocess.run([sys.executable, "tests/make_sample_alerts.py", sample],
                   cwd=ML, check=True, stdout=subprocess.DEVNULL)
    env = dict(os.environ, ISIEM_VERDICT_LOG=vlog)
    subprocess.run([sys.executable, "ml_engine.py", "--replay", sample],
                   cwd=ML, check=True, env=env, stdout=subprocess.DEVNULL)

    got = {}
    with open(vlog) as f:
        for line in f:
            v = json.loads(line)
            got[v["src_ip"]] = v["category"]

    failures = []
    for ip, cat in EXPECT.items():
        if got.get(ip) != cat:
            failures.append(f"  {ip}: expected '{cat}', got '{got.get(ip)}'")
    if MUST_NOT_FLAG in got:
        failures.append(f"  {MUST_NOT_FLAG}: normal traffic was flagged as "
                        f"'{got[MUST_NOT_FLAG]}'")

    if failures:
        print("FAIL:")
        print("\n".join(failures))
        sys.exit(1)
    print(f"PASS: all {len(EXPECT)} categories detected, normal traffic not flagged")


if __name__ == "__main__":
    main()
