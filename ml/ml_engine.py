#!/usr/bin/env python3
"""
ml_engine.py  --  Live behavioural detection engine for the Integrated SIEM.

Runs on the Wazuh server. It follows Wazuh's own alert log in real time, groups
recent alerts by source IP inside a sliding time window, scores each actor with the
behavioural classifier (Random Forest / signatures + Isolation Forest), and when an
actor is judged a threat it:

  1. writes a structured verdict to  VERDICT_LOG  (a Wazuh <localfile> re-ingests
     this, so the ML verdict appears on the Wazuh Dashboard with its own rule); and
  2. records detection timing so Mean-Time-To-Detect can be reported.

The actual containment (block IP / lock account / email) is done by Wazuh Active
Response on the attacked endpoint, triggered by the rule that fires on the verdict.
Keeping containment in Wazuh means it runs on the right host and is auditable — see
wazuh/ and response/.

This design fixes the three faults of the earlier engine: it reads the real alert
stream instead of a non-existent API endpoint; it builds features that actually
exist in Wazuh alerts; and it never blocks from the wrong host.

Usage:
  python3 ml_engine.py                       # live: follow ALERTS_PATH
  python3 ml_engine.py --replay sample.json  # offline: feed a JSON-lines file
  python3 ml_engine.py --once                # one pass over existing alerts, exit
"""
import argparse
import json
import os
import sys
import time
from collections import deque
from datetime import datetime

from behavioural_features import BehaviourAggregator, source_ip, _parse_ts
from classifier import LiveClassifier

ALERTS_PATH = os.environ.get("ISIEM_ALERTS", "/var/ossec/logs/alerts/alerts.json")
VERDICT_LOG = os.environ.get("ISIEM_VERDICT_LOG", "/var/log/isiem/ml_verdicts.json")
WINDOW_SECONDS = 60          # sliding window width
EVAL_EVERY = 5               # seconds between evaluations
KNOWN_IPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "models", "known_ips.json")
BEACON_MIN_EVENTS = 4        # events needed before a beacon-interval check
BEACON_JITTER = 0.25         # max relative deviation of intervals to call it regular


def load_known_ips():
    try:
        with open(KNOWN_IPS_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()


def save_known_ips(ips):
    try:
        os.makedirs(os.path.dirname(KNOWN_IPS_FILE), exist_ok=True)
        with open(KNOWN_IPS_FILE, "w") as f:
            json.dump(sorted(ips), f)
    except Exception as e:
        print(f"[warn] could not persist known IPs: {e}", file=sys.stderr)


def is_regular_beacon(timestamps):
    """True if the connection timestamps are evenly spaced (fixed-interval C2)."""
    ts = sorted(t for t in timestamps if t is not None)
    if len(ts) < BEACON_MIN_EVENTS:
        return False
    gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < BEACON_MIN_EVENTS - 1:
        return False
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return False
    spread = max(abs(g - mean) for g in gaps) / mean
    return spread <= BEACON_JITTER


def emit_verdict(verdict):
    """Append the verdict as one JSON line for Wazuh to re-ingest, and print it."""
    try:
        os.makedirs(os.path.dirname(VERDICT_LOG), exist_ok=True)
        with open(VERDICT_LOG, "a") as f:
            f.write(json.dumps(verdict) + "\n")
    except Exception as e:
        print(f"[warn] could not write verdict log: {e}", file=sys.stderr)
    tag = "THREAT" if verdict["severity"] >= 10 else "SUSPICIOUS"
    print(f"[{verdict['detected_at']}] {tag}: {verdict['src_ip']} -> "
          f"{verdict['category']} (sev {verdict['severity']}, "
          f"{verdict['classifier']}, anomaly={verdict['anomaly']})")


def evaluate(window, known_ips, clf, emitted):
    """Run the classifier over the current window and emit new verdicts.
    `emitted` maps src_ip -> last category, to avoid re-alerting every cycle."""
    agg = BehaviourAggregator(known_ips=known_ips)
    beacon_ts = {}
    for alert in window:
        agg.add(alert)
        ip = source_ip(alert)
        if ip:
            beacon_ts.setdefault(ip, []).append(_parse_ts(alert))

    for ip, feats, vec in agg.all_features():
        verdict = clf.classify(feats, vec)
        category = verdict["category"]

        # Timing-based C2 confirmation overrides a quiet verdict.
        if category in ("Normal", "Anomalous (uncategorised)") and \
                is_regular_beacon(beacon_ts.get(ip, [])):
            category = "Command and Control Beaconing"
            verdict["category"] = category
            verdict["severity"] = max(verdict["severity"], 11)
            verdict["classifier"] += "+beacon_timing"

        if category == "Normal":
            continue
        if emitted.get(ip) == category:
            continue  # already reported this behaviour for this IP
        emitted[ip] = category

        verdict.update({
            "src_ip": ip,
            "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": feats,
            "integration": "isiem-ml",
        })
        emit_verdict(verdict)


def follow(path):
    """Generator yielding new lines appended to `path`, like `tail -f`."""
    while not os.path.exists(path):
        print(f"[info] waiting for {path} ...")
        time.sleep(2)
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line


def parse_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def run_live(path, once=False):
    known = load_known_ips()
    clf = LiveClassifier()
    window = deque()
    emitted = {}
    last_eval = time.time()

    def within_window(alert):
        ts = _parse_ts(alert)
        if ts is None:
            return True
        age = (datetime.now(ts.tzinfo) - ts).total_seconds()
        return age <= WINDOW_SECONDS

    if once:
        # one pass over whatever is already in the file
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    a = parse_line(line)
                    if a:
                        window.append(a)
        evaluate(list(window), known, clf, emitted)
        for a in window:
            ip = source_ip(a)
            if ip:
                known.add(ip)
        save_known_ips(known)
        return

    print(f"[info] ISIEM ML engine following {path} "
          f"(window {WINDOW_SECONDS}s, eval every {EVAL_EVERY}s)")
    for line in follow(path):
        a = parse_line(line)
        if a:
            window.append(a)
        now = time.time()
        if now - last_eval >= EVAL_EVERY:
            while window and not within_window(window[0]):
                old = window.popleft()
                ip = source_ip(old)
                if ip:
                    known.add(ip)        # IP seen -> no longer "new" next time
            evaluate(list(window), known, clf, emitted)
            save_known_ips(known)
            last_eval = now


def run_replay(path):
    """Feed a JSON-lines file as if it were the live stream, evaluate once."""
    known = load_known_ips()
    clf = LiveClassifier()
    window = []
    with open(path) as f:
        for line in f:
            a = parse_line(line)
            if a:
                window.append(a)
    print(f"[info] replaying {len(window)} alerts from {path}")
    evaluate(window, known, clf, {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay", metavar="FILE",
                    help="offline: evaluate a JSON-lines alert file and exit")
    ap.add_argument("--once", action="store_true",
                    help="one pass over existing ALERTS_PATH, then exit")
    ap.add_argument("--path", default=ALERTS_PATH, help="alerts.json path")
    args = ap.parse_args()
    if args.replay:
        run_replay(args.replay)
    else:
        run_live(args.path, once=args.once)


if __name__ == "__main__":
    main()
