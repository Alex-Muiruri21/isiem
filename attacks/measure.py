#!/usr/bin/env python3
"""
measure.py  --  Compute MTTD and MTTR for an attack run by correlating the ISIEM
logs, so Chapter 5's metrics table is filled from evidence rather than by eye.

  MTTD (Mean Time To Detect)  = first ML verdict time  -  attack start time
  MTTR (Mean Time To Respond) = first containment time -  attack start time

Run on the Wazuh server right after a scenario:
  python3 measure.py --start "2026-10-16 23:05:00" --ip 192.168.242.140 \
                     --scenario "SSH Brute Force"

Reads:
  /var/log/isiem/ml_verdicts.json        (detection, written by ml_engine.py)
  /var/ossec/logs/active-responses.log   (containment, written by block_ip.py)
Appends a row to evidence/metrics.csv and prints the result.
"""
import argparse
import json
import os
import re
from datetime import datetime, timedelta

VERDICTS = os.environ.get("ISIEM_VERDICT_LOG", "/var/log/isiem/ml_verdicts.json")
AR_LOG = os.environ.get("ISIEM_AR_LOG", "/var/ossec/logs/active-responses.log")
EVID = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence"))
FMT = "%Y-%m-%d %H:%M:%S"


def in_window(t, start, window):
    """Only count events from THIS run: at/after START and within `window` seconds.
    Without the upper bound, a scenario with no response of its own (e.g. a port
    scan) picked up the NEXT scenario's block and reported a bogus MTTR."""
    return start <= t <= start + timedelta(seconds=window)


def first_detection(ip, start, window):
    best = None
    if not os.path.exists(VERDICTS):
        return None
    with open(VERDICTS) as f:
        for line in f:
            try:
                v = json.loads(line)
            except json.JSONDecodeError:
                continue
            if v.get("src_ip") != ip:
                continue
            try:
                t = datetime.strptime(v["detected_at"], FMT)
            except (KeyError, ValueError):
                continue
            if in_window(t, start, window) and (best is None or t < best[0]):
                best = (t, v.get("category"))
    return best


def first_block(ip, start, window):
    if not os.path.exists(AR_LOG):
        return None
    best = None
    pat = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*BLOCKED\s+" + re.escape(ip))
    with open(AR_LOG) as f:
        for line in f:
            m = pat.search(line)
            if not m:
                continue
            t = datetime.strptime(m.group(1), FMT)
            if in_window(t, start, window) and (best is None or t < best):
                best = t
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help='attack start "YYYY-MM-DD HH:MM:SS"')
    ap.add_argument("--ip", required=True, help="attacker source IP")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--window", type=int, default=300,
                    help="only count detections/blocks within this many seconds "
                         "after START (default 300)")
    args = ap.parse_args()

    start = datetime.strptime(args.start, FMT)
    det = first_detection(args.ip, start, args.window)
    blk = first_block(args.ip, start, args.window)

    mttd = (det[0] - start).total_seconds() if det else None
    mttr = (blk - start).total_seconds() if blk else None

    print(f"Scenario : {args.scenario}")
    print(f"Attacker : {args.ip}")
    print(f"Start    : {args.start}")
    print(f"Detected : {det[0].strftime(FMT)+' ('+det[1]+')' if det else 'NOT DETECTED'}")
    print(f"Contained: {blk.strftime(FMT) if blk else 'NOT CONTAINED'}")
    print(f"MTTD     : {mttd:.1f}s" if mttd is not None else "MTTD     : n/a")
    print(f"MTTR     : {mttr:.1f}s" if mttr is not None else "MTTR     : n/a")
    print(f"Targets  : MTTD < 30s, MTTR < 60s")

    os.makedirs(EVID, exist_ok=True)
    csv = os.path.join(EVID, "metrics.csv")
    new = not os.path.exists(csv)
    with open(csv, "a") as f:
        if new:
            f.write("scenario,attacker_ip,start,detected,category,mttd_s,contained,mttr_s\n")
        f.write(f"{args.scenario},{args.ip},{args.start},"
                f"{det[0].strftime(FMT) if det else ''},{det[1] if det else ''},"
                f"{mttd if mttd is not None else ''},"
                f"{blk.strftime(FMT) if blk else ''},"
                f"{mttr if mttr is not None else ''}\n")
    print(f"\nAppended to {csv}")


if __name__ == "__main__":
    main()
