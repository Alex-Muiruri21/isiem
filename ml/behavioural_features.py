#!/usr/bin/env python3
"""
behavioural_features.py  --  Turn a stream of Wazuh alerts into per-source-IP
behavioural feature vectors.

This is the "behavioural analytics" layer named in the project title. Where the
benchmark models score individual NSL-KDD rows, the live system reasons about an
*actor* (a source IP) over a short time window, counting the kinds of behaviour
that distinguish the seven target attack categories from normal use.

It is deliberately dependency-light (standard library only) so the exact same code
runs on the Wazuh server VM and in the offline tests here, and so it is easy for a
reader to follow. The scikit-learn models consume the numeric vector this produces.

Feature vector (per source IP, within the window), FEATURE_NAMES below:
  failed_logins          auth failures (Wazuh rule groups: authentication_failed)
  successful_logins      auth successes (authentication_success)
  distinct_users         how many usernames were tried
  distinct_dst_hosts     how many internal hosts this IP touched
  distinct_dst_ports     how many ports this IP touched
  honeypot_hits          events coming from the Cowrie honeypot agent
  cowrie_commands        commands run inside the honeypot session
  conn_events            total network-connection events
  off_hours              1 if activity falls outside 08:00-18:00, else 0
  new_source             1 if this IP has not been seen before this window
  max_rule_level         highest Wazuh rule level seen from this IP
  event_count            total events from this IP in the window
"""
import json
from collections import defaultdict
from datetime import datetime

FEATURE_NAMES = [
    "failed_logins", "successful_logins", "distinct_users", "distinct_dst_hosts",
    "distinct_dst_ports", "honeypot_hits", "cowrie_commands", "conn_events",
    "off_hours", "new_source", "max_rule_level", "event_count",
]

# Wazuh rule groups we key off. Kept as substrings so minor group-name changes
# across Wazuh versions still match.
GRP_AUTH_FAIL = ("authentication_failed", "invalid_login", "authentication_failures")
GRP_AUTH_OK = ("authentication_success",)
GRP_CONN = ("firewall", "connection", "netinfo")


def _parse_ts(alert):
    """Return a datetime from a Wazuh alert, or None."""
    ts = alert.get("timestamp") or alert.get("predecoder", {}).get("timestamp")
    if not ts:
        return None
    # Wazuh uses e.g. 2026-10-16T14:03:11.123+0000
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def source_ip(alert):
    """Best-effort extraction of the actor IP from a Wazuh alert."""
    # Only the attacker-side fields. Never fall back to the agent's own IP: that
    # would make a monitored endpoint look like an attacker (and get it blocked).
    data = alert.get("data", {}) or {}
    return data.get("srcip") or data.get("src_ip") or data.get("source_ip")


class BehaviourAggregator:
    """Accumulates alerts into per-IP behaviour. Call add() per alert, then
    features_for() / all_features(). `known_ips` lets the caller persist which
    IPs have been seen across windows so the new_source flag is meaningful."""

    def __init__(self, known_ips=None, business_start=8, business_end=18):
        self.known_ips = set(known_ips or [])
        self.business_start = business_start
        self.business_end = business_end
        self._acc = defaultdict(lambda: {
            "failed_logins": 0, "successful_logins": 0, "users": set(),
            "dst_hosts": set(), "dst_ports": set(), "honeypot_hits": 0,
            "cowrie_commands": 0, "conn_events": 0, "off_hours": 0,
            "max_rule_level": 0, "event_count": 0, "seen_now": set(),
        })

    def add(self, alert):
        data0 = alert.get("data", {}) or {}
        # Skip the engine's own verdicts when Wazuh re-ingests them into
        # alerts.json, otherwise each verdict would feed back into the features.
        if data0.get("integration") == "isiem-ml":
            return
        ip = source_ip(alert)
        if not ip:
            return
        a = self._acc[ip]
        data = alert.get("data", {})
        rule = alert.get("rule", {})
        groups = [g.lower() for g in rule.get("groups", [])]
        agent_name = (alert.get("agent", {}).get("name") or "").lower()
        level = int(rule.get("level", 0) or 0)

        a["event_count"] += 1
        a["max_rule_level"] = max(a["max_rule_level"], level)

        if any(any(k in g for k in GRP_AUTH_FAIL) for g in groups):
            a["failed_logins"] += 1
        if any(any(k in g for k in GRP_AUTH_OK) for g in groups):
            a["successful_logins"] += 1
        if any(any(k in g for k in GRP_CONN) for g in groups):
            a["conn_events"] += 1

        user = data.get("srcuser") or data.get("dstuser") or data.get("user")
        if user:
            a["users"].add(str(user))
        dstip = data.get("dstip") or data.get("dst_ip")
        if dstip:
            a["dst_hosts"].add(str(dstip))
        dport = data.get("dstport") or data.get("dst_port")
        if dport:
            a["dst_ports"].add(str(dport))

        # Cowrie honeypot events: the honeypot agent forwards Cowrie's JSON.
        if "cowrie" in agent_name or "honeypot" in agent_name or "cowrie" in " ".join(groups):
            a["honeypot_hits"] += 1
            eventid = str(data.get("eventid", ""))
            if "command" in eventid:
                a["cowrie_commands"] += 1

        ts = _parse_ts(alert)
        if ts is not None:
            if not (self.business_start <= ts.hour < self.business_end):
                a["off_hours"] = 1

    def features_for(self, ip):
        a = self._acc[ip]
        return [
            a["failed_logins"], a["successful_logins"], len(a["users"]),
            len(a["dst_hosts"]), len(a["dst_ports"]), a["honeypot_hits"],
            a["cowrie_commands"], a["conn_events"], a["off_hours"],
            0 if ip in self.known_ips else 1, a["max_rule_level"], a["event_count"],
        ]

    def all_features(self):
        """Yield (ip, feature_dict, feature_vector) for every IP seen."""
        for ip in self._acc:
            vec = self.features_for(ip)
            yield ip, dict(zip(FEATURE_NAMES, vec)), vec


if __name__ == "__main__":
    # tiny smoke test
    agg = BehaviourAggregator()
    sample = {"timestamp": "2026-10-16T23:10:00.0+0000",
              "agent": {"name": "endpoint-1", "ip": "192.168.242.132"},
              "rule": {"level": 5, "groups": ["authentication_failed"]},
              "data": {"srcip": "192.168.242.140", "srcuser": "root", "dstport": "22"}}
    for _ in range(12):
        agg.add(sample)
    for ip, feats, vec in agg.all_features():
        print(ip, feats)
