#!/usr/bin/env python3
"""
classifier.py  --  Map a behavioural feature vector to one of the seven target
attack categories, with a severity.

Two layers, matching the project design:

  * Supervised layer -- a Random Forest. If a model trained on labelled lab
    behaviour exists (models/live_rf.joblib, produced by train_live.py after the
    Phase-4 attack runs), it is used. Until that data exists, a transparent
    signature classifier stands in. Each signature is drawn directly from the
    attack descriptions in Chapter 2 (section 2.3), so it is defensible and
    explainable rather than a black box.

  * Unsupervised layer -- an Isolation Forest (models/live_iso.joblib) that scores
    how far an actor's behaviour sits from the learned normal baseline. This
    catches novel or slow activity the signatures do not name, and is what lets
    the system claim detection of previously unseen threats.

The two combine: the supervised layer names the category; the anomaly layer can
raise severity or flag "Anomalous (uncategorised)" when the signatures stay quiet
but behaviour is clearly abnormal.
"""
import os
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "models")

CATEGORIES = [
    "Honeypot Interaction",
    "Brute Force / Credential Stuffing",
    "Port Scanning / Reconnaissance",
    "Lateral Movement",
    "Privilege Escalation",
    "Data Exfiltration",
    "Command and Control Beaconing",
    "Suspicious Authentication",
    "Normal",
]

# Severity assigned per category when fired (Wazuh-style 0-15 scale).
SEVERITY = {
    "Honeypot Interaction": 12,
    "Brute Force / Credential Stuffing": 10,
    "Port Scanning / Reconnaissance": 7,
    "Lateral Movement": 12,
    "Privilege Escalation": 13,
    "Data Exfiltration": 12,
    "Command and Control Beaconing": 11,
    "Suspicious Authentication": 8,
    "Normal": 0,
}


def signature_classify(f):
    """Transparent rule set over the feature dict `f`. Returns a category string.
    Order matters: the most specific / highest-harm signatures are tested first."""
    # Honeypot interaction: any contact with the Cowrie decoy is unauthorised by
    # definition (zero false positives), so it is the first and strongest signal.
    if f["honeypot_hits"] >= 1:
        return "Honeypot Interaction"

    # Port scan: one source touching many ports (and often many hosts) quickly,
    # with no successful authentication (a scan probes, it does not log in).
    if f["successful_logins"] == 0 and (
            f["distinct_dst_ports"] >= 10
            or (f["distinct_dst_hosts"] >= 5 and f["failed_logins"] == 0)):
        return "Port Scanning / Reconnaissance"

    # Brute force / credential stuffing: a burst of failed logins. Many distinct
    # usernames tilts it toward credential stuffing, but both map here.
    if f["failed_logins"] >= 8:
        return "Brute Force / Credential Stuffing"

    # Lateral movement: successful auth fanning out to several internal hosts,
    # which a normal user session does not do.
    if f["successful_logins"] >= 1 and f["distinct_dst_hosts"] >= 3:
        return "Lateral Movement"

    # C2 beaconing: repeated connection events to a small, fixed target set.
    # (Interval regularity is confirmed by the engine's timing check.)
    if f["conn_events"] >= 15 and f["distinct_dst_hosts"] <= 2 \
            and f["failed_logins"] == 0:
        return "Command and Control Beaconing"

    # Data exfiltration: sustained outbound connection volume to few hosts.
    if f["conn_events"] >= 25 and f["distinct_dst_hosts"] <= 3:
        return "Data Exfiltration"

    # Suspicious authentication: a successful login that is off-hours or from a
    # never-before-seen source IP -- individually quiet, behaviourally odd.
    if f["successful_logins"] >= 1 and (f["off_hours"] == 1 or f["new_source"] == 1):
        return "Suspicious Authentication"

    # Privilege escalation surfaces mainly through high-level host rules.
    if f["max_rule_level"] >= 12 and f["successful_logins"] >= 1:
        return "Privilege Escalation"

    return "Normal"


class LiveClassifier:
    def __init__(self):
        self.rf = self._load("live_rf.joblib")
        self.iso = self._load("live_iso.joblib")
        self.iso_scaler = self._load("live_scaler.joblib")
        self.feature_order = self._load("live_feature_cols.joblib")

    @staticmethod
    def _load(name):
        p = os.path.join(MODELS, name)
        return joblib.load(p) if os.path.exists(p) else None

    def anomaly(self, vec):
        """Return (is_anomaly, score) from the Isolation Forest, or (False, 0.0)
        if the model has not been trained yet."""
        if self.iso is None:
            return False, 0.0
        X = [vec]
        if self.iso_scaler is not None:
            X = self.iso_scaler.transform(X)
        pred = self.iso.predict(X)[0]
        score = float(self.iso.score_samples(X)[0])
        return (pred == -1), score

    def classify(self, feat_dict, vec):
        """Return a verdict dict: category, severity, source (model vs signature),
        and anomaly info."""
        if self.rf is not None and self.feature_order is not None:
            ordered = [feat_dict[k] for k in self.feature_order]
            category = str(self.rf.predict([ordered])[0])
            source = "random_forest"
        else:
            category = signature_classify(feat_dict)
            source = "signature"

        is_anom, score = self.anomaly(vec)
        severity = SEVERITY.get(category, 0)

        # Anomaly layer escalates: if signatures say Normal but behaviour is a
        # clear outlier, raise it so a novel threat is not silently dropped.
        if category == "Normal" and is_anom:
            category = "Anomalous (uncategorised)"
            severity = 9
        elif is_anom and severity < 12:
            severity += 1  # corroborating anomaly nudges confidence up

        return {
            "category": category,
            "severity": severity,
            "classifier": source,
            "anomaly": is_anom,
            "anomaly_score": round(score, 4),
        }


if __name__ == "__main__":
    c = LiveClassifier()
    tests = [
        {"failed_logins": 12, "successful_logins": 0, "distinct_users": 3,
         "distinct_dst_hosts": 0, "distinct_dst_ports": 1, "honeypot_hits": 0,
         "cowrie_commands": 0, "conn_events": 0, "off_hours": 1, "new_source": 1,
         "max_rule_level": 5, "event_count": 12},
        {"failed_logins": 0, "successful_logins": 0, "distinct_users": 0,
         "distinct_dst_hosts": 8, "distinct_dst_ports": 40, "honeypot_hits": 0,
         "cowrie_commands": 0, "conn_events": 40, "off_hours": 0, "new_source": 1,
         "max_rule_level": 6, "event_count": 48},
        {"failed_logins": 0, "successful_logins": 4, "distinct_users": 1,
         "distinct_dst_hosts": 5, "distinct_dst_ports": 1, "honeypot_hits": 0,
         "cowrie_commands": 0, "conn_events": 6, "off_hours": 1, "new_source": 0,
         "max_rule_level": 5, "event_count": 10},
    ]
    for t in tests:
        vec = [t[k] for k in __import__("behavioural_features").FEATURE_NAMES]
        print(c.classify(t, vec))
