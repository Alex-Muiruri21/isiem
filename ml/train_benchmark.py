#!/usr/bin/env python3
"""
train_benchmark.py  --  Offline benchmark models for the FYP (Chapter 5 evidence).

Trains the two models named in the report on the NSL-KDD benchmark dataset:
  * Random Forest     (supervised)    -- classifies traffic by attack family
  * Isolation Forest  (unsupervised)  -- flags anomalies, trained on normal only

These are the BENCHMARK models: they prove, on a public labelled dataset, that the
chosen algorithms detect intrusions well. They are separate from the LIVE engine
(ml_engine.py) that scores behavioural features from the running lab.

Two evaluations are produced for the Random Forest, and the difference between them
is itself a finding worth discussing in the report:

  1. MATCHED split   -- stratified 80/20 split of KDDTrain+. Train and test come from
                        the same distribution. This is the "model quality" number.
  2. KDDTest+        -- the official NSL-KDD test set, which deliberately contains
                        attack variants absent from training. This is the tougher
                        "generalisation to novel attacks" number, and is lower by
                        design of the dataset (Tavallaee et al., 2009).

Run:  python3 train_benchmark.py
Outputs: models/*.joblib  and  ../evidence/benchmark_*.txt / *.csv
"""
import os
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support)
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(HERE, "models")
EVID = os.path.abspath(os.path.join(HERE, "..", "evidence"))
os.makedirs(MODELS, exist_ok=True)
os.makedirs(EVID, exist_ok=True)

COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# NSL-KDD maps each specific attack to one of four families; 'normal' is its own class.
# This 5-class scheme is the standard academic grouping (DoS, Probe, R2L, U2R).
ATTACK_FAMILY = {
    'normal': 'normal',
    # DoS
    'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS',
    'udpstorm': 'DoS', 'worm': 'DoS',
    # Probe
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L (remote to local)
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    # U2R (user to root)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
}


def load(path):
    df = pd.read_csv(path, names=COLUMNS)
    df.drop('difficulty', axis=1, inplace=True)
    df['family'] = df['label'].map(lambda x: ATTACK_FAMILY.get(x, 'unknown'))
    return df


def tee(fh, *args):
    line = " ".join(str(a) for a in args)
    print(line)
    fh.write(line + "\n")


def main():
    report = open(os.path.join(EVID, "benchmark_results.txt"), "w")
    tee(report, "NSL-KDD benchmark — Random Forest + Isolation Forest")
    tee(report, "=" * 60)

    train = load(os.path.join(DATA, "KDDTrain+.txt"))
    test = load(os.path.join(DATA, "KDDTest+.txt"))
    tee(report, f"Loaded: {len(train)} train rows, {len(test)} official test rows")
    tee(report, f"Train families: {train['family'].value_counts().to_dict()}")

    # --- encode categoricals, fitting on train+test together so labels line up ---
    cat_cols = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        le.fit(pd.concat([train[col], test[col]]).astype(str))
        train[col] = le.transform(train[col].astype(str))
        test[col] = le.transform(test[col].astype(str))
        encoders[col] = le

    feature_cols = [c for c in train.columns if c not in ('label', 'family')]
    scaler = StandardScaler()
    Xtr_all = scaler.fit_transform(train[feature_cols].values)
    ytr_all = train['family'].values
    Xte_off = scaler.transform(test[feature_cols].values)
    yte_off = test['family'].values

    # ============ 1. MATCHED split (model-quality number) ============
    tee(report, "\n[1] Random Forest — matched 80/20 split of KDDTrain+")
    tee(report, "-" * 60)
    Xtr, Xval, ytr, yval = train_test_split(
        Xtr_all, ytr_all, test_size=0.20, random_state=42, stratify=ytr_all)
    rf = RandomForestClassifier(n_estimators=200, max_depth=None,
                                random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(Xtr, ytr)
    pred = rf.predict(Xval)
    acc_matched = accuracy_score(yval, pred)
    tee(report, f"Accuracy (matched split): {acc_matched*100:.2f}%")
    tee(report, classification_report(yval, pred, zero_division=0))

    # ============ 2. Official KDDTest+ (generalisation number) ============
    tee(report, "\n[2] Random Forest — official KDDTest+ (novel attacks present)")
    tee(report, "-" * 60)
    rf_full = RandomForestClassifier(n_estimators=200, max_depth=None,
                                     random_state=42, n_jobs=-1,
                                     class_weight='balanced')
    rf_full.fit(Xtr_all, ytr_all)
    pred_off = rf_full.predict(Xte_off)
    acc_off = accuracy_score(yte_off, pred_off)
    tee(report, f"Accuracy (official test set): {acc_off*100:.2f}%")
    tee(report, classification_report(yte_off, pred_off, zero_division=0))

    labels_sorted = sorted(set(yte_off) | set(pred_off))
    cm = confusion_matrix(yte_off, pred_off, labels=labels_sorted)
    pd.DataFrame(cm, index=labels_sorted, columns=labels_sorted).to_csv(
        os.path.join(EVID, "benchmark_rf_confusion.csv"))
    tee(report, f"Confusion matrix saved -> evidence/benchmark_rf_confusion.csv")

    # ============ 3. Isolation Forest (unsupervised) ============
    tee(report, "\n[3] Isolation Forest — trained on NORMAL rows only")
    tee(report, "-" * 60)
    Xnorm = Xtr_all[ytr_all == 'normal']
    iso = IsolationForest(n_estimators=200, contamination=0.1,
                          random_state=42, n_jobs=-1)
    iso.fit(Xnorm)
    # -1 = anomaly -> treat as attack; 1 = inlier -> normal
    iso_pred = np.where(iso.predict(Xte_off) == -1, 'attack', 'normal')
    iso_true = np.where(yte_off == 'normal', 'normal', 'attack')
    acc_iso = accuracy_score(iso_true, iso_pred)
    tee(report, f"Accuracy (normal vs attack on test set): {acc_iso*100:.2f}%")
    tee(report, classification_report(iso_true, iso_pred, zero_division=0))

    # --- persist models + preprocessing for reuse ---
    joblib.dump(rf_full, os.path.join(MODELS, "benchmark_rf.joblib"))
    joblib.dump(iso, os.path.join(MODELS, "benchmark_iso.joblib"))
    joblib.dump(scaler, os.path.join(MODELS, "benchmark_scaler.joblib"))
    joblib.dump(encoders, os.path.join(MODELS, "benchmark_encoders.joblib"))
    joblib.dump(feature_cols, os.path.join(MODELS, "benchmark_feature_cols.joblib"))

    summary = {
        "rf_accuracy_matched_split": round(acc_matched * 100, 2),
        "rf_accuracy_official_testset": round(acc_off * 100, 2),
        "iso_accuracy_official_testset": round(acc_iso * 100, 2),
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "classes": sorted(set(ytr_all)),
    }
    with open(os.path.join(EVID, "benchmark_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    tee(report, "\nSummary: " + json.dumps(summary))
    report.close()
    print("\nDone. Evidence written to evidence/benchmark_*.")


if __name__ == "__main__":
    main()
