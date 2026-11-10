#!/usr/bin/env python3
"""
train_benchmark_cicids.py  --  CICIDS2017 counterpart to train_benchmark.py.

This is the SECOND offline benchmark named in the proposal. It is deliberately a
STANDALONE benchmark, not a merge with NSL-KDD: NSL-KDD has 41 KDD-derived features
and CICIDS2017 has ~78 CICFlowMeter flow features, so they share no common feature
space and "combining" them is not defensible. The honest, standard approach — and
what Chapter 5 reports — is each dataset evaluated independently, side by side.

Mirrors train_benchmark.py:
  * Random Forest     (supervised, multi-class)  -- accuracy on a matched 80/20 split
  * Isolation Forest  (unsupervised)             -- trained on BENIGN only, scored
                                                    as benign-vs-attack

Why CICIDS2017 matters here: Random Forest on CICIDS2017 typically lands ~99%, which
is the evidence that carries the >=85% detection-accuracy requirement that NSL-KDD's
official KDDTest+ (73.79%) does not. CICIDS2017 also covers attack types closer to
this project's seven live categories: FTP/SSH-Patator -> Brute Force, PortScan ->
Port Scanning, Bot -> C2 Beaconing, DDoS/DoS* -> volumetric, Infiltration/Web attacks.

Run:
  python3 train_benchmark_cicids.py                 # default dir: data/cicids2017/
  python3 train_benchmark_cicids.py --data /path/to/cicids_csvs
  python3 train_benchmark_cicids.py --max-rows 0    # use ALL rows (needs more RAM)

Outputs: models/benchmark_cicids_*.joblib  and  ../evidence/benchmark_cicids_*.txt/.csv/.json
"""
import os
import glob
import json
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA = os.path.join(HERE, "data", "cicids2017")
MODELS = os.path.join(HERE, "models")
EVID = os.path.abspath(os.path.join(HERE, "..", "evidence"))
os.makedirs(MODELS, exist_ok=True)
os.makedirs(EVID, exist_ok=True)

# CICIDS2017 ships many fine-grained labels. Group them into coarse families so the
# multi-class problem is stable and the report is readable. Matching is done on a
# normalised (stripped, lower-cased) label, and 'web attack' is matched as a prefix
# because the raw files use an odd dash byte in "Web Attack - Brute Force" etc.
def family_of(raw_label):
    s = str(raw_label).strip().lower().replace("\x96", "-").replace("–", "-")
    if s in ("benign", "normal"):
        return "BENIGN"
    if s.startswith("web attack"):
        return "Web Attack"
    if s in ("ftp-patator", "ssh-patator"):
        return "Brute Force"
    if s == "portscan":
        return "PortScan"
    if s == "ddos":
        return "DDoS"
    if s.startswith("dos"):
        return "DoS"
    if s == "bot":
        return "Bot"
    if s == "infiltration":
        return "Infiltration"
    if s == "heartbleed":
        return "Heartbleed"
    return s  # anything unexpected is kept verbatim so it is visible, not hidden


def tee(fh, *args):
    line = " ".join(str(a) for a in args)
    print(line)
    fh.write(line + "\n")


def load_all(data_dir, report, per_file_frac=None):
    files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not files:
        raise SystemExit(
            f"No CSVs found in {data_dir}\n"
            f"  Put the CICIDS2017 MachineLearningCSV files there, or pass --data <dir>."
        )
    tee(report, f"Found {len(files)} CSV file(s):")
    if per_file_frac:
        tee(report, f"Random-sampling {per_file_frac:.0%} of each file at read time "
                    f"(memory-safe mode).")
    frames = []
    for fp in files:
        # engine='python' + on_bad_lines tolerates the occasional malformed row.
        df = pd.read_csv(fp, low_memory=False, skipinitialspace=True,
                         encoding="latin-1", on_bad_lines="skip")
        df.columns = [c.strip() for c in df.columns]
        n = len(df)
        # Sample EACH file before concat so the full 2.8M-row frame never has to
        # live in RAM at once. Random sampling keeps each file's label mix.
        if per_file_frac and 0 < per_file_frac < 1:
            df = df.sample(frac=per_file_frac, random_state=42)
        # Downcast numeric columns to float32 now to roughly halve memory.
        for c in df.columns:
            if df[c].dtype == "float64":
                df[c] = df[c].astype("float32")
        tee(report, f"  {os.path.basename(fp):60s} {n:>9d} rows"
                    + (f" -> kept {len(df)}" if per_file_frac else ""))
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    del frames
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA, help="dir of CICIDS2017 CSVs")
    ap.add_argument("--max-rows", type=int, default=500000,
                    help="stratified row cap to fit in RAM (0 = use all rows)")
    ap.add_argument("--per-file-frac", type=float, default=None,
                    help="randomly sample this fraction of EACH file at read time, "
                         "before concat (e.g. 0.2). Use on low-RAM VMs to avoid "
                         "swap-thrashing the full 2.8M-row load.")
    args = ap.parse_args()

    report = open(os.path.join(EVID, "benchmark_cicids_results.txt"), "w")
    tee(report, "CICIDS2017 benchmark - Random Forest + Isolation Forest")
    tee(report, "=" * 60)

    df = load_all(args.data, report, per_file_frac=args.per_file_frac)

    # --- find the label column (CICIDS2017 calls it 'Label') ---
    label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
    if label_col is None:
        raise SystemExit(f"No 'Label' column found. Columns seen: {list(df.columns)[:10]} ...")

    # --- clean: drop obvious identifier/time columns, coerce features numeric ---
    drop_like = ("flow id", "source ip", "src ip", "destination ip", "dst ip",
                 "timestamp", "source port", "fwd header length.1")
    id_cols = [c for c in df.columns if c.strip().lower() in drop_like]
    if id_cols:
        tee(report, f"Dropping non-feature columns: {id_cols}")
        df.drop(columns=id_cols, inplace=True)

    df["family"] = df[label_col].map(family_of)
    df.drop(columns=[label_col], inplace=True)

    feature_cols = [c for c in df.columns if c != "family"]
    # Coerce every feature to numeric; CICIDS2017 has Infinity and blank cells.
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(X)
    good = X.notna().all(axis=1)
    X = X[good].astype(np.float32)
    y = df.loc[good, "family"].values
    tee(report, f"Rows after cleaning: {len(X)} (dropped {before - len(X)} with inf/NaN)")
    tee(report, f"Family distribution: {pd.Series(y).value_counts().to_dict()}")

    # Drop ultra-rare classes (<10 rows) that break a stratified split.
    vc = pd.Series(y).value_counts()
    keep = set(vc[vc >= 10].index)
    mask = np.array([lab in keep for lab in y])
    # X is a DataFrame: boolean-select rows by position, then reset the index so
    # the later numpy conversions line up. (y is already a numpy array.)
    X, y = X[mask].reset_index(drop=True), y[mask]
    if set(keep) != set(vc.index):
        tee(report, f"Dropped rare classes (<10 rows): {sorted(set(vc.index) - keep)}")

    # --- optional stratified subsample so it fits the lab VM's RAM ---
    if args.max_rows and len(X) > args.max_rows:
        Xs, _, ys, _ = train_test_split(
            X, y, train_size=args.max_rows, random_state=42, stratify=y)
        X, y = Xs, ys
        tee(report, f"Stratified subsample to {len(X)} rows (--max-rows {args.max_rows}).")
    else:
        tee(report, f"Using all {len(X)} rows.")

    scaler = StandardScaler()
    Xsc = scaler.fit_transform(X)

    # ============ 1. Random Forest - matched 80/20 split ============
    tee(report, "\n[1] Random Forest - matched 80/20 split")
    tee(report, "-" * 60)
    Xtr, Xte, ytr, yte = train_test_split(
        Xsc, y, test_size=0.20, random_state=42, stratify=y)
    rf = RandomForestClassifier(n_estimators=200, max_depth=None,
                                random_state=42, n_jobs=-1, class_weight="balanced")
    rf.fit(Xtr, ytr)
    pred = rf.predict(Xte)
    acc_rf = accuracy_score(yte, pred)
    tee(report, f"Accuracy (matched split): {acc_rf*100:.2f}%")
    tee(report, classification_report(yte, pred, zero_division=0))

    labels_sorted = sorted(set(yte) | set(pred))
    cm = confusion_matrix(yte, pred, labels=labels_sorted)
    pd.DataFrame(cm, index=labels_sorted, columns=labels_sorted).to_csv(
        os.path.join(EVID, "benchmark_cicids_rf_confusion.csv"))
    tee(report, "Confusion matrix saved -> evidence/benchmark_cicids_rf_confusion.csv")

    # ============ 2. Isolation Forest - BENIGN only, benign vs attack ============
    tee(report, "\n[2] Isolation Forest - trained on BENIGN rows only")
    tee(report, "-" * 60)
    Xnorm = Xsc[y == "BENIGN"]
    iso = IsolationForest(n_estimators=200, contamination=0.1,
                          random_state=42, n_jobs=-1)
    iso.fit(Xnorm)
    iso_pred = np.where(iso.predict(Xsc) == -1, "attack", "normal")
    iso_true = np.where(y == "BENIGN", "normal", "attack")
    acc_iso = accuracy_score(iso_true, iso_pred)
    tee(report, f"Accuracy (normal vs attack): {acc_iso*100:.2f}%")
    tee(report, classification_report(iso_true, iso_pred, zero_division=0))

    # --- persist models + preprocessing ---
    joblib.dump(rf, os.path.join(MODELS, "benchmark_cicids_rf.joblib"))
    joblib.dump(iso, os.path.join(MODELS, "benchmark_cicids_iso.joblib"))
    joblib.dump(scaler, os.path.join(MODELS, "benchmark_cicids_scaler.joblib"))
    joblib.dump(feature_cols, os.path.join(MODELS, "benchmark_cicids_feature_cols.joblib"))

    summary = {
        "rf_accuracy_matched_split": round(acc_rf * 100, 2),
        "iso_accuracy_benign_vs_attack": round(acc_iso * 100, 2),
        "dataset": "CICIDS2017 (MachineLearningCSV)",
        "rows_used": int(len(X)),
        "classes": labels_sorted,
    }
    with open(os.path.join(EVID, "benchmark_cicids_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    tee(report, "\nSummary: " + json.dumps(summary))
    report.close()
    print("\nDone. Evidence written to evidence/benchmark_cicids_*.")


if __name__ == "__main__":
    main()
