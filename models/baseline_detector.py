"""
Baseline anomaly scorer on top of the protocol-native feature frame.

Isolation Forest, not a time-series foundation model — this exists to
prove the parser -> features -> model pipeline works end-to-end on real
Modbus wire format before investing in fine-tuning a TSFM (Toto /
Chronos-2 / TTM) or netFound embeddings, which needs a real licensed
OT dataset (see TODO.md) rather than synthetic traffic.

Run:
    python models/baseline_detector.py
"""

from __future__ import annotations

import sys

import pandas as pd
from sklearn.ensemble import IsolationForest

sys.path.insert(0, ".")
from features.build_features import build_features  # noqa: E402
from parser.modbus_parser import parse_pcap  # noqa: E402

NUMERIC_FEATURES = [
    "function_code", "is_write", "is_novel_function_for_session",
    "is_novel_address_for_session", "inter_arrival_s", "inter_arrival_zscore",
    "events_in_1s_window", "write_value_zscore",
    "latency_s", "is_exception",
]


def score(feats: pd.DataFrame) -> pd.DataFrame:
    X = feats[NUMERIC_FEATURES].fillna(0)
    model = IsolationForest(n_estimators=200, contamination=0.03, random_state=42)
    feats = feats.copy()
    feats["anomaly_score"] = -model.fit_predict(X)  # 1 = anomaly, -1 -> 1 flip for readability... see below
    feats["anomaly_score_raw"] = -model.decision_function(X)  # higher = more anomalous
    feats["flagged"] = model.predict(X) == -1
    return feats


def evaluate(feats: pd.DataFrame, labels_path: str) -> None:
    labels = pd.read_csv(labels_path)
    merged = feats.merge(labels, on="transaction_id", suffixes=("", "_truth"))

    tp = ((merged["flagged"]) & (merged["is_anomaly"])).sum()
    fp = ((merged["flagged"]) & (~merged["is_anomaly"])).sum()
    fn = ((~merged["flagged"]) & (merged["is_anomaly"])).sum()
    tn = ((~merged["flagged"]) & (~merged["is_anomaly"])).sum()

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print(f"\n--- Evaluation against ground truth ({labels_path}) ---")
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"Precision={precision:.2%}  Recall={recall:.2%}")

    print("\nFlagged-but-missed anomaly types:")
    missed = merged[(~merged["flagged"]) & (merged["is_anomaly"])]
    print(missed["anomaly_type"].value_counts().to_string() if len(missed) else "  (none)")

    print("\nCaught anomaly types:")
    caught = merged[(merged["flagged"]) & (merged["is_anomaly"])]
    print(caught["anomaly_type"].value_counts().to_string() if len(caught) else "  (none)")

    print("\nTop 10 highest-scored flagged transactions:")
    top = merged[merged["flagged"]].sort_values("anomaly_score_raw", ascending=False).head(10)
    print(top[["transaction_id", "src", "dst", "function_code", "write_value",
               "anomaly_score_raw", "is_anomaly", "anomaly_type"]].to_string(index=False))


if __name__ == "__main__":
    pcap_path = "data/synthetic/modbus_traffic.pcap"
    labels_path = "data/synthetic/ground_truth_labels.csv"

    df = parse_pcap(pcap_path)
    feats = build_features(df)
    scored = score(feats)
    evaluate(scored, labels_path)
