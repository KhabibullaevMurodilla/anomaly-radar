"""End-to-end pipeline test: parse -> features -> score, checked against
the planted ground truth. This is a regression floor, not a target —
it fails loudly if a future change silently makes detection worse, and
the bar is set low on purpose because the baseline model is intentionally
simple (see TODO.md for why and what replaces it).
"""

import os

import pandas as pd

from features.build_features import build_features
from models.baseline_detector import score
from parser.modbus_parser import parse_pcap

PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "modbus_traffic.pcap")
LABELS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "ground_truth_labels.csv")


def test_pipeline_runs_end_to_end_without_error():
    df = parse_pcap(PCAP_PATH)
    feats = build_features(df)
    scored = score(feats)
    assert "flagged" in scored.columns
    assert "anomaly_score_raw" in scored.columns
    assert len(scored) == len(df)


def test_detection_rate_does_not_regress_below_known_floor():
    df = parse_pcap(PCAP_PATH)
    feats = build_features(df)
    scored = score(feats)
    labels = pd.read_csv(LABELS_PATH)
    merged = scored.merge(labels, on="transaction_id")

    tp = ((merged["flagged"]) & (merged["is_anomaly"])).sum()
    fp = ((merged["flagged"]) & (~merged["is_anomaly"])).sum()
    fn = ((~merged["flagged"]) & (merged["is_anomaly"])).sum()

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    # Known baseline as of the windowed-feature update: ~20.8% / ~23.3%.
    # Don't silently regress below half of that.
    assert precision > 0.10
    assert recall > 0.10


def test_flagging_rate_is_sane():
    # contamination=0.03 should flag roughly 3% of transactions, not 0%
    # (model broken) or 50%+ (features degenerate / all-zero).
    df = parse_pcap(PCAP_PATH)
    feats = build_features(df)
    scored = score(feats)
    flag_rate = scored["flagged"].mean()
    assert 0.01 < flag_rate < 0.10
