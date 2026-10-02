"""
Turns parsed Modbus transactions into the feature representation an
anomaly model reasons over — per (src, dst, unit_id) "session", not
per-packet. This is the protocol-native part of the design: features are
built from what the transaction *means* (function code, address touched,
value written, how that compares to this session's own history), not
from raw byte counts or packet sizes.

This baseline uses hand-built statistical features + Isolation Forest to
prove the pipeline end-to-end. The next step up (see TODO.md) swaps this
scorer for a fine-tuned time-series foundation model operating on the
same feature frame — the parser and feature frame stay the same either way.
"""

from __future__ import annotations

from collections import deque

import pandas as pd

BURST_WINDOW_S = 1.0  # window for the "events per second, this session" rate feature


class _RunningStats:
    """Welford's online mean/variance — avoids storing full history per session."""

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    def zscore(self, x: float) -> float:
        if self.n < 2:
            return 0.0
        var = self.m2 / (self.n - 1)
        std = var ** 0.5
        return (x - self.mean) / std if std > 1e-9 else 0.0


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["session"] = df["src"] + "->" + df["dst"] + ":" + df["unit_id"].astype(str)
    df = df.sort_values("request_ts").reset_index(drop=True)

    # Per-session rolling context — this is what makes it protocol-native
    # rather than generic: "is this normal for THIS src/dst/unit_id pair",
    # not "is this an unusual byte count in general."
    feats = []
    session_history: dict[str, dict] = {}

    for _, row in df.iterrows():
        sess = row["session"]
        hist = session_history.setdefault(sess, {
            "funcs_seen": set(), "addrs_seen": set(), "last_ts": None,
            "recent_ts": deque(), "inter_arrival_stats": _RunningStats(),
            "write_value_stats": _RunningStats(),
        })

        ts = row["request_ts"]
        inter_arrival = (ts - hist["last_ts"]) if hist["last_ts"] is not None else None
        hist["last_ts"] = ts

        # Rolling event-rate window — this is what catches a scan burst that
        # per-event features miss: a flood of individually-plausible reads
        # is only anomalous in aggregate, over a short window, for this session.
        hist["recent_ts"].append(ts)
        while hist["recent_ts"] and ts - hist["recent_ts"][0] > BURST_WINDOW_S:
            hist["recent_ts"].popleft()
        events_in_window = len(hist["recent_ts"])

        # How unusual is this gap relative to *this session's own* cadence —
        # catches both bursts (ratio << 1) and unusual slowdowns (ratio >> 1).
        inter_arrival_zscore = (
            hist["inter_arrival_stats"].zscore(inter_arrival) if inter_arrival is not None else 0.0
        )

        addr = row.get("startAddr")
        if pd.isna(addr):
            addr = row.get("registerAddr")

        value = row.get("registerValue")
        has_value = value is not None and not pd.isna(value)
        # z-score against this session's OWN write-value history — this is
        # what separates "rare but legitimate setpoint" from "malicious
        # write": a value inside the session's normal spread scores low
        # even if the address itself is seen only occasionally.
        write_value_zscore = hist["write_value_stats"].zscore(value) if has_value else 0.0

        feat = {
            "row_id": row["row_id"],
            "transaction_id": row["transaction_id"],
            "src": row["src"],
            "dst": row["dst"],
            "session": sess,
            "function_code": row["function_code"],
            "is_write": int(bool(row["is_write"])),
            "is_novel_function_for_session": int(row["function_code"] not in hist["funcs_seen"]),
            "is_novel_address_for_session": int(
                addr is not None and not pd.isna(addr) and addr not in hist["addrs_seen"]
            ),
            "inter_arrival_s": inter_arrival if inter_arrival is not None else 2.0,
            "inter_arrival_zscore": inter_arrival_zscore,
            "events_in_1s_window": events_in_window,
            "write_value": value if has_value else -1,
            "write_value_zscore": write_value_zscore,
            "latency_s": row.get("latency_s") if not pd.isna(row.get("latency_s")) else 0.0,
            "is_exception": int(bool(row.get("is_exception"))),
        }
        feats.append(feat)

        hist["funcs_seen"].add(row["function_code"])
        if addr is not None and not pd.isna(addr):
            hist["addrs_seen"].add(addr)
        if inter_arrival is not None:
            hist["inter_arrival_stats"].update(inter_arrival)
        if has_value:
            hist["write_value_stats"].update(value)

    return pd.DataFrame(feats)


if __name__ == "__main__":
    import sys

    sys.path.insert(0, "..")
    from parser.modbus_parser import parse_pcap

    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/modbus_traffic.pcap"
    df = parse_pcap(pcap_path)
    feats = build_features(df)
    print(feats.head(10).to_string())
    print(f"\nBuilt features for {len(feats)} transactions.")
