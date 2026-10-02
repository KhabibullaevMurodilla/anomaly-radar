"""Tests for the protocol-native feature builder, using small hand-built
transaction frames rather than a full pcap — these pin down the exact
semantics of each feature (novelty, windowed rate, z-scores) independent
of the parser.
"""

import pandas as pd

from features.build_features import build_features


def _row(transaction_id, src, dst, unit_id, function_code, is_write, ts,
         start_addr=None, register_addr=None, register_value=None, latency_s=0.01, is_exception=False):
    return {
        # row_id stands in for the parser-assigned unique identifier here;
        # transaction_id is kept separate since real captures can reuse it
        # (see parser/modbus_parser.py) — these tests use transaction_id
        # only as a human-readable label to look rows up by, not as a key.
        "row_id": transaction_id, "transaction_id": transaction_id, "src": src, "dst": dst, "unit_id": unit_id,
        "function_code": function_code, "is_write": is_write, "request_ts": ts,
        "startAddr": start_addr, "registerAddr": register_addr, "registerValue": register_value,
        "latency_s": latency_s, "is_exception": is_exception,
    }


def test_first_function_and_address_are_novel():
    df = pd.DataFrame([
        _row(1, "A", "B", 1, 3, False, 0.0, start_addr=100),
    ])
    feats = build_features(df)
    assert feats.loc[0, "is_novel_function_for_session"] == 1
    assert feats.loc[0, "is_novel_address_for_session"] == 1


def test_repeated_function_and_address_not_novel():
    df = pd.DataFrame([
        _row(1, "A", "B", 1, 3, False, 0.0, start_addr=100),
        _row(2, "A", "B", 1, 3, False, 2.0, start_addr=100),
    ])
    feats = build_features(df)
    assert feats.loc[1, "is_novel_function_for_session"] == 0
    assert feats.loc[1, "is_novel_address_for_session"] == 0


def test_burst_increases_events_in_window():
    # Three requests 5 seconds apart -> never more than one event in the
    # 1-second window. Three requests 10ms apart -> all three land in it.
    slow = pd.DataFrame([_row(i, "A", "B", 1, 3, False, float(i) * 5, start_addr=100) for i in range(3)])
    fast = pd.DataFrame([_row(i, "A", "B", 1, 3, False, i * 0.01, start_addr=100) for i in range(3)])

    slow_feats = build_features(slow)
    fast_feats = build_features(fast)

    assert slow_feats["events_in_1s_window"].max() == 1
    assert fast_feats["events_in_1s_window"].max() == 3


def test_write_value_zscore_flags_outlier_against_own_session_history():
    # Session establishes a tight normal range, then one wildly different write.
    rows = [_row(i, "A", "B", 1, 6, True, float(i) * 2, register_addr=200, register_value=100 + i)
            for i in range(10)]
    rows.append(_row(99, "A", "B", 1, 6, True, 30.0, register_addr=200, register_value=65000))
    df = pd.DataFrame(rows)

    feats = build_features(df)
    outlier_z = feats.loc[feats["transaction_id"] == 99, "write_value_zscore"].iloc[0]
    normal_z = feats.loc[feats["transaction_id"] == 5, "write_value_zscore"].abs().iloc[0]

    assert abs(outlier_z) > 5
    assert normal_z < abs(outlier_z)


def test_different_sessions_tracked_independently():
    # A function code novel on session A->B should still be novel the first
    # time it's seen on A->C, since sessions are keyed by (src, dst, unit).
    df = pd.DataFrame([
        _row(1, "A", "B", 1, 3, False, 0.0, start_addr=100),
        _row(2, "A", "C", 1, 3, False, 0.0, start_addr=100),
    ])
    feats = build_features(df)
    assert feats.loc[1, "is_novel_function_for_session"] == 1
    assert feats.loc[1, "is_novel_address_for_session"] == 1
