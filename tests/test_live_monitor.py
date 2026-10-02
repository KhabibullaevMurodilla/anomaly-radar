"""Tests for the live-capture refactor and LiveMonitor's windowing logic.

Two things need checking: (1) splitting parse_pcap() into a reusable
StreamingModbusMatcher didn't change its output — a packet-by-packet feed
must produce identical transactions to the old all-at-once rdpcap() path;
(2) LiveMonitor's rolling window and "alert once per newly-flagged
session" logic, which has no equivalent to test against in the file-based
pipeline since it only exists for live mode.
"""

import os

import pandas as pd
from scapy.all import rdpcap

from live.monitor import LiveMonitor
from parser.modbus_parser import StreamingModbusMatcher, parse_pcap

PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "modbus_traffic.pcap")


def test_streaming_matcher_matches_parse_pcap_output():
    """Feeding packets one at a time through StreamingModbusMatcher (as
    live capture does) must produce the same transactions as parse_pcap's
    all-at-once rdpcap() path — this is the refactor's core correctness
    requirement, since both now share this class."""
    expected = parse_pcap(PCAP_PATH)

    matcher = StreamingModbusMatcher()
    for pkt in rdpcap(PCAP_PATH):
        matcher.process(pkt)
    rows = matcher.drain(include_unanswered=True)
    got = pd.DataFrame(rows)

    assert len(got) == len(expected)
    # Compare on content, not row_id/order, which depend on sort — the
    # matching itself (which request paired with which response) is what
    # must be identical.
    key_cols = ["transaction_id", "src", "dst", "function_code", "request_ts", "response_ts"]
    got_sorted = got[key_cols].sort_values(key_cols).reset_index(drop=True)
    expected_sorted = expected[key_cols].sort_values(key_cols).reset_index(drop=True)
    pd.testing.assert_frame_equal(got_sorted, expected_sorted)


def _row(src, dst, unit_id, func_code, t, is_exception=False):
    return {
        "src": src, "dst": dst, "unit_id": unit_id, "function_code": func_code,
        "request_ts": t, "response_ts": t + 0.01, "latency_s": 0.01,
        "is_exception": is_exception, "transaction_id": 0,
    }


def test_window_evicts_old_transactions():
    """A transaction older than window_s should age out of the rolling
    window rather than being scored forever."""
    mon = LiveMonitor("lo", window_s=10.0, interval_s=1000.0)  # interval irrelevant here
    now = 1_000_000.0
    mon._window.extend([
        _row("10.0.0.1", "10.0.0.2", 1, 3, now - 20),  # too old, should be evicted
        _row("10.0.0.1", "10.0.0.2", 1, 3, now - 1),   # recent, should survive
    ])
    mon._evict_old(now)
    assert len(mon._window) == 1
    assert mon._window[0]["request_ts"] == now - 1


def test_alert_fires_once_per_newly_flagged_session():
    """An attacker session should trigger exactly one alert when it first
    crosses the threshold, not on every subsequent scoring tick while it
    stays flagged — otherwise a 5-minute scan would spam one alert per
    --interval forever."""
    alerts = []
    mon = LiveMonitor("lo", window_s=600.0, interval_s=1000.0,
                       on_alert=lambda session, z, row: alerts.append(session))

    now = 2_000_000.0
    rows = []
    # 8 calm peer sessions on the same dst, low rate / no exceptions
    for i in range(8):
        for j in range(3):
            rows.append(_row(f"10.0.0.{i+10}", "10.0.0.99", 1, 3, now - 100 + j * 10))
    # 1 scan-like session: many requests, all exceptions, nonstandard func codes
    for j in range(40):
        rows.append(_row("10.0.0.200", "10.0.0.99", 1, 99, now - 50 + j * 0.1, is_exception=True))

    mon._window.extend(rows)
    mon._score_window()
    assert alerts == ["modbus:10.0.0.200->10.0.0.99:1"]

    # Score again with no new data — must NOT re-alert on the same session.
    mon._score_window()
    assert alerts == ["modbus:10.0.0.200->10.0.0.99:1"]
