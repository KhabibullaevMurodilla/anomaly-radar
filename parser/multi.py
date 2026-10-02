"""
Multi-protocol entry point: parses Modbus/TCP AND S7comm out of the same
capture in a single pass, combined into one DataFrame with a `protocol`
column. A real OT network is not single-protocol — the project's own
4SICS validation capture is actually majority S7comm, not Modbus (checked
directly: 106,421 S7comm frames vs. 99,472 Modbus frames) — so scoring a
real capture with only a Modbus parser was only ever seeing part of its
traffic.

Uses the fast raw reader (parser/pcapreader.py) rather than scapy's
rdpcap(), feeding every packet to both protocols' StreamingXMatcher —
each one internally ignores packets on a port it doesn't own, so a single
read of the file drives both. Note this means the combined view here
carries the lightweight common schema only (transaction_id, unit_id,
function_code, is_exception, timing) for BOTH protocols — not Modbus's
richer per-function-code register fields (addr/value), which
parser/modbus_parser.py's scapy-based parse_pcap() still provides and
which models/baseline_detector.py's per-transaction features need. Use
THIS module for anything session-level (models/session_detector.py,
live/monitor.py); use modbus_parser.parse_pcap() directly for the
per-transaction Modbus-only detector.

Usage:
    from parser.multi import parse_pcap_multi
    df = parse_pcap_multi("path/to/capture.pcap")
"""

from __future__ import annotations

import pandas as pd

from parser.modbus_parser import StreamingModbusMatcher
from parser.pcapreader import iter_tcp_packets
from parser.s7comm_parser import StreamingS7CommMatcher


def parse_pcap_multi(path: str) -> pd.DataFrame:
    modbus = StreamingModbusMatcher()
    s7 = StreamingS7CommMatcher()

    for pkt in iter_tcp_packets(path):
        modbus.process(pkt)
        s7.process(pkt)

    rows = modbus.drain(include_unanswered=True) + s7.drain(include_unanswered=True)
    df = pd.DataFrame(rows)
    if not df.empty:
        # Same row_id rationale as each individual parser: neither
        # protocol's transaction/pdu-reference id is guaranteed unique,
        # and now two protocols' ids are being combined into one frame,
        # which makes a single unifying unique key even more necessary.
        df["row_id"] = range(len(df))
        df = df.sort_values("request_ts").reset_index(drop=True)
    return df


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m parser.multi <path_to.pcap>")
        sys.exit(1)

    df = parse_pcap_multi(sys.argv[1])
    print(f"Parsed {len(df)} transactions across protocols: "
          f"{df['protocol'].value_counts().to_dict() if not df.empty else {}}")
    print(df.head(10).to_string())
