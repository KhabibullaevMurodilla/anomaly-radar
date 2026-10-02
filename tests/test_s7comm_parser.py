"""Tests for the S7comm parser, against the real 4SICS capture's S7comm
traffic specifically.

Not committed to this repo (data/real/ is gitignored) — these skip if the
file isn't present locally. Rebuild it from the 200MB 4SICS capture with:

    tshark -r 4SICS-GeekLounge-151022.pcap -Y "tcp.port==102" -F pcap \\
      -w data/real/s7comm/4sics-151022-s7comm-only.pcap

Why S7comm at all, and why this specific capture: checked directly with
`tshark -z io,phs` (not assumed) that the 4SICS capture is actually
MAJORITY S7comm — 106,421 S7comm frames vs. 99,472 Modbus frames. A
Modbus-only detector run against this network was only ever seeing about
half its real industrial traffic.
"""

import os

import pytest

from parser.modbus_parser import StreamingModbusMatcher
from parser.multi import parse_pcap_multi
from parser.pcapreader import iter_tcp_packets
from parser.s7comm_parser import StreamingS7CommMatcher, parse_pcap

S7_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "real", "s7comm", "4sics-151022-s7comm-only.pcap")
MODBUS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "real", "4sics-151022-modbus-only.pcap")

requires_real_s7 = pytest.mark.skipif(not os.path.exists(S7_PATH), reason="real S7comm capture not present locally — see module docstring")


@requires_real_s7
def test_parses_real_s7comm_traffic_without_crashing():
    df = parse_pcap(S7_PATH)
    assert len(df) > 50_000, "expected tens of thousands of real S7comm transactions in this capture"


@requires_real_s7
def test_real_s7comm_function_codes_are_recognized():
    """If the TPKT/COTP/S7-header framing were wrong, function codes would
    come out as noise ('unknown_N' for everything) instead of the expected
    polling-traffic shape: mostly read_var, a handful of writes."""
    df = parse_pcap(S7_PATH)
    names = df["function_name"].value_counts()
    assert names.get("read_var", 0) > 50_000
    assert not names.index.str.startswith("unknown_").all()


@requires_real_s7
def test_real_s7comm_rows_have_the_common_schema():
    """Session-level scoring (models/session_detector.py) needs these
    columns regardless of protocol — if S7comm parsing drifted from the
    shared schema, this is where it'd be caught."""
    df = parse_pcap(S7_PATH)
    for col in ("transaction_id", "unit_id", "function_code", "src", "dst",
                "request_ts", "response_ts", "is_exception", "protocol", "row_id"):
        assert col in df.columns
    assert (df["protocol"] == "s7comm").all()
    assert df["row_id"].is_unique


def test_fast_reader_and_scapy_path_agree_on_a_small_capture():
    """StreamingS7CommMatcher.process() accepts both a raw tuple (fast
    pcapreader path) and a live scapy packet — they must reach the same
    verdict on the same traffic, or live monitoring and file parsing would
    silently diverge. Modbus.pcap is a small synthetic-ish capture with no
    S7comm traffic, so this just confirms both paths agree on "nothing
    here" without crashing; the real-data tests above cover the fast path
    at scale.
    """
    if not os.path.exists(MODBUS_PATH):
        pytest.skip("no capture available to cross-check")

    fast = StreamingS7CommMatcher()
    for rec in iter_tcp_packets(MODBUS_PATH):
        fast.process(rec)
    fast_rows = fast.drain(include_unanswered=True)

    from scapy.all import rdpcap
    scapy_matcher = StreamingS7CommMatcher()
    for pkt in rdpcap(MODBUS_PATH):
        scapy_matcher.process(pkt)
    scapy_rows = scapy_matcher.drain(include_unanswered=True)

    assert len(fast_rows) == len(scapy_rows) == 0


@requires_real_s7
def test_multi_protocol_parse_combines_both_protocols():
    """parser/multi.py needs to find S7comm sessions even when run against
    a file that also has Modbus traffic — build a tiny synthetic mix isn't
    necessary here since the full 4SICS capture already has both; this
    confirms parse_pcap_multi recovers S7comm in the presence of Modbus."""
    import subprocess
    import tempfile

    # Merge the two already-filtered real subsets into one file so this
    # test exercises genuine protocol mixing, not just a single-protocol file.
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        subprocess.run(
            ["mergecap", "-w", tmp.name, MODBUS_PATH, S7_PATH],
            check=True, capture_output=True,
        )
        df = parse_pcap_multi(tmp.name)

    assert set(df["protocol"].unique()) == {"modbus", "s7comm"}
    assert (df["protocol"] == "modbus").sum() > 1000
    assert (df["protocol"] == "s7comm").sum() > 50_000
    assert df["row_id"].is_unique


def test_streaming_matcher_has_no_pending_requests_leaked_as_responses():
    """A response with no matching pending request (e.g. the capture starts
    mid-connection) must be dropped, not crash or fabricate a row — same
    contract as StreamingModbusMatcher."""
    matcher = StreamingS7CommMatcher()
    # A lone S7 Ack-Data response with nothing queued for its connection key.
    tpkt_cotp = bytes([0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80])
    s7_ack_data = bytes([0x32, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x04, 0xFF])
    matcher.process((1000.0, "10.0.0.99", "10.0.0.1", 102, 50000, tpkt_cotp + s7_ack_data))
    assert matcher.drain(include_unanswered=True) == []
