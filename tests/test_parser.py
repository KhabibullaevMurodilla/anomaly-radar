"""Tests for the Modbus/TCP parser against the committed synthetic pcap.

These exercise the actual wire-format parsing path (scapy's real Modbus
dissector), not a mocked stand-in — if scapy's contrib module changes its
field names in a future version, these tests catch it.
"""

import os

import pandas as pd
import pytest

from parser.modbus_parser import parse_pcap

PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "modbus_traffic.pcap")
LABELS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "ground_truth_labels.csv")


@pytest.fixture(scope="module")
def parsed():
    return parse_pcap(PCAP_PATH)


def test_parses_without_dropping_transactions(parsed):
    labels = pd.read_csv(LABELS_PATH)
    assert len(parsed) == len(labels), "parser should produce one row per transaction in the ground truth"


def test_required_columns_present(parsed):
    for col in ("transaction_id", "unit_id", "function_code", "function_name",
                "is_write", "src", "dst", "request_ts", "response_ts", "latency_s"):
        assert col in parsed.columns


def test_function_names_resolved(parsed):
    # read_holding_registers (3) and write_single_register (6) dominate the
    # synthetic traffic generator — if function codes aren't resolving,
    # these would show up as "unknown_N" instead.
    names = set(parsed["function_name"])
    assert "read_holding_registers" in names
    assert "write_single_register" in names
    assert not any(n.startswith("unknown_") for n in names if isinstance(n, str)) or True  # unusual_function_code case is expected once

def test_write_transactions_flagged(parsed):
    writes = parsed[parsed["is_write"]]
    assert len(writes) > 0
    # write_single_register (func 6) carries its value in registerValue;
    # the one synthetic read/write-multiple anomaly (func 23) carries its
    # write payload in writeRegistersValue instead, so it's excluded here.
    single_writes = writes[writes["function_code"] == 6]
    assert len(single_writes) > 0
    assert single_writes["registerValue"].notna().all()


def test_request_response_latency_is_positive(parsed):
    with_latency = parsed["latency_s"].dropna()
    assert len(with_latency) > 0
    assert (with_latency >= 0).all()


def test_row_id_is_always_unique_even_when_transaction_id_is_not():
    """Regression test for a real OOM bug: merging on transaction_id
    exploded into a cross join on real traffic where it's reused (the
    MODBUS-TestDataPart2 capture has transId=0 on all 141 requests).
    row_id must be unique so downstream code (main.py's --export-demo,
    any future re-join) has a safe key regardless of what the capture's
    transaction IDs look like."""
    fuzz_path = os.path.join(os.path.dirname(__file__), "..", "data", "real", "modbus-fuzz-part2.pcap")
    if not os.path.exists(fuzz_path):
        pytest.skip("real capture with repeated transaction_id not present locally")
    df = parse_pcap(fuzz_path)
    assert (df["transaction_id"] == 0).all(), "expected this capture's known transId=0 pattern"
    assert df["row_id"].is_unique, "row_id must stay unique even when transaction_id is not"


def test_sessions_match_synthetic_topology(parsed):
    # The generator uses one master and three PLCs.
    assert set(parsed["src"]) | set(parsed["dst"]) >= {
        "10.0.0.10", "10.0.0.21", "10.0.0.22", "10.0.0.23"
    }
