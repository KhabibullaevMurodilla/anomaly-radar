"""Validation against real Modbus/TCP captures (not synthetic traffic).

These come from automayt/ICS-pcap (public domain test captures, originally
Digital Bond's Modbus test suites). They're not committed to this repo
(see data/real/ in .gitignore — avoid redistributing third-party capture
files even when they're freely downloadable), so these tests are skipped
if the files aren't present locally. Fetch them with:

    curl -o data/real/modbus-fuzz-1.pcap \\
      https://media.githubusercontent.com/media/automayt/ICS-pcap/master/MODBUS/MODBUS-TestDataPart1/MODBUS-TestDataPart1.pcap
    curl -o data/real/modbus-fuzz-2.pcap \\
      https://media.githubusercontent.com/media/automayt/ICS-pcap/master/MODBUS/MODBUS-TestDataPart2/MODBUS-TestDataPart2.pcap

This is where the FIFO-per-connection matching fix in modbus_parser.py
came from: real Modbus masters often never increment the transaction ID
(MODBUS-TestDataPart2 is 141/141 requests at transId=0), which the
original transaction-id-keyed join silently mismatched.
"""

import os

import pytest

from parser.modbus_parser import parse_pcap

REAL_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "real")


def _real_pcaps():
    if not os.path.isdir(REAL_DIR):
        return []
    return [os.path.join(REAL_DIR, f) for f in os.listdir(REAL_DIR) if f.endswith(".pcap")]


pytestmark = pytest.mark.skipif(not _real_pcaps(), reason="no real captures in data/real/ — see module docstring to fetch them")


@pytest.mark.parametrize("path", _real_pcaps())
def test_real_capture_parses_without_crashing(path):
    df = parse_pcap(path)
    # Not every real pcap in this folder is necessarily Modbus (e.g. a
    # Siemens S7comm capture would correctly parse to zero rows) — the
    # bar here is "doesn't crash on real wire format," not "finds traffic."
    assert df is not None


def test_fifo_matching_handles_repeated_transaction_id():
    """Regression test for the real bug this found: a capture where every
    request uses transaction_id=0 must still get one row per request/response
    pair, matched in connection order — not collapsed or cross-matched."""
    candidates = [p for p in _real_pcaps() if "Part2" in p or "part2" in p]
    if not candidates:
        pytest.skip("MODBUS-TestDataPart2 not present locally")
    df = parse_pcap(candidates[0])
    assert (df["transaction_id"] == 0).all(), "this capture is expected to reuse transId=0 throughout"
    assert len(df) > 100, "FIFO matching should recover ~all request/response pairs, not collapse them"
    # Each transaction should have a distinct, sequential function code in
    # this fuzz-test capture (0,1,2,3,...) — if matching were still broken,
    # we'd see repeats/collisions instead of a clean sweep.
    assert df["function_code"].nunique() > 50
