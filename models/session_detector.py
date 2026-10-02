"""
Session-level, population-relative anomaly detector.

This exists to close the blind spot found by testing against a real
4SICS capture: the per-transaction baseline_detector.py compares each
transaction to *that session's own history*, which cannot catch a client
that is malicious from the very first packet — there's no earlier
"normal" period for it to deviate from (see TODO.md for the full story).

The fix here is a different axis of comparison: instead of "is this
transaction unusual for this session," ask "is this *session*, as a
whole, unusual compared to the other sessions talking to the same PLC."
A live scan that holds a single connection open and sweeps 256 function
codes at 370 req/s looks nothing like the handful of other legitimate
clients politely polling the same device every couple of seconds — even
though, from inside its own history, it never deviates from itself.

Run:
    python models/session_detector.py <pcap>
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from parser.modbus_parser import parse_pcap  # noqa: E402

# The standard function code set, per protocol (per each one's spec).
# Anything outside a session's own protocol's set is already a red flag
# on its own, independent of any baseline. Keyed by the `protocol` column
# parser/multi.py (and now modbus_parser.py / s7comm_parser.py) attach to
# every row; a dataframe with no `protocol` column (older single-protocol
# Modbus dataframes, e.g. in tests written before S7comm support existed)
# defaults to "modbus" below, so this stays backward compatible.
STANDARD_FUNCTION_CODES = {
    "modbus": {1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 24, 43},
    "s7comm": {0x04, 0x05, 0xF0, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29},
}

Z_THRESHOLD = 2.5  # how many std devs from the peer-group mean counts as an outlier


def build_session_summaries(df: pd.DataFrame) -> pd.DataFrame:
    """One row per (protocol, src, dst, unit_id) session, with aggregate
    behavior stats. Protocol is part of the session key — not just src/dst/
    unit_id — so a PLC that happens to speak two protocols (seen in the
    4SICS capture: Modbus and S7comm sessions to overlapping hosts) doesn't
    get its Modbus and S7comm conversations collapsed into one session or
    peer-compared against each other, which would be comparing apples to
    oranges (the two protocols' normal function-code diversity and request
    rates aren't on the same scale).
    """
    df = df.copy()
    if "protocol" not in df.columns:
        df["protocol"] = "modbus"  # backward compat with pre-multi-protocol dataframes
    df["session"] = df["protocol"] + ":" + df["src"] + "->" + df["dst"] + ":" + df["unit_id"].astype(str)

    rows = []
    for session, grp in df.groupby("session"):
        n = len(grp)
        protocol = grp["protocol"].iloc[0]
        duration = grp["request_ts"].max() - grp["request_ts"].min()
        # A single-transaction session has no meaningful rate — leave it as
        # NaN (excluded from z-scoring) rather than dividing by a near-zero
        # duration, which produces a nonsense "1,000,000 req/s" artifact.
        request_rate = (n / duration) if (n > 1 and duration > 1e-6) else np.nan

        func_codes = grp["function_code"].dropna()
        standard_codes = STANDARD_FUNCTION_CODES.get(protocol, STANDARD_FUNCTION_CODES["modbus"])
        nonstandard = (~func_codes.isin(standard_codes)).mean() if len(func_codes) else 0.0

        rows.append({
            "session": session,
            "protocol": protocol,
            "src": grp["src"].iloc[0],
            "dst": grp["dst"].iloc[0],
            "n_transactions": n,
            "duration_s": duration,
            "request_rate_per_s": request_rate,
            "exception_rate": grp["is_exception"].mean(),
            "unique_function_codes": func_codes.nunique(),
            "nonstandard_function_code_rate": nonstandard,
        })

    return pd.DataFrame(rows)


def score_sessions(summaries: pd.DataFrame) -> pd.DataFrame:
    """Z-score each session against its peer group: other sessions hitting
    the SAME destination AND protocol (dst, protocol) — the right
    comparison set, since normal traffic volume/shape legitimately differs
    PLC to PLC, vendor to vendor, and protocol to protocol (S7comm's
    typical function-code diversity, for instance, is nothing like
    Modbus's). Falls back to the global population *within that protocol*
    for a dst with too few peers to form a meaningful baseline.
    """
    summaries = summaries.copy()
    metrics = ["request_rate_per_s", "exception_rate", "unique_function_codes", "nonstandard_function_code_rate"]

    for metric in metrics:
        summaries[f"{metric}_zscore"] = 0.0

    for (dst, protocol), grp in summaries.groupby(["dst", "protocol"]):
        same_protocol = summaries[summaries["protocol"] == protocol]
        peer_pool = grp if len(grp) >= 3 else same_protocol  # fall back to same-protocol population if too few peers at this dst
        for metric in metrics:
            mean, std = peer_pool[metric].mean(), peer_pool[metric].std()
            if std and std > 1e-9:
                z = (summaries.loc[grp.index, metric] - mean) / std
            else:
                z = pd.Series(0.0, index=grp.index)
            # A metric that's undefined for this session (e.g. request rate
            # for a single-transaction session) contributes no evidence
            # either way, rather than blowing up the max() with a NaN.
            summaries.loc[grp.index, f"{metric}_zscore"] = z.fillna(0.0)

    zscore_cols = [f"{m}_zscore" for m in metrics]
    summaries["max_abs_zscore"] = summaries[zscore_cols].abs().max(axis=1)
    summaries["flagged"] = summaries["max_abs_zscore"] > Z_THRESHOLD
    return summaries


def analyze(pcap_path: str) -> pd.DataFrame:
    """Multi-protocol: scores Modbus AND S7comm sessions found in the same
    capture (parser.multi.parse_pcap_multi), not just Modbus."""
    from parser.multi import parse_pcap_multi
    df = parse_pcap_multi(pcap_path)
    summaries = build_session_summaries(df)
    return score_sessions(summaries)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python models/session_detector.py <pcap>")
        sys.exit(1)

    result = analyze(sys.argv[1])
    cols = ["session", "n_transactions", "request_rate_per_s", "exception_rate",
            "unique_function_codes", "nonstandard_function_code_rate", "max_abs_zscore", "flagged"]
    print(result[cols].sort_values("max_abs_zscore", ascending=False).to_string(index=False))
