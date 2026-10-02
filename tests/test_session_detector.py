"""Tests for the population-relative session detector — the layer added
after real-world testing showed the per-transaction, session-relative
baseline_detector.py has a structural blind spot: it can't catch an
attacker who is anomalous from the very first packet of a session, since
there's no earlier "normal" period for that session to deviate from.
"""

import pandas as pd

from models.session_detector import build_session_summaries, score_sessions


def _row(src, dst, unit_id, ts, function_code, is_exception):
    return {"src": src, "dst": dst, "unit_id": unit_id, "request_ts": ts,
            "function_code": function_code, "is_exception": is_exception}


def test_benign_peer_sessions_are_not_flagged():
    # Three sessions to different PLCs, all polling at a similar rate with
    # the same standard function code and no exceptions — none should
    # stand out against each other.
    rows = []
    for dst in ("B", "C", "D"):
        for i in range(50):
            rows.append(_row("A", dst, 1, i * 2.0, 3, False))
    df = pd.DataFrame(rows)

    summaries = score_sessions(build_session_summaries(df))
    assert not summaries["flagged"].any()


def test_scan_like_session_is_flagged_against_benign_peers():
    # Ten sessions hit the SAME destination: nine poll normally, one
    # sweeps function codes at high rate with a high exception rate —
    # the pattern found in the real 4SICS capture. Needs a peer group of
    # a reasonable size: with a self-inclusive z-score (the outlier's own
    # value widens the population std it's measured against), the max
    # possible |z| is bounded by sqrt(n_peers - 1) — too few peers and no
    # outlier, however extreme, can mathematically cross the threshold.
    rows = []
    for p in range(9):
        for i in range(50):
            rows.append(_row(f"peer{p}", "PLC", 1, i * 2.0, 3, False))
    for i in range(500):
        rows.append(_row("attacker", "PLC", 1, i * 0.01, i % 200, True))
    df = pd.DataFrame(rows)

    summaries = score_sessions(build_session_summaries(df))
    attacker_row = summaries[summaries["src"] == "attacker"].iloc[0]
    peer_rows = summaries[summaries["src"] != "attacker"]

    assert attacker_row["flagged"]
    assert not peer_rows["flagged"].any()
    assert attacker_row["max_abs_zscore"] > peer_rows["max_abs_zscore"].max()


def test_single_transaction_session_does_not_produce_rate_artifact():
    # A session with exactly one transaction has an undefined rate — this
    # used to compute as 1,000,000 req/s from a near-zero duration and
    # could spuriously dominate the z-score. It should be excluded instead.
    rows = [_row("A", "B", 1, 0.0, 3, False)]
    df = pd.DataFrame(rows)
    summaries = build_session_summaries(df)
    assert pd.isna(summaries.iloc[0]["request_rate_per_s"])
