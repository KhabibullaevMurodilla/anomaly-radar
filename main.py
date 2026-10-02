#!/usr/bin/env python3
"""
OT Anomaly Radar — command-line entry point.

Runs the full pipeline against a pcap and reports anomalies at BOTH
levels this project detects at, by default:

  1. Per-transaction (baseline_detector.py) — is this transaction unusual
     for what THIS session has done before. Catches address/function
     novelty and value/timing outliers within an established session.
     Modbus/TCP only (see models/baseline_detector.py).
  2. Per-session (session_detector.py) — is this whole session unusual
     compared to its PEERS talking to the same PLC. Catches an attacker
     who is anomalous from their very first packet, which (1) cannot see
     by construction — see TODO.md for how this was found, against a
     real captured scan, not assumed. Multi-protocol: scores Modbus/TCP
     AND S7comm sessions found in the same capture (parser/multi.py).

Usage:
    python main.py capture.pcap                     # both detectors, human-readable
    python main.py capture.pcap --transactions-only  # just the per-transaction detector
    python main.py capture.pcap --sessions-only      # just the per-session detector
    python main.py capture.pcap --json               # per-transaction results as JSON
    python main.py capture.pcap --labels truth.csv   # precision/recall vs ground truth
    sudo python main.py --watch eth0                 # live: sniff a SPAN/mirror port,
                                                       # alert as sessions get flagged

The interactive demo (ot-radar.html) does NOT consume anything exported
from here — it runs this same parsing/scoring logic client-side in
JavaScript so a user's own pcap never has to leave their browser. See
scripts/export_raw_demo.py if you need to regenerate the worked-example
dataset bundled with that page.
"""

from __future__ import annotations

import argparse
import sys

import pandas as pd

from features.build_features import build_features
from models.baseline_detector import evaluate, score
from models.session_detector import analyze as analyze_sessions
from parser.modbus_parser import parse_pcap

SESSION_COLS = ["session", "protocol", "n_transactions", "request_rate_per_s", "exception_rate",
                "unique_function_codes", "nonstandard_function_code_rate", "max_abs_zscore"]
TRANSACTION_COLS = ["transaction_id", "src", "dst", "function_code", "write_value", "anomaly_score_raw"]


def run_transactions(pcap_path: str):
    df = parse_pcap(pcap_path)
    if df.empty:
        raise SystemExit(f"No Modbus/TCP transactions found in {pcap_path}. "
                          f"Is this a Modbus capture on port 502?")
    feats = build_features(df)
    scored = score(feats)
    return df, scored


def print_transaction_report(df: pd.DataFrame, scored: pd.DataFrame) -> None:
    flagged = scored[scored["flagged"]].sort_values("anomaly_score_raw", ascending=False)
    print(f"[per-transaction] {len(df)} transactions parsed, {len(flagged)} flagged "
          f"({len(flagged) / len(df):.1%}) — unusual for their own session's history")
    if len(flagged):
        print(flagged[TRANSACTION_COLS].head(10).to_string(index=False))
        if len(flagged) > 10:
            print(f"... and {len(flagged) - 10} more. Use --json for the full list.")
    else:
        print("  none flagged")


def print_session_report(session_result: pd.DataFrame) -> None:
    flagged = session_result[session_result["flagged"]].sort_values("max_abs_zscore", ascending=False)
    protocols = ", ".join(sorted(session_result["protocol"].unique())) if len(session_result) else "none"
    print(f"\n[per-session] {len(session_result)} sessions ({protocols}), {len(flagged)} flagged — "
          f"unusual compared to peer sessions on the same PLC and protocol")
    if len(flagged):
        print(flagged[SESSION_COLS].to_string(index=False))
    else:
        print("  none flagged")


def main():
    ap = argparse.ArgumentParser(description="Parse a Modbus/TCP pcap and score it for anomalies, at both the transaction and session level.")
    ap.add_argument("pcap", nargs="?", help="Path to a Modbus/TCP pcap file (omit when using --watch)")
    ap.add_argument("--labels", help="Optional ground-truth CSV (transaction_id,is_anomaly,anomaly_type,...) — "
                                      "switches to a precision/recall report for the per-transaction detector")
    ap.add_argument("--json", action="store_true", help="Print flagged transactions as JSON instead of a text report")
    ap.add_argument("--transactions-only", action="store_true", help="Run only the per-transaction detector")
    ap.add_argument("--sessions-only", action="store_true", help="Run only the per-session detector")
    ap.add_argument("--watch", metavar="IFACE", help="Live mode: sniff Modbus/TCP on this interface "
                                                        "(a SPAN/mirror port or tap) instead of reading a pcap, "
                                                        "and alert as sessions get flagged. Needs root/CAP_NET_RAW.")
    ap.add_argument("--window", type=float, default=300.0, metavar="SECONDS",
                     help="--watch only: rolling window of recent traffic to score against (default 300s)")
    ap.add_argument("--interval", type=float, default=15.0, metavar="SECONDS",
                     help="--watch only: how often to re-score the window (default 15s)")
    args = ap.parse_args()

    if args.watch:
        from live.monitor import LiveMonitor
        LiveMonitor(args.watch, window_s=args.window, interval_s=args.interval).run()
        return

    if not args.pcap:
        ap.error("pcap is required unless --watch is given")

    if args.labels:
        df, scored = run_transactions(args.pcap)
        evaluate(scored, args.labels)
        return

    if args.sessions_only:
        print_session_report(analyze_sessions(args.pcap))
        return

    df, scored = run_transactions(args.pcap)

    if args.json:
        flagged = scored[scored["flagged"]].sort_values("anomaly_score_raw", ascending=False)
        print(flagged.to_json(orient="records"))
        return

    print_transaction_report(df, scored)
    if not args.transactions_only:
        # analyze_sessions() re-parses the pcap rather than reusing the
        # Modbus-only `df` above — necessary now, not just an extra pass:
        # `df` only has Modbus transactions (run_transactions() uses
        # modbus_parser's scapy-based parser for the richer per-function
        # register fields the per-transaction detector needs), and the
        # session-level detector needs S7comm sessions too. It's also
        # using parser/multi.py's fast reader under the hood, not scapy,
        # so re-parsing here is cheap regardless of capture size.
        print_session_report(analyze_sessions(args.pcap))

    if not args.labels:
        print("\nNo --labels provided, so the per-transaction numbers above are unvalidated. "
              "Pass --labels ground_truth.csv for precision/recall against known attacks.")


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except BrokenPipeError:
        # Piping output into `head` or similar closes stdin early — that's
        # a normal way to use a CLI, not an error worth a traceback.
        sys.stderr.close()
        sys.exit(0)
