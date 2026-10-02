#!/usr/bin/env python3
"""
Export a raw per-transaction JSON for ot-radar.html's client-side
"Worked example" (loadExample() fetches this file directly).

Unlike main.py's old --export-demo (which pre-scored transactions with
the Python detectors, removed once the demo moved client-side), this file
carries only the raw fields the in-browser JS pipeline needs to parse and
score itself — the whole point is that the SAME JS code path that runs on
a user's own uploaded pcap also runs on this worked example, so what they
see here is proof the client-side detector actually works, not a canned
result.

Multi-protocol: pulls from data/real/4sics-151022-mixed.pcap (Modbus +
S7comm merged — see the mergecap command below) via parser.multi, so the
browser tool's worked example demonstrates both protocols, matching what
the CLI and live monitor now do. Regenerate the merged source file with:

    mergecap -F pcap -w data/real/4sics-151022-mixed.pcap \\
      data/real/4sics-151022-modbus-only.pcap \\
      data/real/s7comm/4sics-151022-s7comm-only.pcap

Schema: {"transactions": [{id, src, dst, unit, func, t, exc, protocol}, ...]}
  id       -> row_id (guaranteed unique; see parser/modbus_parser.py)
  t        -> request_ts offset from the capture's first transaction, seconds
  unit     -> unit_id
  func     -> function_code
  exc      -> is_exception
  protocol -> "modbus" or "s7comm"
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parser.multi import parse_pcap_multi

PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "real", "4sics-151022-mixed.pcap")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "real_demo_raw.json")


def main():
    df = parse_pcap_multi(PCAP_PATH)
    df = df.sort_values("request_ts")
    t0 = df["request_ts"].min()

    rows = []
    for _, r in df.iterrows():
        rows.append({
            "id": int(r["row_id"]),
            "src": r["src"],
            "dst": r["dst"],
            "unit": int(r["unit_id"]) if not (r["unit_id"] != r["unit_id"]) else None,
            "func": int(r["function_code"]) if not (r["function_code"] != r["function_code"]) else None,
            "t": round(float(r["request_ts"] - t0), 3),
            "exc": bool(r["is_exception"]) if r["is_exception"] is not None else False,
            "protocol": r["protocol"],
        })

    with open(OUT_PATH, "w") as f:
        json.dump({"transactions": rows}, f)

    by_protocol = {}
    for r in rows:
        by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + 1
    print(f"Wrote {OUT_PATH}: {len(rows)} transactions {by_protocol} "
          f"({sum(1 for r in rows if r['exc'])} exceptions, "
          f"{len(set((r['protocol'], r['src'], r['dst'], r['unit']) for r in rows))} sessions)")


if __name__ == "__main__":
    main()
