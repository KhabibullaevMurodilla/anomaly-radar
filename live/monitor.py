"""
Live monitoring — the same session-level, population-relative detector as
models/session_detector.py, run continuously against a SPAN/mirror port or
tap instead of a saved pcap. Multi-protocol: Modbus/TCP and S7comm both,
not just Modbus (see parser/multi.py for why that matters on real OT
networks — this project's own validation capture is majority S7comm).

This can't live in ot-radar.html: a browser page has no access to a
network interface, only to a file you hand it. Live capture needs
packet-capture privileges on a real host, so it runs here, in the CLI.

How it works: sniff() feeds every packet to BOTH protocols'
StreamingXMatcher (parser/modbus_parser.py, parser/s7comm_parser.py) — the
exact same matchers parser/multi.py uses for file-based multi-protocol
parsing, so there's one matching implementation per protocol, not separate
ones for live vs. file. Each matcher internally ignores packets on a port
it doesn't own. Completed transactions land in a rolling window (default:
last 5 minutes); every `interval` seconds, that window gets scored with
the same peer-group z-scoring session_detector.py uses on a whole file,
and any session that just crossed the flagged threshold is reported once,
not on every subsequent tick it stays flagged.

Usage:
    sudo python main.py --watch eth0
    sudo python main.py --watch eth0 --window 600 --interval 30

Needs root or CAP_NET_RAW to open the interface, like any packet capture
(tcpdump, Wireshark). Point it at a SPAN/mirror port of the OT switch, or
a tap — not a random workstation NIC, which won't see PLC-to-PLC traffic.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Callable

from models.session_detector import build_session_summaries, score_sessions
from parser.modbus_parser import StreamingModbusMatcher
from parser.modbus_parser import _rows_to_df as _rows_to_df_common  # same row_id/sort logic, protocol-agnostic
from parser.s7comm_parser import StreamingS7CommMatcher

DEFAULT_BPF_FILTER = "tcp port 502 or tcp port 102"  # Modbus/TCP and S7comm (ISO-on-TCP)


class LiveMonitor:
    def __init__(self, iface: str, window_s: float = 300.0, interval_s: float = 15.0,
                 bpf_filter: str = DEFAULT_BPF_FILTER,
                 on_alert: Callable[[str, float, dict], None] | None = None):
        self.iface = iface
        self.window_s = window_s
        self.interval_s = interval_s
        self.bpf_filter = bpf_filter
        self.on_alert = on_alert or self._default_alert

        self._matchers = [StreamingModbusMatcher(), StreamingS7CommMatcher()]
        self._window: deque[dict] = deque()  # transactions within window_s, oldest first
        self._already_flagged: set[str] = set()
        self._last_report = 0.0
        self.transactions_seen = 0

    @staticmethod
    def _default_alert(session: str, max_abs_z: float, summary_row: dict) -> None:
        print(f"[ALERT] session {session} flagged — max|z|={max_abs_z:.2f} vs its peers "
              f"(n={summary_row['n_transactions']}, "
              f"req/s={summary_row['request_rate_per_s']:.2f}, "
              f"exc%={summary_row['exception_rate']*100:.0f}%, "
              f"func_codes={summary_row['unique_function_codes']})")

    def _on_packet(self, pkt) -> None:
        completed = []
        for matcher in self._matchers:
            matcher.process(pkt)
            completed.extend(matcher.drain())
        if completed:
            self.transactions_seen += len(completed)
            self._window.extend(completed)

        now = time.time()
        self._evict_old(now)
        if now - self._last_report >= self.interval_s and self._window:
            self._last_report = now
            self._score_window()

    def _evict_old(self, now: float) -> None:
        # request_ts is wall-clock (scapy's pkt.time), directly comparable
        # to time.time() for live traffic — unlike replaying an old pcap,
        # where request_ts would be whatever time the capture was taken.
        cutoff = now - self.window_s
        while self._window and self._window[0]["request_ts"] < cutoff:
            self._window.popleft()

    def _score_window(self) -> None:
        df = _rows_to_df_common(list(self._window))
        if df.empty:
            return
        summaries = score_sessions(build_session_summaries(df))
        flagged = summaries[summaries["flagged"]]
        newly_flagged = flagged[~flagged["session"].isin(self._already_flagged)]
        for _, row in newly_flagged.iterrows():
            self.on_alert(row["session"], row["max_abs_zscore"], row.to_dict())
        # A session can also stop being flagged as the window slides past
        # it — drop it from the seen-set so a later recurrence alerts again
        # instead of being silently suppressed as "already reported".
        self._already_flagged = set(flagged["session"])

    def run(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            raise SystemExit("Live capture needs scapy (already in requirements.txt): "
                              "pip install -r requirements.txt")

        print(f"[watch] sniffing {self.bpf_filter!r} on {self.iface} — "
              f"scoring a {self.window_s:.0f}s rolling window every {self.interval_s:.0f}s. "
              f"Ctrl-C to stop.")
        try:
            sniff(iface=self.iface, filter=self.bpf_filter, prn=self._on_packet, store=False)
        except PermissionError:
            raise SystemExit(
                "Permission denied opening that interface — live capture needs root or "
                "CAP_NET_RAW, same as tcpdump/Wireshark. Try:\n"
                "  sudo python main.py --watch " + self.iface + "\n"
                "or grant the capability once instead of running as root:\n"
                "  sudo setcap cap_net_raw+ep $(readlink -f $(which python3))"
            )
        except OSError as e:
            raise SystemExit(f"Could not open interface {self.iface!r}: {e}. "
                              f"List available interfaces with: python -c "
                              f"'from scapy.all import get_if_list; print(get_if_list())'")
