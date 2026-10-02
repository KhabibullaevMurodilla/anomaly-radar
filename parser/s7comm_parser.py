"""
Protocol-native S7comm parser (Siemens S7/TIA Portal, ISO-on-TCP port 102).

Why this protocol, specifically, as the second one: the 4SICS real capture
this project validates against is actually MAJORITY S7comm, not Modbus —
106,421 S7comm frames vs. 99,472 Modbus frames (checked directly with
`tshark -z io,phs`, not assumed). A "Modbus-only" detector was only ever
seeing roughly half of that network's real industrial traffic. S7 PLCs
(Siemens S7-300/400/1200/1500) are also extremely common outside North
America, which is a gap a Modbus/DNP3-only tool would have left wide open.

Unlike Modbus, scapy has no contrib dissector for S7comm, so this parses
the wire format directly from raw TCP bytes: TPKT (RFC 1006, 4 bytes) +
COTP (ISO 8073, variable) + the S7 header itself. Only the framing needed
to identify a transaction is parsed — not full item-level decoding of
read/write addresses, which real S7comm parsing libraries (snap7,
python-snap7, the Wireshark dissector) do far more completely. This is
deliberately scoped to what the anomaly-detection pipeline actually needs:
function code, success/failure, request<->response pairing, timing — the
same fields Modbus contributes, so the rest of the pipeline (features,
both detectors) doesn't need to know which protocol it's looking at.

Known simplifications, stated plainly rather than hidden:
  - No TCP reassembly: a PDU split across TCP segments (large block
    downloads, mainly) won't parse. Short Job/Ack-Data telegrams — the
    overwhelming majority of real polling and control traffic — fit in
    one segment and are unaffected.
  - unit_id is always 0. S7's rack/slot addressing is negotiated in the
    COTP Connection Request/Confirm handshake (TSAP), which isn't parsed
    here — sessions are still correctly separated by (src, dst), just not
    further split by rack/slot on one connection.
  - Exception detection (is_exception) is only accurate for Write Var
    (0x05) Ack-Data responses, which carry one return code. Read Var
    (0x04) responses carry a return code PER requested item in a
    variable-length list — not parsed here — so read responses are never
    flagged as exceptions. This under-counts read failures; it does not
    produce false positives.

Usage:
    from parser.s7comm_parser import parse_pcap
    df = parse_pcap("path/to/capture.pcap")
"""

from __future__ import annotations

import struct

import pandas as pd
from scapy.layers.inet import IP, TCP

from parser.pcapreader import iter_tcp_packets

S7COMM_PORT = 102

ROSCTR_JOB = 1
ROSCTR_ACK = 2
ROSCTR_ACK_DATA = 3
ROSCTR_USERDATA = 7
ROSCTR_NAMES = {ROSCTR_JOB: "job", ROSCTR_ACK: "ack", ROSCTR_ACK_DATA: "ack_data", ROSCTR_USERDATA: "userdata"}

# The S7 "function code" (first byte of the Parameter section) is this
# protocol's analogue of Modbus's function code. 0x28/0x29 are called out
# because issuing them is a direct availability attack (stopping a PLC),
# not just reconnaissance — worth a human recognizing them by name in a
# report, same reasoning as naming Modbus's write functions.
FUNCTION_CODES = {
    0x04: "read_var",
    0x05: "write_var",
    0xF0: "setup_communication",
    0x1A: "request_download",
    0x1B: "download_block",
    0x1C: "download_ended",
    0x1D: "start_upload",
    0x1E: "upload",
    0x1F: "end_upload",
    0x28: "plc_control",  # includes remote STOP
    0x29: "plc_stop",
}
WRITE_FUNCTIONS = {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29}  # writes program/state, not just reads it
STANDARD_FUNCTION_CODES = set(FUNCTION_CODES)


def _parse_s7_header(payload: bytes) -> dict | None:
    """payload is the raw TCP payload, expected to start at a TPKT header.
    Returns None for anything that isn't a parseable S7comm-over-COTP-Data
    PDU: a COTP connection request/confirm (no S7 payload), a non-TPKT
    segment (mid-PDU continuation — see the no-reassembly limitation
    above), or a short/malformed capture.
    """
    if len(payload) < 7 or payload[0] != 0x03:
        return None  # not TPKT version 3
    cotp_li = payload[4]
    if len(payload) < 5 + cotp_li:
        return None
    cotp_pdu_type = payload[5] & 0xF0
    if cotp_pdu_type != 0xF0:
        return None  # not a Data TPDU (e.g. 0xE0 Connection Request, 0xD0 Confirm) — no S7 payload follows

    s7_off = 5 + cotp_li
    if len(payload) < s7_off + 10 or payload[s7_off] != 0x32:
        return None  # not a valid S7 header (protocol id must be 0x32)

    rosctr = payload[s7_off + 1]
    pdu_ref = struct.unpack(">H", payload[s7_off + 4:s7_off + 6])[0]
    param_len = struct.unpack(">H", payload[s7_off + 6:s7_off + 8])[0]

    header = {"rosctr": rosctr, "pdu_reference": pdu_ref}

    if rosctr == ROSCTR_ACK:
        # Ack (no data) header: 2 extra bytes, error class + error code —
        # no parameter/data section at all.
        if len(payload) < s7_off + 12:
            return None
        header["function_code"] = None
        header["is_exception"] = payload[s7_off + 10] != 0
        return header

    param_off = s7_off + 10
    func_code = payload[param_off] if param_len >= 1 and len(payload) > param_off else None
    header["function_code"] = func_code

    if rosctr == ROSCTR_ACK_DATA and func_code == 0x05 and len(payload) > param_off + 1:
        # Write Var ack-data's single global return code — see the
        # module docstring for why only this case is checked.
        header["is_exception"] = payload[param_off + 1] != 0xFF
    else:
        header["is_exception"] = False
    return header


class StreamingS7CommMatcher:
    """S7comm analogue of modbus_parser.StreamingModbusMatcher — same FIFO-
    per-TCP-connection matching, same incremental process()/drain() shape
    so parser/multi.py can fan a packet out to every protocol's matcher
    without caring which one it is. The FIFO rationale applies here too:
    pdu_reference wraps and isn't guaranteed unique across a connection's
    lifetime, same category of problem as Modbus's transaction ID.
    """

    def __init__(self):
        self._pending: dict[tuple, list[dict]] = {}
        self._completed: list[dict] = []

    def process(self, pkt) -> None:
        """Accepts either a raw (ts, src, dst, sport, dport, payload)
        tuple — what the fast file reader (pcapreader.iter_tcp_packets)
        and parse_packets() below produce — or a live scapy packet from
        sniff(), so the exact same matching logic backs both the
        file-parsing path and live/monitor.py.
        """
        if isinstance(pkt, tuple):
            ts, src, dst, sport, dport, payload = pkt
        else:
            if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                return
            tcp = pkt[TCP]
            ts = float(pkt.time)
            src, dst = pkt[IP].src, pkt[IP].dst
            sport, dport = int(tcp.sport), int(tcp.dport)
            payload = bytes(tcp.payload)

        if dport != S7COMM_PORT and sport != S7COMM_PORT:
            return
        if not payload:
            return
        header = _parse_s7_header(payload)
        if header is None:
            return

        func_code = header["function_code"]

        if dport == S7COMM_PORT and header["rosctr"] == ROSCTR_JOB:
            conn_key = (src, sport, dst)
            self._pending.setdefault(conn_key, []).append({
                "transaction_id": header["pdu_reference"],
                "unit_id": 0,  # see module docstring: rack/slot not parsed from the COTP handshake
                "function_code": func_code,
                "function_name": FUNCTION_CODES.get(func_code, f"unknown_{func_code}") if func_code is not None else "unknown",
                "is_write": func_code in WRITE_FUNCTIONS if func_code is not None else False,
                "src": src, "dst": dst, "request_ts": ts,
                "protocol": "s7comm",
            })
        elif sport == S7COMM_PORT and header["rosctr"] in (ROSCTR_ACK, ROSCTR_ACK_DATA):
            conn_key = (dst, dport, src)
            queue = self._pending.get(conn_key)
            if not queue:
                return  # response with no outstanding request on this connection
            req = queue.pop(0)
            req["response_ts"] = ts
            req["latency_s"] = ts - req["request_ts"]
            req["is_exception"] = header["is_exception"]
            self._completed.append(req)

    def drain(self, include_unanswered: bool = False) -> list[dict]:
        rows, self._completed = self._completed, []
        if include_unanswered:
            for queue in self._pending.values():
                for req in queue:
                    rows.append({**req, "response_ts": None, "latency_s": None, "is_exception": None})
            self._pending = {}
        return rows


def _rows_to_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    if not df.empty:
        # Same row_id rationale as modbus_parser.py: pdu_reference (S7's
        # transaction_id here) isn't guaranteed unique, so anything that
        # re-joins this dataframe needs a key that is.
        df["row_id"] = range(len(df))
        df = df.sort_values("request_ts").reset_index(drop=True)
    return df


def parse_packets(packets) -> pd.DataFrame:
    """Parse an iterable of packets into one row per S7comm transaction.
    Accepts either raw tuples (pcapreader.iter_tcp_packets) or scapy
    packets (e.g. rdpcap() output) — see StreamingS7CommMatcher.process()."""
    matcher = StreamingS7CommMatcher()
    for pkt in packets:
        matcher.process(pkt)
    return _rows_to_df(matcher.drain(include_unanswered=True))


def parse_pcap(path: str) -> pd.DataFrame:
    """Parse an S7comm pcap file into one row per transaction. Uses the
    fast raw reader (parser/pcapreader.py), not scapy's rdpcap() — see
    that module's docstring for why: rdpcap() was too slow on this
    project's own real S7comm validation capture."""
    return parse_packets(iter_tcp_packets(path))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python s7comm_parser.py <path_to.pcap>")
        sys.exit(1)

    df = parse_pcap(sys.argv[1])
    print(f"Parsed {len(df)} S7comm transactions.")
    print(df.head(10).to_string())
