"""
Protocol-native Modbus/TCP parser.

This is the core idea behind the "protocol-native" approach (per Cisco's
APEX paper): instead of feeding a model raw byte/packet-size time series,
parse each Modbus transaction into its semantic fields — function code,
unit id, register address, register value, request/response pairing,
timing — and build a *transaction chain* per (source, dest, unit_id).
That structured chain is what gets fed to the anomaly model downstream,
not raw bytes.

Input:  a pcap file containing Modbus/TCP traffic (port 502).
Output: a pandas-ready list of dicts, one row per Modbus transaction,
        with request and response fields joined on transaction_id.

Usage:
    from parser.modbus_parser import parse_pcap
    df = parse_pcap("path/to/capture.pcap")
"""

from __future__ import annotations

import pandas as pd
from scapy.all import rdpcap
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from scapy.layers.inet import IP, TCP

from parser.pcapreader import iter_tcp_packets

MODBUS_PORT = 502

# Function code -> human label (the common subset seen in OT traffic)
FUNCTION_CODES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    22: "mask_write_register",
    23: "read_write_multiple_registers",
}

WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}
READ_FUNCTIONS = {1, 2, 3, 4}


def _extract_request_fields(adu) -> dict:
    """Pull the semantically meaningful fields out of a Modbus request ADU
    (a ModbusADURequest — either a layer sliced out of a full scapy packet
    via pkt[ModbusADURequest], or constructed directly from raw TCP
    payload bytes via ModbusADURequest(payload); both dissect identically,
    see parse_pcap()'s fast path below for why that distinction exists).

    The MBAP header (transId/unitId) lives on ModbusADURequest; the
    function code and its arguments live on the function-specific PDU
    layer stacked beneath it (e.g. ModbusPDU03ReadHoldingRegistersRequest),
    so we read the header from the ADU and everything else from its payload.
    """
    pdu = adu.payload
    func_code = getattr(pdu, "funcCode", None)
    fields = {
        "transaction_id": adu.transId,
        "unit_id": adu.unitId,
        "function_code": func_code,
        "function_name": FUNCTION_CODES.get(func_code, f"unknown_{func_code}"),
        "is_write": func_code in WRITE_FUNCTIONS,
    }
    # Address/value fields vary by function code — pull what's present
    # rather than assuming a fixed schema, since read vs write PDUs differ.
    for attr in ("startAddr", "quantity", "outputAddr", "outputValue",
                 "registerAddr", "registerValue", "byteCount",
                 "readStartingAddr", "readQuantityRegisters",
                 "writeStartingAddr", "writeQuantityRegisters", "writeRegistersValue"):
        if hasattr(pdu, attr):
            val = getattr(pdu, attr)
            fields[attr] = list(val) if isinstance(val, list) else val
    return fields


def _extract_response_fields(adu) -> dict:
    """Same ADU-object contract as _extract_request_fields() above."""
    pdu = adu.payload
    func_code = getattr(pdu, "funcCode", None)
    fields = {
        "transaction_id": adu.transId,
        "response_function_code": func_code,
        "is_exception": func_code is not None and func_code >= 0x80,
    }
    if hasattr(pdu, "registerVal"):
        fields["response_values"] = list(pdu.registerVal)
    if hasattr(pdu, "coilStatus"):
        fields["response_values"] = list(pdu.coilStatus)
    if hasattr(pdu, "exceptCode"):
        fields["exception_code"] = pdu.exceptCode
    return fields


def _extract_request_fields_raw(payload: bytes) -> dict | None:
    """MBAP-only extraction straight from TCP payload bytes — the fast
    path used for multi-protocol parsing (parser/multi.py), which only
    needs the common schema (transaction_id, unit_id, function_code), not
    the full per-function-code register addr/value decoding
    _extract_request_fields() does via scapy's PDU layer. Same 7-byte
    MBAP layout as the client-side JS parser in ot-radar.html, cross-
    checked against it.
    """
    if len(payload) < 8:
        return None
    trans_id = (payload[0] << 8) | payload[1]
    unit_id = payload[6]
    func_code = payload[7]
    return {
        "transaction_id": trans_id,
        "unit_id": unit_id,
        "function_code": func_code,
        "function_name": FUNCTION_CODES.get(func_code, f"unknown_{func_code}"),
        "is_write": func_code in WRITE_FUNCTIONS,
    }


def _extract_response_fields_raw(payload: bytes) -> dict | None:
    if len(payload) < 8:
        return None
    func_code = payload[7]
    return {
        "transaction_id": (payload[0] << 8) | payload[1],
        "is_exception": func_code >= 0x80,
    }


class StreamingModbusMatcher:
    """Incremental version of the FIFO request/response matcher.

    parse_pcap() needs this logic to run once over a whole file; live
    capture (live/monitor.py) needs the exact same matching logic to run
    packet-by-packet as traffic arrives, with no pcap file at all. Rather
    than keep two copies of the matching rules in sync by hand, both paths
    go through this class — parse_packets() below just feeds it every
    packet from a pcap in one pass; live monitoring feeds it one packet
    at a time from scapy's sniff() callback.

    Joins request and response **in FIFO order per TCP connection**
    (client_ip, client_port, server_ip) — not by the Modbus transaction
    ID field. This matters because many real Modbus masters (especially
    serial-to-TCP gateways) never increment the transaction ID — it's
    0 on every request — which was confirmed against real captures
    (automayt/ICS-pcap's MODBUS-TestDataPart2: 141/141 requests at
    transId=0). Matching on that field alone silently mispairs requests
    with the wrong responses whenever it's reused. A single TCP
    connection is strictly ordered, and Modbus is not pipelined per
    connection in practice, so "oldest unanswered request on this
    connection" is the reliable match — transaction_id is kept in the
    output for diagnostics, but is not part of the join key.
    """

    def __init__(self):
        # One FIFO queue of unanswered requests per TCP connection, keyed
        # by (client_ip, client_port, server_ip) — stable for the life of
        # the connection regardless of which unit_ids get multiplexed
        # over it.
        self._pending: dict[tuple, list[dict]] = {}
        self._completed: list[dict] = []

    def process(self, pkt) -> None:
        """Feed one packet in. Completed transactions accumulate
        internally — call drain() to collect and clear them.

        Accepts a raw (ts, src, dst, sport, dport, payload) tuple — from
        the fast reader (parser/pcapreader.py), used by the multi-protocol
        path (parser/multi.py) — or a live scapy packet (from sniff()),
        used by live/monitor.py and parse_pcap() below. The raw path only
        extracts the common schema (MBAP header fields); the scapy path
        additionally decodes per-function-code register addr/value via
        _extract_request_fields(), which parse_pcap()'s single-protocol
        callers (e.g. the per-transaction Isolation Forest features) need
        and the session-level detector does not.
        """
        if isinstance(pkt, tuple):
            ts, src, dst, sport, dport, payload = pkt
            if dport != MODBUS_PORT and sport != MODBUS_PORT:
                return
            if dport == MODBUS_PORT:
                req = _extract_request_fields_raw(payload)
                if req is None:
                    return
                conn_key = (src, sport, dst)
                self._pending.setdefault(conn_key, []).append(
                    {**req, "src": src, "dst": dst, "request_ts": ts, "protocol": "modbus"}
                )
            else:
                resp = _extract_response_fields_raw(payload)
                if resp is None:
                    return
                conn_key = (dst, dport, src)
                queue = self._pending.get(conn_key)
                if not queue:
                    return
                req = queue.pop(0)
                row = {**req, **resp, "response_ts": ts}
                row["latency_s"] = row["response_ts"] - row["request_ts"]
                self._completed.append(row)
            return

        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return

        tcp = pkt[TCP]
        ts = float(pkt.time)
        src, dst = pkt[IP].src, pkt[IP].dst

        if tcp.dport == MODBUS_PORT and pkt.haslayer(ModbusADURequest):
            req = _extract_request_fields(pkt[ModbusADURequest])
            conn_key = (src, tcp.sport, dst)
            self._pending.setdefault(conn_key, []).append(
                {**req, "src": src, "dst": dst, "request_ts": ts, "protocol": "modbus"}
            )

        elif tcp.sport == MODBUS_PORT and pkt.haslayer(ModbusADUResponse):
            resp = _extract_response_fields(pkt[ModbusADUResponse])
            conn_key = (dst, tcp.dport, src)  # client_ip, client_port, server_ip
            queue = self._pending.get(conn_key)
            if not queue:
                return  # response with no outstanding request on this connection
            req = queue.pop(0)
            row = {**req, **resp, "response_ts": ts}
            row["latency_s"] = row["response_ts"] - row["request_ts"]
            self._completed.append(row)

    def process_payload(self, ts: float, src: str, dst: str, sport: int, dport: int, payload: bytes) -> None:
        """Fast-file-parsing path with FULL fidelity (register addr/value,
        not just the MBAP header): constructs scapy's ModbusADURequest/
        ModbusADUResponse layer directly from the raw TCP payload bytes —
        `ModbusADURequest(payload)` dissects identically to slicing
        pkt[ModbusADURequest] out of a fully-dissected packet, but without
        scapy having to dissect Ethernet/IP/TCP/every-other-protocol-it-
        knows-about first. parse_pcap() below uses parser/pcapreader.py's
        fast reader to get (ts, src, dst, sport, dport, payload) for every
        TCP packet, cheaply, then only pays scapy's dissection cost for
        packets actually on the Modbus port — the fix for a real measured
        problem: rdpcap() alone took ~30s on this project's 104k-packet
        Modbus-only validation capture, and became impractical (minutes)
        once real captures mix in a larger second protocol (S7comm),
        because rdpcap() dissects every packet in the file, Modbus or not.
        """
        if dport != MODBUS_PORT and sport != MODBUS_PORT:
            return
        if len(payload) < 8:
            return

        if dport == MODBUS_PORT:
            adu = ModbusADURequest(bytes(payload))
            req = _extract_request_fields(adu)
            conn_key = (src, sport, dst)
            self._pending.setdefault(conn_key, []).append(
                {**req, "src": src, "dst": dst, "request_ts": ts, "protocol": "modbus"}
            )
        else:
            adu = ModbusADUResponse(bytes(payload))
            resp = _extract_response_fields(adu)
            conn_key = (dst, dport, src)
            queue = self._pending.get(conn_key)
            if not queue:
                return
            req = queue.pop(0)
            row = {**req, **resp, "response_ts": ts}
            row["latency_s"] = row["response_ts"] - row["request_ts"]
            self._completed.append(row)

    def drain(self, include_unanswered: bool = False) -> list[dict]:
        """Return and clear completed transactions seen since the last
        drain(). In live mode, called periodically (see live/monitor.py)
        rather than only at end-of-capture, so a request that's still
        waiting on a response isn't lost — it just stays in self._pending
        and completes on a later drain() once its response arrives.

        include_unanswered=True also flushes anything still pending as an
        unanswered row (response_ts=None) — the pcap-file equivalent of
        "capture ended, nothing more is coming"; a live monitor never
        wants this, since the response may simply not have arrived yet.
        """
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
        # A guaranteed-unique row identifier, assigned BEFORE sorting so it
        # travels with its row regardless of sort order. This matters
        # because transaction_id is NOT reliably unique on real traffic —
        # confirmed against a real capture where it was 0 for every single
        # request — so anything downstream that needs to re-join this
        # dataframe with a derived one (features, scores) must use row_id,
        # never transaction_id. Merging on a duplicated key silently
        # explodes into a cross join (seen firsthand: a 50k-row real
        # dataframe merged on transaction_id OOM-killed the process).
        df["row_id"] = range(len(df))
        df = df.sort_values("request_ts").reset_index(drop=True)
    return df


def parse_packets(packets) -> pd.DataFrame:
    """Parse an already-loaded iterable of scapy packets (e.g. from
    rdpcap(), or buffered live packets) into one row per transaction."""
    matcher = StreamingModbusMatcher()
    for pkt in packets:
        matcher.process(pkt)
    return _rows_to_df(matcher.drain(include_unanswered=True))


def parse_pcap(path: str) -> pd.DataFrame:
    """Parse a Modbus/TCP pcap file into one row per transaction, with
    full per-function-code register fields. Uses the fast raw reader
    (parser/pcapreader.py) + StreamingModbusMatcher.process_payload() —
    see that method's docstring for why, instead of scapy's rdpcap()."""
    matcher = StreamingModbusMatcher()
    for ts, src, dst, sport, dport, payload in iter_tcp_packets(path):
        matcher.process_payload(ts, src, dst, sport, dport, payload)
    return _rows_to_df(matcher.drain(include_unanswered=True))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python modbus_parser.py <path_to.pcap>")
        sys.exit(1)

    df = parse_pcap(sys.argv[1])
    print(f"Parsed {len(df)} Modbus transactions.")
    print(df.head(10).to_string())
