"""
Fast raw pcap + Ethernet/IPv4/TCP reader — no scapy.

scapy's rdpcap() fully dissects every packet through its entire protocol
registry. Measured directly against this project's own real validation
captures: ~30s for the ~104k-packet Modbus-only capture (acceptable, and
what parser/modbus_parser.py still uses), but the 4SICS capture's S7comm
traffic is bigger — ~371k TCP packets on port 102 — and that timed out
past 2 minutes with rdpcap(). This reader extracts only what a protocol
matcher needs (timestamp, IPs, ports, raw TCP payload) via struct, same
technique already proven in ot-radar.html's client-side JS parser — reading
the whole 4SICS-GeekLounge-151022 S7 subset (49MB) takes well under a
second this way.

Supports both classic pcap AND pcapng — found out the hard way that this
matters: one of this project's own bundled real-capture files turned out
to be pcapng (tshark defaults to it since Wireshark ~3.0), which an
earlier version of this reader rejected outright. pcapng is now the
default output format for Wireshark/tshark/dumpcap, so a tool that can't
read it would fail on a lot of real-world captures, not just an edge case.
Ethernet link-layer only, for both formats — same scope as the rest of
this project's parsers.
"""

from __future__ import annotations

import struct
from typing import Iterator

Packet = tuple[float, str, str, int, int, bytes]  # ts, src_ip, dst_ip, sport, dport, tcp_payload

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", False), 0xD4C3B2A1: (">", False),
    0xA1B23C4D: ("<", True), 0x4D3CB2A1: (">", True),
}
_PCAPNG_MAGIC = 0x0A0D0D0A
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

_BLOCK_SECTION_HEADER = 0x0A0D0D0A
_BLOCK_INTERFACE_DESC = 0x00000001
_BLOCK_ENHANCED_PACKET = 0x00000006


def iter_tcp_packets(path: str) -> Iterator[Packet]:
    """Yield one tuple per TCP/IPv4-over-Ethernet packet in a classic pcap
    OR pcapng file: (timestamp, src_ip, dst_ip, src_port, dst_port,
    tcp_payload). Anything else (non-IPv4, non-TCP, truncated) is silently
    skipped, same behavior as the scapy-based parsers' haslayer() checks.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 4:
        return

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == _PCAPNG_MAGIC:
        frames = _iter_pcapng_frames(data)
    elif magic in _PCAP_MAGICS:
        frames = _iter_classic_pcap_frames(data)
    else:
        raise ValueError(
            f"Not a recognized pcap/pcapng file (bad magic 0x{magic:08x}). "
            f"If this came from somewhere unusual, re-save it as pcap or "
            f"pcapng in Wireshark first."
        )

    for ts, pkt in frames:
        row = _parse_ethernet_ipv4_tcp(pkt)
        if row is not None:
            src, dst, sport, dport, payload = row
            yield ts, src, dst, sport, dport, payload


def _parse_ethernet_ipv4_tcp(pkt: bytes):
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack_from(">H", pkt, 12)[0]
    if ethertype != 0x0800:
        return None  # IPv4 only

    ip_off = 14
    if len(pkt) < ip_off + 20:
        return None
    ihl = (pkt[ip_off] & 0x0F) * 4
    proto = pkt[ip_off + 9]
    if proto != 6:
        return None  # TCP only
    src = ".".join(str(b) for b in pkt[ip_off + 12:ip_off + 16])
    dst = ".".join(str(b) for b in pkt[ip_off + 16:ip_off + 20])

    tcp_off = ip_off + ihl
    if len(pkt) < tcp_off + 20:
        return None
    sport, dport = struct.unpack_from(">HH", pkt, tcp_off)
    data_offset = ((pkt[tcp_off + 12] >> 4) & 0x0F) * 4
    payload_off = tcp_off + data_offset
    if payload_off > len(pkt):
        return None

    return src, dst, sport, dport, pkt[payload_off:]


def _iter_classic_pcap_frames(data: bytes):
    magic = struct.unpack_from("<I", data, 0)[0]
    endian, nano = _PCAP_MAGICS[magic]

    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        raise ValueError(f"Unsupported link type ({linktype}) — only Ethernet captures are supported.")

    off = 24
    total_len = len(data)
    divisor = 1e9 if nano else 1e6

    while off + 16 <= total_len:
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + incl_len > total_len:
            break
        yield ts_sec + ts_sub / divisor, data[off:off + incl_len]
        off += incl_len


def _iter_pcapng_frames(data: bytes):
    """Minimal pcapng reader: Section Header, Interface Description, and
    Enhanced Packet blocks only — the three block types every modern
    tshark/dumpcap capture actually uses for plain Ethernet traffic. Other
    block types (Name Resolution, Interface Statistics, obsolete Simple
    Packet Blocks with no per-packet timestamp) are skipped by their
    declared length rather than understood, which is enough to not get
    lost, even if this reader doesn't use what's in them.
    """
    off = 0
    total_len = len(data)
    endian = "<"  # overwritten per-section by the Section Header Block's byte-order magic
    # Per-interface timestamp resolution (seconds per tick), indexed by
    # interface id in declaration order — required because EPB timestamps
    # are meaningless without it, and it's an *option* (not fixed), so it
    # must be tracked, not assumed.
    if_tsresol: list[float] = []

    while off + 8 <= total_len:
        block_type = struct.unpack_from("<I", data, off)[0]  # block type is always little-endian-read first
        if block_type == _BLOCK_SECTION_HEADER:
            # Body: byte-order-magic(4) tells endianness for the rest of this section.
            bom = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bom == _PCAPNG_BYTE_ORDER_MAGIC else ">"
            if_tsresol = []  # interface ids restart within a new section

        block_len = struct.unpack_from(endian + "I", data, off + 4)[0]
        if block_len < 12 or off + block_len > total_len:
            break  # truncated/corrupt trailing block — stop rather than misread past the end
        body = data[off + 8: off + block_len - 4]

        if block_type == _BLOCK_INTERFACE_DESC:
            if_tsresol.append(_parse_if_tsresol(body, endian))
        elif block_type == _BLOCK_ENHANCED_PACKET:
            frame = _parse_enhanced_packet_block(body, endian, if_tsresol)
            if frame is not None:
                yield frame
        # Other block types (Name Resolution 0x4, Interface Statistics
        # 0x5, Simple Packet 0x3 with no timestamp, custom blocks, etc.)
        # are intentionally skipped — advancing by block_len is enough.

        off += block_len


def _parse_if_tsresol(idb_body: bytes, endian: str) -> float:
    """Default timestamp resolution per the pcapng spec is 10^-6 (microsecond)
    when an interface declares no if_tsresol option."""
    options = idb_body[8:]  # linktype(2) + reserved(2) + snaplen(4) precede options
    opt_off = 0
    while opt_off + 4 <= len(options):
        opt_code, opt_len = struct.unpack_from(endian + "HH", options, opt_off)
        if opt_code == 0:  # opt_endofopt
            break
        val_off = opt_off + 4
        if opt_code == 9 and opt_len >= 1:  # if_tsresol
            raw = options[val_off]
            exponent = raw & 0x7F
            return 2.0 ** -exponent if raw & 0x80 else 10.0 ** -exponent
        opt_off = val_off + ((opt_len + 3) // 4) * 4  # options are padded to 4-byte boundaries
    return 1e-6


def _parse_enhanced_packet_block(epb_body: bytes, endian: str, if_tsresol: list[float]):
    if len(epb_body) < 20:
        return None
    iface_id, ts_high, ts_low, incl_len, _orig_len = struct.unpack_from(endian + "IIIII", epb_body, 0)
    if incl_len > len(epb_body) - 20:
        return None
    tsresol = if_tsresol[iface_id] if iface_id < len(if_tsresol) else 1e-6
    ts = ((ts_high << 32) | ts_low) * tsresol
    pkt = epb_body[20:20 + incl_len]
    return ts, pkt
