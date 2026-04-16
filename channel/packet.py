"""
Packet framing and fragmentation for the mock Meshtastic channel.

Wire frame layout (max 227 bytes per physical packet):

  Offset  Size  Field           Description
  ------  ----  -----           -----------
  0       1     msg_type        0x01=HANDSHAKE  0x02=MESSAGE  0x03=ACK  0x04=EPHEMERAL_OFFER
  1       2     session_id      uint16 big-endian; unique per logical send
  3       2     fragment_index  uint16 big-endian; 0-based
  5       2     fragment_total  uint16 big-endian; total fragment count
  7       220   body            up to 220 bytes of payload fragment

Header = 7 bytes.  Max body = 220 bytes.  Total <= 227 bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAX_PACKET_BYTES: int = 227
HEADER_SIZE: int = 7          # 1 + 2 + 2 + 2
MAX_BODY_BYTES: int = MAX_PACKET_BYTES - HEADER_SIZE   # 220
_HEADER_FMT = ">BHHH"        # big-endian: uint8, uint16, uint16, uint16


class MsgType:
    HANDSHAKE: int = 0x01
    MESSAGE: int = 0x02
    ACK: int = 0x03
    EPHEMERAL_OFFER: int = 0x04  # B broadcasts a per-session ephemeral RSA public key


@dataclass
class FramedPacket:
    msg_type: int
    session_id: int       # 0–65535
    fragment_index: int   # 0-based
    fragment_total: int   # >= 1
    body: bytes


# ---------------------------------------------------------------------------
# Low-level encode / decode
# ---------------------------------------------------------------------------

def frame_packet(
    msg_type: int,
    session_id: int,
    fragment_index: int,
    fragment_total: int,
    body: bytes,
) -> bytes:
    """Serialize one FramedPacket to wire bytes (<= 227 bytes)."""
    if len(body) > MAX_BODY_BYTES:
        raise ValueError(
            f"body too large: {len(body)} > {MAX_BODY_BYTES}"
        )
    header = struct.pack(_HEADER_FMT, msg_type, session_id, fragment_index, fragment_total)
    return header + body


def parse_packet(raw: bytes) -> FramedPacket:
    """Deserialize wire bytes into a FramedPacket. Raises ValueError on malformed input."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"packet too short: {len(raw)} bytes")
    msg_type, session_id, fragment_index, fragment_total = struct.unpack_from(
        _HEADER_FMT, raw, 0
    )
    body = raw[HEADER_SIZE:]
    if len(body) > MAX_BODY_BYTES:
        raise ValueError(f"body exceeds max: {len(body)} bytes")
    return FramedPacket(
        msg_type=msg_type,
        session_id=session_id,
        fragment_index=fragment_index,
        fragment_total=fragment_total,
        body=body,
    )


# ---------------------------------------------------------------------------
# Fragmentation / reassembly
# ---------------------------------------------------------------------------

def fragment(msg_type: int, session_id: int, data: bytes) -> list[bytes]:
    """
    Split *data* into wire-ready fragments.

    Returns a list of raw byte strings each <= MAX_PACKET_BYTES.
    *session_id* must be a uint16 chosen by the caller (e.g. random.randint(0, 65535)).
    """
    if not data:
        # One empty fragment
        return [frame_packet(msg_type, session_id, 0, 1, b"")]

    chunks: list[bytes] = [
        data[i : i + MAX_BODY_BYTES] for i in range(0, len(data), MAX_BODY_BYTES)
    ]
    total = len(chunks)
    return [
        frame_packet(msg_type, session_id, idx, total, chunk)
        for idx, chunk in enumerate(chunks)
    ]


def reassemble(fragments: list[FramedPacket]) -> bytes:
    """
    Reassemble a complete logical message from its FramedPackets.

    The list may be in any order; all fragments must be present.
    Raises ValueError if any fragment is missing or counts mismatch.
    """
    if not fragments:
        raise ValueError("no fragments supplied")

    total = fragments[0].fragment_total
    if any(f.fragment_total != total for f in fragments):
        raise ValueError("fragment_total mismatch across fragments")

    if len(fragments) != total:
        raise ValueError(
            f"expected {total} fragments, got {len(fragments)}"
        )

    ordered = sorted(fragments, key=lambda f: f.fragment_index)
    for expected_idx, pkt in enumerate(ordered):
        if pkt.fragment_index != expected_idx:
            raise ValueError(
                f"missing fragment at index {expected_idx}"
            )

    return b"".join(pkt.body for pkt in ordered)
