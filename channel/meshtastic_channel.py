"""
Mock Meshtastic transport layer.

Simulates the key characteristics of a Meshtastic LoRa mesh channel:
  - Max 227-byte physical packet payload
  - Broadcast delivery: every subscriber except the sender receives each message
  - Configurable one-way latency (ms)
  - Per-fragment packet loss (probability-based)
  - Transparent fragmentation / reassembly

Usage
-----
    channel = MeshtasticChannel(latency_ms=100, packet_loss_pct=5)
    channel.subscribe("node_a", callback_a)
    channel.subscribe("node_b", callback_b)
    channel.send("node_a", large_payload)   # returns immediately
    # callback_b fires after latency with the reassembled payload
"""

from __future__ import annotations

import random
import threading
import time
from collections import defaultdict
from typing import Optional

from .packet import FramedPacket, fragment, parse_packet, reassemble
from .types import NodeId, RawPayload, SubscriberCallback

_BUFFER_TIMEOUT_S: float = 30.0


class MeshtasticChannel:
    """Thread-safe mock broadcast channel with Meshtastic constraints."""

    def __init__(
        self,
        latency_ms: float = 200.0,
        packet_loss_pct: float = 0.0,
        seed: Optional[int] = None,
    ) -> None:
        self.latency_ms = latency_ms
        self.packet_loss_pct = packet_loss_pct
        self._rng = random.Random(seed)
        self._lock = threading.Lock()

        # node_id → callback
        self._subscribers: dict[NodeId, SubscriberCallback] = {}

        # Reassembly buffers:
        #   receiver_id → (sender_id, session_id) → list[FramedPacket | None]
        self._buffers: dict[
            NodeId, dict[tuple[NodeId, int], list[Optional[FramedPacket]]]
        ] = defaultdict(dict)

        # Buffer timestamps for timeout eviction:
        #   receiver_id → (sender_id, session_id) → float (unix time)
        self._buffer_timestamps: dict[NodeId, dict[tuple[NodeId, int], float]] = (
            defaultdict(dict)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self, node_id: NodeId, callback: SubscriberCallback) -> None:
        with self._lock:
            self._subscribers[node_id] = callback

    def unsubscribe(self, node_id: NodeId) -> None:
        with self._lock:
            self._subscribers.pop(node_id, None)

    def send(self, from_node_id: NodeId, payload: RawPayload) -> None:
        """
        Broadcast *payload* from *from_node_id* to all other subscribers.
        Returns immediately; delivery happens in a background daemon thread.
        """
        session_id = self._rng.randint(0, 65535)
        # Determine msg_type from first byte of payload if already framed,
        # but here payload is the *logical* message (unframed); we use
        # msg_type=0x00 at the channel level — the actual msg_type is
        # embedded by the node layer inside the payload body.
        # Fragment using msg_type=0x00 as a transport envelope.
        from .packet import MsgType
        raw_fragments = fragment(0x00, session_id, payload)

        surviving = []
        for raw in raw_fragments:
            if self._rng.uniform(0, 100) < self.packet_loss_pct:
                print(
                    f"  [channel] fragment {raw_fragments.index(raw)} "
                    f"of session 0x{session_id:04X} from {from_node_id} "
                    f"lost (simulated {self.packet_loss_pct:.0f}% loss)"
                )
            else:
                surviving.append(raw)

        if not surviving:
            return

        delay_s = self.latency_ms / 1000.0

        def _deliver() -> None:
            time.sleep(delay_s)
            with self._lock:
                receivers = {
                    nid: cb
                    for nid, cb in self._subscribers.items()
                    if nid != from_node_id
                }
            for raw in surviving:
                for receiver_id, callback in receivers.items():
                    self._deliver_fragment(from_node_id, receiver_id, raw, callback)

        t = threading.Thread(target=_deliver, daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _deliver_fragment(
        self,
        from_node_id: NodeId,
        receiver_id: NodeId,
        raw_fragment: bytes,
        callback: SubscriberCallback,
    ) -> None:
        try:
            pkt = parse_packet(raw_fragment)
        except ValueError as exc:
            print(f"  [channel] malformed fragment from {from_node_id}: {exc}")
            return

        key = (from_node_id, pkt.session_id)
        now = time.monotonic()

        with self._lock:
            self._evict_stale(receiver_id, now)

            buf = self._buffers[receiver_id]
            ts_map = self._buffer_timestamps[receiver_id]

            if key not in buf:
                buf[key] = [None] * pkt.fragment_total
                ts_map[key] = now

            slot_list = buf[key]
            if pkt.fragment_index < len(slot_list):
                slot_list[pkt.fragment_index] = pkt

            # Check if all fragments arrived
            if all(slot is not None for slot in slot_list):
                complete_fragments: list[FramedPacket] = slot_list  # type: ignore[assignment]
                del buf[key]
                del ts_map[key]
            else:
                complete_fragments = []

        if complete_fragments:
            try:
                payload = reassemble(complete_fragments)
            except ValueError as exc:
                print(f"  [channel] reassembly failed for {key}: {exc}")
                return
            callback(from_node_id, payload)

    def _evict_stale(self, receiver_id: NodeId, now: float) -> None:
        """Remove buffer entries older than _BUFFER_TIMEOUT_S. Called under lock."""
        ts_map = self._buffer_timestamps.get(receiver_id, {})
        stale = [k for k, t in ts_map.items() if now - t > _BUFFER_TIMEOUT_S]
        buf = self._buffers.get(receiver_id, {})
        for k in stale:
            buf.pop(k, None)
            ts_map.pop(k, None)
