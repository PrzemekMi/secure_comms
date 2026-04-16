"""
Side A communication node.

Role: Handshake INITIATOR with forward secrecy.

Forward secrecy protocol (RSA ephemeral key exchange):
  1. A waits for an EPHEMERAL_OFFER from B (a fresh per-session RSA public key
     signed by B's long-term YubiKey)
  2. A verifies B's YubiKey signature on the ephemeral public key
  3. A encrypts the Fernet session key under B's ephemeral public key (not the
     long-term key), then signs the ciphertext with A's own YubiKey
  4. A broadcasts the HANDSHAKE

Because the Fernet key is encrypted under an ephemeral key that B will discard,
compromising B's long-term YubiKey later cannot reveal past session keys.

Side A never imports from side_b/.
"""

from __future__ import annotations

import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from channel.meshtastic_channel import MeshtasticChannel
from channel.packet import MsgType, fragment
from channel.types import NodeId, RawPayload
from yubikey.interface import YubiKeyInterface

from .keystore import SideAKeystore

_FERNET_TTL_S: int = 300


class SideANode:
    """
    Side A session node.

    Waits for EPHEMERAL_OFFER from the peer, then initiates the handshake
    using the peer's ephemeral public key for Fernet key encapsulation.
    """

    def __init__(
        self,
        node_id: NodeId,
        yubikey: YubiKeyInterface,
        keystore: SideAKeystore,
        channel: MeshtasticChannel,
    ) -> None:
        self.node_id = node_id
        self._yubikey = yubikey
        self._keystore = keystore
        self._channel = channel

        self._fernet_key: bytes | None = None
        self._peer_ready: bool = False

        # Per-peer ephemeral public keys received via EPHEMERAL_OFFER.
        # Keyed by peer node_id.  Cleared after use in initiate_handshake().
        self._peer_ephemeral_keys: dict[NodeId, RSAPublicKey] = {}

        self._session_lock = threading.Lock()
        self._session_id_counter: int = 0

        channel.subscribe(node_id, self._on_receive)
        print(f"[{self.node_id}] Node started.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initiate_handshake(self, peer_node_id: NodeId) -> None:
        """
        Encrypt the Fernet session key under the peer's ephemeral RSA public key
        (received via EPHEMERAL_OFFER), sign the ciphertext with A's YubiKey,
        and broadcast as a HANDSHAKE packet.

        Requires: peer_node_id has previously sent an EPHEMERAL_OFFER.

        Handshake payload layout:
          [1 byte: MsgType.HANDSHAKE]
          [4 bytes: sig_len]
          [sig_len bytes: A's YubiKey PSS signature over the ciphertext]
          [256 bytes: RSA-OAEP ciphertext of Fernet key under peer's ephemeral key]
        """
        if not self._keystore.has_peer(peer_node_id):
            raise RuntimeError(
                f"[{self.node_id}] No long-term key for {peer_node_id}. "
                "Run ceremony first."
            )

        with self._session_lock:
            eph_pub = self._peer_ephemeral_keys.get(peer_node_id)

        if eph_pub is None:
            raise RuntimeError(
                f"[{self.node_id}] No ephemeral key from {peer_node_id}. "
                "Wait for EPHEMERAL_OFFER or call node_b.offer_ephemeral_key()."
            )

        # Step 1: generate Fernet key
        fernet_key = Fernet.generate_key()

        # Step 2: encrypt under the peer's EPHEMERAL public key (not long-term)
        ciphertext = eph_pub.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Step 3: sign the ciphertext with A's long-term YubiKey (authentication)
        signature = self._yubikey.sign(ciphertext)
        sig_len = len(signature).to_bytes(4, "big")
        handshake_body = sig_len + signature + ciphertext

        # Step 4: broadcast
        payload = bytes([MsgType.HANDSHAKE]) + handshake_body
        raw_fragments = fragment(0x00, self._next_session_id(), payload)
        print(
            f"[{self.node_id}] Sending HANDSHAKE to {peer_node_id} "
            f"({len(raw_fragments)} fragment(s)) — encrypted under ephemeral key."
        )
        self._channel.send(self.node_id, payload)

        with self._session_lock:
            self._fernet_key = fernet_key
            self._peer_ready = False
            # Ephemeral key used — remove it so it can't be reused for another session
            self._peer_ephemeral_keys.pop(peer_node_id, None)

    def send_message(self, plaintext: str) -> None:
        """Fernet-encrypt *plaintext* and broadcast over the channel."""
        with self._session_lock:
            key = self._fernet_key
        if key is None:
            raise RuntimeError(
                f"[{self.node_id}] No session key. Call initiate_handshake() first."
            )
        token = Fernet(key).encrypt(plaintext.encode("utf-8"))
        payload = bytes([MsgType.MESSAGE]) + token
        print(
            f"[{self.node_id}] Sending MESSAGE "
            f"({len(token)} bytes encrypted): {plaintext!r}"
        )
        self._channel.send(self.node_id, payload)

    # ------------------------------------------------------------------
    # Channel callback
    # ------------------------------------------------------------------

    def _on_receive(self, from_node_id: NodeId, payload: RawPayload) -> None:
        if not payload:
            return
        msg_type = payload[0]
        body = payload[1:]

        if msg_type == MsgType.EPHEMERAL_OFFER:
            self._handle_ephemeral_offer(from_node_id, body)
        elif msg_type == MsgType.ACK:
            self._handle_ack(from_node_id)
        elif msg_type == MsgType.MESSAGE:
            self._handle_message(from_node_id, body)
        elif msg_type == MsgType.HANDSHAKE:
            pass  # A does not respond to incoming handshakes
        else:
            print(f"[{self.node_id}] Unknown msg_type 0x{msg_type:02X} from {from_node_id}")

    # ------------------------------------------------------------------
    # EPHEMERAL_OFFER handling
    # ------------------------------------------------------------------

    def _handle_ephemeral_offer(self, from_node_id: NodeId, body: bytes) -> None:
        """
        Verify the long-term YubiKey signature on the offered ephemeral public key,
        then store the ephemeral public key for use in initiate_handshake().

        EPHEMERAL_OFFER body layout:
          [4 bytes: sig_len]
          [sig_len bytes: sender's YubiKey PSS signature over DER ephemeral public key]
          [N bytes: DER-encoded ephemeral RSA-2048 public key]
        """
        if not self._keystore.has_peer(from_node_id):
            print(
                f"[{self.node_id}] Ignored EPHEMERAL_OFFER from unknown peer {from_node_id}."
            )
            return

        if len(body) < 4:
            print(f"[{self.node_id}] Malformed EPHEMERAL_OFFER from {from_node_id}: too short")
            return

        sig_len = int.from_bytes(body[:4], "big")
        if len(body) < 4 + sig_len:
            print(f"[{self.node_id}] Malformed EPHEMERAL_OFFER from {from_node_id}: truncated sig")
            return

        signature = body[4 : 4 + sig_len]
        eph_pub_der = body[4 + sig_len :]

        # Verify using the sender's long-term ceremony key
        peer_long_term_key = self._keystore.get_peer_key(from_node_id)
        try:
            peer_long_term_key.verify(
                signature,
                eph_pub_der,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as exc:
            print(
                f"[{self.node_id}] EPHEMERAL_OFFER signature FAILED from {from_node_id}: {exc}"
            )
            return

        eph_pub = serialization.load_der_public_key(eph_pub_der)
        if not isinstance(eph_pub, RSAPublicKey):
            print(f"[{self.node_id}] EPHEMERAL_OFFER from {from_node_id}: not an RSA key")
            return

        with self._session_lock:
            self._peer_ephemeral_keys[from_node_id] = eph_pub

        print(
            f"[{self.node_id}] EPHEMERAL_OFFER accepted from {from_node_id}. "
            "Signature OK. Ready to initiate handshake."
        )

    # ------------------------------------------------------------------
    # ACK / Message handling
    # ------------------------------------------------------------------

    def _handle_ack(self, from_node_id: NodeId) -> None:
        with self._session_lock:
            self._peer_ready = True
        print(f"[{self.node_id}] ACK received from {from_node_id}. Peer is ready.")

    def _handle_message(self, from_node_id: NodeId, token: bytes) -> None:
        with self._session_lock:
            key = self._fernet_key
        if key is None:
            print(f"[{self.node_id}] Cannot decrypt: no session key yet.")
            return
        try:
            plaintext = Fernet(key).decrypt(token, ttl=_FERNET_TTL_S).decode("utf-8")
            print(f"[{self.node_id}] Message from {from_node_id}: {plaintext!r}")
        except InvalidToken:
            print(
                f"[{self.node_id}] InvalidToken from {from_node_id}: "
                "message tampered, replayed, or expired."
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_session_id(self) -> int:
        with self._session_lock:
            self._session_id_counter = (self._session_id_counter + 1) % 65536
            return self._session_id_counter
