"""
Side B communication node.

Role: Handshake RESPONDER with forward secrecy.

Forward secrecy protocol (RSA ephemeral key exchange):
  1. B generates a fresh RSA-2048 ephemeral key pair per session
  2. B broadcasts the ephemeral public key signed by its long-term YubiKey
     (EPHEMERAL_OFFER packet)
  3. A encrypts the Fernet session key under B's ephemeral public key
  4. B decrypts with the ephemeral private key, then immediately discards it
  5. Even if B's long-term YubiKey is later compromised, past session keys
     cannot be recovered — the ephemeral private key is gone

Side B never imports from side_a/.
"""

from __future__ import annotations

import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from channel.meshtastic_channel import MeshtasticChannel
from channel.packet import MsgType, fragment
from channel.types import NodeId, RawPayload
from yubikey.interface import YubiKeyInterface

from .keystore import SideBKeystore

_FERNET_TTL_S: int = 300


class SideBNode:
    """
    Side B session node.

    Call offer_ephemeral_key() to broadcast a fresh ephemeral RSA public key
    before each session.  Waits for a HANDSHAKE packet, decrypts the Fernet
    key with the ephemeral private key, then discards it (forward secrecy).
    """

    def __init__(
        self,
        node_id: NodeId,
        yubikey: YubiKeyInterface,
        keystore: SideBKeystore,
        channel: MeshtasticChannel,
    ) -> None:
        self.node_id = node_id
        self._yubikey = yubikey
        self._keystore = keystore
        self._channel = channel

        # Ephemeral RSA key pair — generated fresh per session, discarded after use.
        # None until offer_ephemeral_key() is called.
        self._eph_private_key: RSAPrivateKey | None = None

        self._fernet_key: bytes | None = None
        self._session_lock = threading.Lock()
        self._session_id_counter: int = 0

        channel.subscribe(node_id, self._on_receive)
        print(f"[{self.node_id}] Node started, waiting for ephemeral key offer step.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def offer_ephemeral_key(self) -> None:
        """
        Generate a fresh RSA-2048 ephemeral key pair for the upcoming session,
        sign the public key with the long-term YubiKey, and broadcast it.

        A receives this, verifies the YubiKey signature, and uses the ephemeral
        public key to encrypt the Fernet session key in the subsequent HANDSHAKE.

        EPHEMERAL_OFFER payload layout:
          [4 bytes: sig_len]
          [sig_len bytes: YubiKey PSS signature over the DER-encoded ephemeral public key]
          [N bytes: DER-encoded ephemeral RSA-2048 public key]

        Key generation takes ~50–200 ms for RSA-2048.
        """
        print(f"[{self.node_id}] Generating ephemeral RSA-2048 key pair...")
        eph_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        eph_pub_der = eph_priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Sign the DER bytes with the long-term YubiKey to prove this offer
        # comes from a legitimate, ceremony-authenticated B node.
        signature = self._yubikey.sign(eph_pub_der)
        sig_len = len(signature).to_bytes(4, "big")
        offer_body = sig_len + signature + eph_pub_der

        with self._session_lock:
            self._eph_private_key = eph_priv

        payload = bytes([MsgType.EPHEMERAL_OFFER]) + offer_body
        print(
            f"[{self.node_id}] Broadcasting EPHEMERAL_OFFER "
            f"({len(eph_pub_der)} bytes DER, signed)."
        )
        self._channel.send(self.node_id, payload)

    def send_message(self, plaintext: str) -> None:
        """Fernet-encrypt *plaintext* and broadcast over the channel."""
        with self._session_lock:
            key = self._fernet_key
        if key is None:
            raise RuntimeError(
                f"[{self.node_id}] No session key. Wait for handshake to complete."
            )
        token = Fernet(key).encrypt(plaintext.encode("utf-8"))
        payload = bytes([MsgType.MESSAGE]) + token
        print(
            f"[{self.node_id}] Sending message "
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

        if msg_type == MsgType.HANDSHAKE:
            self._handle_handshake(from_node_id, body)
        elif msg_type == MsgType.MESSAGE:
            self._handle_message(from_node_id, body)
        elif msg_type in (MsgType.ACK, MsgType.EPHEMERAL_OFFER):
            pass  # B does not process its own echoes
        else:
            print(f"[{self.node_id}] Unknown msg_type 0x{msg_type:02X} from {from_node_id}")

    # ------------------------------------------------------------------
    # Handshake handling
    # ------------------------------------------------------------------

    def _handle_handshake(self, from_node_id: NodeId, body: bytes) -> None:
        """
        Verify A's PSS signature, decrypt Fernet key with ephemeral private key,
        then immediately discard the ephemeral private key (forward secrecy).

        Handshake body layout:
          [4 bytes: sig_len][sig_len bytes: A's PSS sig over ciphertext][ciphertext]
        """
        if len(body) < 4:
            print(f"[{self.node_id}] Malformed HANDSHAKE from {from_node_id}: too short")
            return

        sig_len = int.from_bytes(body[:4], "big")
        if len(body) < 4 + sig_len:
            print(f"[{self.node_id}] Malformed HANDSHAKE from {from_node_id}: truncated sig")
            return

        signature = body[4 : 4 + sig_len]
        ciphertext = body[4 + sig_len :]

        if not self._keystore.has_peer(from_node_id):
            print(
                f"[{self.node_id}] Rejected HANDSHAKE from unknown peer {from_node_id}. "
                "Run ceremony first."
            )
            return

        # Verify A's long-term identity via ceremony-registered public key
        peer_pubkey = self._keystore.get_peer_key(from_node_id)
        try:
            peer_pubkey.verify(
                signature,
                ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as exc:
            print(f"[{self.node_id}] Signature verification FAILED from {from_node_id}: {exc}")
            return

        # Decrypt with the ephemeral private key, then discard it immediately.
        with self._session_lock:
            eph_priv = self._eph_private_key
            self._eph_private_key = None  # discard — forward secrecy

        if eph_priv is None:
            print(
                f"[{self.node_id}] No ephemeral key available. "
                "Call offer_ephemeral_key() before the handshake."
            )
            return

        try:
            fernet_key = eph_priv.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            print(f"[{self.node_id}] Fernet key decryption FAILED: {exc}")
            return

        # eph_priv goes out of scope here — Python GC will collect it.
        # The ephemeral private key is now unreachable.
        del eph_priv

        with self._session_lock:
            self._fernet_key = fernet_key

        print(
            f"[{self.node_id}] Handshake OK from {from_node_id}. "
            "Signature verified. Ephemeral key used and discarded. "
            "Session key installed. (Forward secrecy active)"
        )

        ack_payload = bytes([MsgType.ACK])
        self._channel.send(self.node_id, ack_payload)

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

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
