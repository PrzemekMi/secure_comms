"""
Side A keystore.

Stores peer public keys loaded during the in-person ceremony.
Side A's own private key lives on the YubiKey and is never stored here.

This keystore is intentionally in-memory.  For persistence, serialize
_peer_public_keys to JSON (DER base64) and load on startup.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class SideAKeystore:

    def __init__(self) -> None:
        self._peer_public_keys: dict[str, RSAPublicKey] = {}

    def store_peer_key(self, node_id: str, pem: bytes) -> None:
        """Deserialize PEM and store under *node_id*. Called during ceremony."""
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, RSAPublicKey):
            raise TypeError(f"Expected RSAPublicKey, got {type(key)}")
        self._peer_public_keys[node_id] = key

    def get_peer_key(self, node_id: str) -> RSAPublicKey:
        """Retrieve stored peer key. Raises KeyError if not found."""
        try:
            return self._peer_public_keys[node_id]
        except KeyError:
            raise KeyError(
                f"[SideAKeystore] No key for peer '{node_id}'. "
                "Run the ceremony first."
            )

    def has_peer(self, node_id: str) -> bool:
        return node_id in self._peer_public_keys

    def list_peers(self) -> list[str]:
        return list(self._peer_public_keys.keys())

    @staticmethod
    def fingerprint(pem: bytes) -> str:
        """SHA-256 fingerprint of the DER-encoded public key, colon-separated octets."""
        key = serialization.load_pem_public_key(pem)
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest()
        return ":".join(digest[i : i + 2].upper() for i in range(0, len(digest), 2))
