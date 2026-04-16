"""
Side B keystore.

Structurally identical to SideAKeystore — kept separate so Side A and
Side B remain fully independent modules with no cross-imports.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class SideBKeystore:

    def __init__(self) -> None:
        self._peer_public_keys: dict[str, RSAPublicKey] = {}

    def store_peer_key(self, node_id: str, pem: bytes) -> None:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, RSAPublicKey):
            raise TypeError(f"Expected RSAPublicKey, got {type(key)}")
        self._peer_public_keys[node_id] = key

    def get_peer_key(self, node_id: str) -> RSAPublicKey:
        try:
            return self._peer_public_keys[node_id]
        except KeyError:
            raise KeyError(
                f"[SideBKeystore] No key for peer '{node_id}'. "
                "Run the ceremony first."
            )

    def has_peer(self, node_id: str) -> bool:
        return node_id in self._peer_public_keys

    def list_peers(self) -> list[str]:
        return list(self._peer_public_keys.keys())

    @staticmethod
    def fingerprint(pem: bytes) -> str:
        key = serialization.load_pem_public_key(pem)
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest()
        return ":".join(digest[i : i + 2].upper() for i in range(0, len(digest), 2))
