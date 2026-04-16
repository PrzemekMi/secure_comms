"""
In-person key exchange ceremony.

Both operators are physically present (or both MockYubiKeys are in the same
test process).  Each side exports its YubiKey public key and stores the
other's key into their own keystore.  No network, no CA.

Trust model
-----------
After run() completes, both operators should read aloud (or compare on screen)
the SHA-256 fingerprints printed by this script.  If they match what each
party independently computed, the exchange is trusted.

Usage
-----
    from ceremony.ceremony import CeremonyOrchestrator
    from yubikey.mock_yubikey import MockYubiKey
    from side_a.keystore import SideAKeystore
    from side_b.keystore import SideBKeystore

    yk_a = MockYubiKey("node_a")
    yk_b = MockYubiKey("node_b")
    ks_a = SideAKeystore()
    ks_b = SideBKeystore()

    ceremony = CeremonyOrchestrator(
        node_a_id="node_a", yubikey_a=yk_a, keystore_a=ks_a,
        node_b_id="node_b", yubikey_b=yk_b, keystore_b=ks_b,
    )
    ceremony.run()
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization

from side_a.keystore import SideAKeystore
from side_b.keystore import SideBKeystore
from yubikey.interface import YubiKeyInterface


class CeremonyOrchestrator:
    """Drives the one-time bilateral public-key exchange."""

    def __init__(
        self,
        node_a_id: str,
        yubikey_a: YubiKeyInterface,
        keystore_a: SideAKeystore,
        node_b_id: str,
        yubikey_b: YubiKeyInterface,
        keystore_b: SideBKeystore,
    ) -> None:
        self._node_a_id = node_a_id
        self._yubikey_a = yubikey_a
        self._keystore_a = keystore_a
        self._node_b_id = node_b_id
        self._yubikey_b = yubikey_b
        self._keystore_b = keystore_b

    def run(self) -> None:
        """
        Exchange public keys between both sides.

        Steps:
          1. Export A's public key PEM → store in B's keystore
          2. Export B's public key PEM → store in A's keystore
          3. Print fingerprints for visual out-of-band verification
        """
        print("\n" + "=" * 60)
        print("  KEY EXCHANGE CEREMONY")
        print("=" * 60)
        print("Both operators must be physically present.")
        print("Compare the fingerprints below out-of-band.\n")

        pem_a = self._yubikey_a.get_public_key_pem()
        pem_b = self._yubikey_b.get_public_key_pem()

        # Cross-store
        self._keystore_b.store_peer_key(self._node_a_id, pem_a)
        self._keystore_a.store_peer_key(self._node_b_id, pem_b)

        fp_a = self._fingerprint(pem_a)
        fp_b = self._fingerprint(pem_b)

        print(f"  {self._node_a_id} public key fingerprint (SHA-256):")
        print(f"    {fp_a}\n")
        print(f"  {self._node_b_id} public key fingerprint (SHA-256):")
        print(f"    {fp_b}\n")
        print("Ceremony complete. Verify fingerprints before proceeding.")
        print("=" * 60 + "\n")

    @staticmethod
    def _fingerprint(pem: bytes) -> str:
        key = serialization.load_pem_public_key(pem)
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest()
        return ":".join(digest[i : i + 2].upper() for i in range(0, len(digest), 2))
