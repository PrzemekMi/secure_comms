"""
Abstract YubiKey interface.

Both MockYubiKey (software RSA) and RealYubiKey (ykman PIV slot 9a)
implement this contract.  The rest of the system only ever holds a
YubiKeyInterface reference, so swapping mock ↔ real requires zero
changes to node or ceremony code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class YubiKeyInterface(ABC):

    @abstractmethod
    def get_public_key_pem(self) -> bytes:
        """
        Return the RSA-2048 public key in PEM format.
        Called during the in-person ceremony to export the key for the peer.
        """

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Sign *data* using RSA-PSS with MGF1-SHA256 and maximum salt length.
        Returns raw DER signature bytes (256 bytes for RSA-2048).
        The private key never leaves the device.
        """

    @abstractmethod
    def get_serial(self) -> str:
        """
        Return a unique device identifier string.
        Used as the node_id on the Meshtastic channel.
        """
