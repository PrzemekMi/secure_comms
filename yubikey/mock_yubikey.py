"""
Software mock of a YubiKey.

Generates an RSA-2048 key pair in memory and implements the full
YubiKeyInterface contract using the cryptography library.  Used for
all tests and demo runs that don't have physical YubiKey hardware.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .interface import YubiKeyInterface


class MockYubiKey(YubiKeyInterface):
    """Pure-software YubiKey substitute for testing and development."""

    def __init__(self, serial: str) -> None:
        self._serial = serial
        self._private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    def get_public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def get_serial(self) -> str:
        return self._serial
