"""
Real YubiKey integration stub.

Requires yubikey-manager (ykman) to be installed:
  pip install yubikey-manager

Uses PIV slot 9a (Authentication) for all signing operations.
The RSA-2048 private key is generated on the device and never exported.

To generate a key on the YubiKey before first use:
  ykman piv keys generate --algorithm RSA2048 9a pubkey.pem
  ykman piv certificates generate --subject "CN=SecureComms" 9a pubkey.pem

Each method below shows the equivalent ykman CLI command as a comment
so you can test individual operations at the shell before wiring them up.
"""

from __future__ import annotations

from .interface import YubiKeyInterface


class RealYubiKey(YubiKeyInterface):
    """
    Production YubiKey driver.  Wire the NotImplementedError stubs to
    ykman Python API calls (yubikit) once you have physical hardware.
    """

    def __init__(self, serial: str) -> None:
        self._serial = serial
        # TODO: open device connection
        #   from yubikit.core.smartcard import SmartCardConnection
        #   from yubikit.piv import PivSession
        #   device = connect_to_device(serial)[0]
        #   self._connection = device.open_connection(SmartCardConnection)
        #   self._piv = PivSession(self._connection)

    def get_public_key_pem(self) -> bytes:
        """
        Export the public key from PIV slot 9a.

        CLI equivalent:
          ykman piv keys export 9a -        # prints PEM to stdout

        Python (yubikit):
          from yubikit.piv import SLOT
          cert = self._piv.get_certificate(SLOT.AUTHENTICATION)
          return cert.public_key().public_bytes(PEM, SubjectPublicKeyInfo)
        """
        raise NotImplementedError(
            "Wire to: ykman piv keys export 9a -\n"
            "See yubikit.piv.PivSession.get_certificate(SLOT.AUTHENTICATION)"
        )

    def sign(self, data: bytes) -> bytes:
        """
        Sign *data* with RSA-PSS using the private key in slot 9a.

        The YubiKey expects a SHA-256 digest, not raw data.

        CLI equivalent:
          echo -n '<data>' | openssl dgst -sha256 -binary | \\
          ykman piv sign 9a RSA2048 -

        Python (yubikit):
          import hashlib
          from yubikit.piv import SLOT, KEY_TYPE, HASH_ALGORITHM
          digest = hashlib.sha256(data).digest()
          return self._piv.sign(
              SLOT.AUTHENTICATION,
              KEY_TYPE.RSA2048,
              digest,
              HASH_ALGORITHM.SHA256,
          )
        """
        raise NotImplementedError(
            "Wire to ykman piv sign 9a RSA2048 <digest>\n"
            "See yubikit.piv.PivSession.sign()"
        )

    def get_serial(self) -> str:
        """
        CLI equivalent:
          ykman info   # shows Serial number

        Python (yubikit):
          from yubikit.management import ManagementSession
          mgmt = ManagementSession(self._connection)
          return str(mgmt.get_device_info().serial)
        """
        return self._serial
