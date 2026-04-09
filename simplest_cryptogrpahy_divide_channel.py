from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class CommsChannel:
    def pass_packet(self, sender: str, receiver: "Side", packet_type: str, payload: bytes) -> None:
        receiver.receive(sender, packet_type, payload)


class Side:

    def __init__(self, name: str, coms_channel: CommsChannel) -> None:
        self.name = name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.coms_channel = coms_channel
        self.ephemeral_key: bytes | None = None
        self.peer_public_keys: dict[str, rsa.RSAPublicKey] = {}

    def register_peer_public_key(self, peer_name: str, peer_public_key: rsa.RSAPublicKey) -> None:
        self.peer_public_keys[peer_name] = peer_public_key

    def send_ephemeral_key(self, receiver: "Side") -> None:
        ephemeral_key = Fernet.generate_key()

        # "Encrypt with private key" equivalent: sign with private key
        signature = self.private_key.sign(
            ephemeral_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Packet format: [4-byte signature length][signature][ephemeral_key]
        packet = len(signature).to_bytes(4, "big") + signature + ephemeral_key

        self.ephemeral_key = ephemeral_key
        self.coms_channel.pass_packet(self.name, receiver, "ephemeral_key", packet)

    def send_message(self, receiver: "Side", message: str) -> None:
        if self.ephemeral_key is None:
            raise RuntimeError(f"{self.name}: missing ephemeral key")

        cipher = Fernet(self.ephemeral_key)
        encrypted_message = cipher.encrypt(message.encode("utf-8"))
        self.coms_channel.pass_packet(self.name, receiver, "message", encrypted_message)

    def receive(self, sender: str, packet_type: str, payload: bytes) -> None:
        if packet_type == "ephemeral_key":
            if sender not in self.peer_public_keys:
                raise RuntimeError(f"{self.name}: missing public key for sender {sender}")

            sender_public_key = self.peer_public_keys[sender]

            if len(payload) < 4:
                raise ValueError("Invalid ephemeral_key packet")
            sig_len = int.from_bytes(payload[:4], "big")
            signature = payload[4 : 4 + sig_len]
            decrypted_key = payload[4 + sig_len :]

            # "Decrypt with public key" equivalent: verify signature with public key
            sender_public_key.verify(
                signature,
                decrypted_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            self.ephemeral_key = decrypted_key
            print(f"[{self.name}] received and verified ephemeral key from {sender}")
            return

        if packet_type == "message":
            if self.ephemeral_key is None:
                raise RuntimeError(f"{self.name}: cannot decrypt, missing ephemeral key")

            cipher = Fernet(self.ephemeral_key)
            plaintext = cipher.decrypt(payload).decode("utf-8")
            print(f"[{self.name}] decoded message from {sender}: {plaintext}")
            return

        raise ValueError(f"Unknown packet type: {packet_type}")


def main() -> None:
    communication_channel = CommsChannel()

    side_a = Side(name="SIDE_A", coms_channel=communication_channel)
    side_b = Side(name="SIDE_B", coms_channel=communication_channel)

    # Each side stores the other side's public key
    side_a.register_peer_public_key("SIDE_B", side_b.public_key)
    side_b.register_peer_public_key("SIDE_A", side_a.public_key)

    side_a.send_ephemeral_key(side_b)

    side_a.send_message(side_b, "Hello from A")
    side_b.send_message(side_a, "Hi A, message received")


if __name__ == "__main__":
    main()