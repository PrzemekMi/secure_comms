from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class MockRelay:
	def pass_packet(self, sender: str, receiver: "Side", packet_type: str, payload: bytes) -> None:
		receiver.receive(sender, packet_type, payload)


@dataclass
class Side:
	name: str
	relay: MockRelay

	def __post_init__(self) -> None:
		self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		self.public_key = self.private_key.public_key()
		self.ephemeral_key: bytes | None = None

	def send_ephemeral_key(self, receiver: "Side") -> None:
		ephemeral_key = Fernet.generate_key()
		encrypted_key = receiver.public_key.encrypt(
			ephemeral_key,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None,
			),
		)
		self.ephemeral_key = ephemeral_key
		self.relay.pass_packet(self.name, receiver, "ephemeral_key", encrypted_key)

	def send_message(self, receiver: "Side", message: str) -> None:
		if self.ephemeral_key is None:
			raise RuntimeError(f"{self.name}: missing ephemeral key")

		cipher = Fernet(self.ephemeral_key)
		encrypted_message = cipher.encrypt(message.encode("utf-8"))
		self.relay.pass_packet(self.name, receiver, "message", encrypted_message)

	def receive(self, sender: str, packet_type: str, payload: bytes) -> None:
		if packet_type == "ephemeral_key":
			decrypted_key = self.private_key.decrypt(
				payload,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None,
				),
			)
			self.ephemeral_key = decrypted_key
			print(f"[{self.name}] received and decrypted ephemeral key from {sender}")
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
	relay = MockRelay()

	side_a = Side(name="SIDE_A", relay=relay)
	side_b = Side(name="SIDE_B", relay=relay)

	side_a.send_ephemeral_key(side_b)

	side_a.send_message(side_b, "Hello from A")
	side_b.send_message(side_a, "Hi A, message received")


if __name__ == "__main__":
	main()
