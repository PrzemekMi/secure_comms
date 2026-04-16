"""
Secure Comms — Demo / Test Environment

Usage
-----
Automated smoke test (no interaction required):
    python demo/demo.py --auto

Interactive CLI:
    python demo/demo.py

Interactive commands
--------------------
  ceremony              Run the in-person key exchange with MockYubiKeys
  offer                 B generates & broadcasts a fresh ephemeral RSA key (forward secrecy)
  handshake             A initiates handshake using B's ephemeral key
  send a <message>      Side A sends an encrypted message
  send b <message>      Side B sends an encrypted message
  loss <pct>            Set channel packet_loss_pct (0–100)
  latency <ms>          Set channel latency_ms
  status                Print session state
  help                  Show this help
  quit / exit           Exit

Session order: ceremony -> offer -> handshake -> send

Every crypto step is printed as it happens.
"""

from __future__ import annotations

import sys
import time

sys.path.insert(0, __file__.replace("/demo/demo.py", "").replace("\\demo\\demo.py", ""))

from ceremony.ceremony import CeremonyOrchestrator
from channel.meshtastic_channel import MeshtasticChannel
from side_a.keystore import SideAKeystore
from side_a.node import SideANode
from side_b.keystore import SideBKeystore
from side_b.node import SideBNode
from yubikey.mock_yubikey import MockYubiKey


NODE_A_ID = "node_a"
NODE_B_ID = "node_b"


def build_environment(latency_ms: float = 100.0, packet_loss_pct: float = 0.0):
    yk_a = MockYubiKey(NODE_A_ID)
    yk_b = MockYubiKey(NODE_B_ID)
    ks_a = SideAKeystore()
    ks_b = SideBKeystore()
    channel = MeshtasticChannel(latency_ms=latency_ms, packet_loss_pct=packet_loss_pct)
    node_a = SideANode(node_id=NODE_A_ID, yubikey=yk_a, keystore=ks_a, channel=channel)
    node_b = SideBNode(node_id=NODE_B_ID, yubikey=yk_b, keystore=ks_b, channel=channel)
    ceremony = CeremonyOrchestrator(
        node_a_id=NODE_A_ID, yubikey_a=yk_a, keystore_a=ks_a,
        node_b_id=NODE_B_ID, yubikey_b=yk_b, keystore_b=ks_b,
    )
    return channel, node_a, node_b, ceremony


def run_auto() -> None:
    """Fully automated smoke test — no user input required."""
    print("\n" + "=" * 60)
    print("  AUTOMATED SMOKE TEST")
    print("=" * 60)

    channel, node_a, node_b, ceremony = build_environment(latency_ms=50)

    # --- Ceremony ---
    ceremony.run()

    # --- Ephemeral key offer (forward secrecy) ---
    print("\n[demo] B offers ephemeral key (forward secrecy)...")
    node_b.offer_ephemeral_key()
    time.sleep(0.3)  # allow async delivery of EPHEMERAL_OFFER to A

    # --- Handshake ---
    print("\n[demo] A initiates handshake using B's ephemeral key...")
    node_a.initiate_handshake(NODE_B_ID)
    time.sleep(0.5)  # allow async delivery

    # --- Messaging ---
    print("\n[demo] Side A -> Side B:")
    node_a.send_message("Hello from Alpha")
    time.sleep(0.3)

    node_a.send_message("The channel is encrypted end-to-end")
    time.sleep(0.3)

    print("\n[demo] Side B -> Side A:")
    node_b.send_message("Hello back from Bravo")
    time.sleep(0.3)

    node_b.send_message("Acknowledged, over and out")
    time.sleep(0.3)

    # --- Packet loss demo ---
    print("\n[demo] Setting 40% packet loss...")
    channel.packet_loss_pct = 40.0
    channel._rng.seed(42)

    node_a.send_message("Will this survive 40% loss?")
    time.sleep(0.5)

    channel.packet_loss_pct = 0.0

    print("\n[demo] Smoke test complete.")
    print("=" * 60 + "\n")


def run_interactive() -> None:
    channel, node_a, node_b, ceremony = build_environment()
    ceremony_done = False

    print("\nSecure Comms interactive environment.")
    print("Type 'help' for available commands.\n")

    while True:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not raw:
            continue

        parts = raw.split(maxsplit=2)
        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            print("Bye.")
            break

        elif cmd == "help":
            print(__doc__)

        elif cmd == "ceremony":
            ceremony.run()
            ceremony_done = True

        elif cmd == "offer":
            node_b.offer_ephemeral_key()
            time.sleep(channel.latency_ms / 1000.0 + 0.1)

        elif cmd == "handshake":
            if not ceremony_done:
                print("  Run 'ceremony' first.")
                continue
            try:
                node_a.initiate_handshake(NODE_B_ID)
            except RuntimeError as exc:
                print(f"  Error: {exc}")
                print("  Hint: run 'offer' first so B provides an ephemeral key.")
                continue
            time.sleep(channel.latency_ms / 1000.0 + 0.1)

        elif cmd == "send":
            if len(parts) < 3:
                print("  Usage: send a <message>  or  send b <message>")
                continue
            side = parts[1].lower()
            message = parts[2]
            if side == "a":
                try:
                    node_a.send_message(message)
                except RuntimeError as exc:
                    print(f"  Error: {exc}")
            elif side == "b":
                try:
                    node_b.send_message(message)
                except RuntimeError as exc:
                    print(f"  Error: {exc}")
            else:
                print("  Side must be 'a' or 'b'.")
            time.sleep(channel.latency_ms / 1000.0+ 0.1)

        elif cmd == "loss":
            if len(parts) < 2:
                print("  Usage: loss <0–100>")
                continue
            try:
                pct = float(parts[1])
                channel.packet_loss_pct = max(0.0, min(100.0, pct))
                print(f"  Packet loss set to {channel.packet_loss_pct:.1f}%")
            except ValueError:
                print("  Expected a number.")

        elif cmd == "latency":
            if len(parts) < 2:
                print("  Usage: latency <ms>")
                continue
            try:
                ms = float(parts[1])
                channel.latency_ms = max(0.0, ms)
                print(f"  Latency set to {channel.latency_ms:.0f} ms")
            except ValueError:
                print("  Expected a number.")

        elif cmd == "status":
            a_key = node_a._fernet_key
            b_key = node_b._fernet_key
            print(f"  Ceremony done : {ceremony_done}")
            print(f"  A session key : {'SET' if a_key else 'NONE'}")
            print(f"  B session key : {'SET' if b_key else 'NONE'}")
            print(f"  A peer ready  : {node_a._peer_ready}")
            print(f"  Latency       : {channel.latency_ms:.0f} ms")
            print(f"  Packet loss   : {channel.packet_loss_pct:.1f}%")

        else:
            print(f"  Unknown command '{cmd}'. Type 'help'.")


if __name__ == "__main__":
    if "--auto" in sys.argv:
        run_auto()
    else:
        run_interactive()
