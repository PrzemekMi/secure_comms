---
name: Project Architecture
description: Core architecture of secure_comms — two-party LoRa mesh comms using YubiKey PIV + Fernet symmetric encryption
type: project
---

secure_comms is a Python cryptographic communications project that simulates a two-party (Side A, Side B) secure messaging system over a mock Meshtastic LoRa mesh channel.

**Why:** Designed for high-assurance, air-gapped or LoRa-only mesh environments where no network CA is available; trust is anchored to physical YubiKey PIV hardware.

**Key components:**
- `yubikey/` — YubiKeyInterface ABC, MockYubiKey (in-memory RSA-2048), RealYubiKey stub (all NotImplementedError)
- `ceremony/` — CeremonyOrchestrator: one-time physical in-person bilateral public key exchange with SHA-256 fingerprint verification
- `channel/` — MeshtasticChannel mock: broadcast, fragmentation (7-byte header + 220-byte body, 227-byte max), reassembly, configurable latency/loss, 30s buffer timeout
- `side_a/` — SideANode (initiator): waits for EPHEMERAL_OFFER from B, encrypts Fernet key under ephemeral RSA pub key, signs ciphertext with long-term YubiKey
- `side_b/` — SideBNode (responder): generates fresh RSA-2048 ephemeral key pair per session, signs ephemeral pub key with long-term YubiKey, decrypts Fernet key, discards ephemeral private key
- `demo/` — Interactive CLI + automated smoke test

**Crypto primitives in use:**
- RSA-2048 with OAEP-SHA256 for Fernet key encapsulation
- RSA-PSS with MGF1-SHA256 + MAX_LENGTH salt for signatures
- Fernet (AES-128-CBC + HMAC-SHA256) for symmetric encryption
- TTL=300s on all Fernet tokens

**Existing threat model:** `THREAT_MODEL.md` at repo root, 14 threat entries (THREAT-1 through THREAT-14). Last reviewed/updated 2026-04-15.

**How to apply:** When reviewing new features, cross-reference against this architecture; pay special attention to the session_id counter, the ephemeral key lifecycle, the reassembly buffer, and the in-memory keystore/key material handling.
