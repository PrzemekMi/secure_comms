# Threat Model

## System Overview

Two parties (Side A, Side B) communicate over a Meshtastic LoRa mesh channel.
Identity is anchored to a YubiKey PIV slot (RSA-2048). Trust is established
once, in person, with no third-party certificate authority. All traffic on the
channel is encrypted with Fernet (AES-128-CBC + HMAC-SHA256).

---

## Trust Anchors

| Anchor | What we trust |
|--------|--------------|
| In-person ceremony | Both operators are physically present and compare fingerprints |
| YubiKey hardware | RSA private key cannot be exported from PIV slot 9a |
| Python `cryptography` library | Correct implementation of RSA-OAEP, RSA-PSS, Fernet |
| OS memory isolation | No other process reads in-memory Fernet key |

---

## Attack Vectors

### 1. Eavesdropping on the Meshtastic channel
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | All message payloads are Fernet-encrypted (AES-128-CBC + HMAC-SHA256). The channel carries only ciphertext. An observer sees random-looking bytes. |
| **Residual risk** | None for message content. Traffic metadata (timing, volume) is visible. |

---

### 2. Handshake replay
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | RSA-OAEP padding includes random bytes, making each ciphertext unique. A replayed HANDSHAKE packet decrypts to the same Fernet key, but Fernet tokens carry a timestamp. With `ttl=300`, tokens older than 5 minutes are rejected with `InvalidToken`. |
| **Future improvement** | Add a nonce/sequence number to the handshake body to detect replays of the handshake itself, not just message tokens. |

---

### 3. Fernet message replay
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | `Fernet.decrypt(token, ttl=300)` rejects tokens whose embedded timestamp is more than 5 minutes old. |
| **Caveat** | Relies on system clock accuracy. Clock skew > 5 minutes between sides would cause false rejections. |

---

### 4. Man-in-the-middle during handshake
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | The RSA-OAEP ciphertext is signed with the sender's YubiKey using RSA-PSS. An attacker who intercepts and modifies the ciphertext cannot produce a valid signature without physical access to the YubiKey. |

---

### 5. Man-in-the-middle during the in-person ceremony
| | |
|---|---|
| **Status** | **Trusted** |
| **Mechanism** | Both operators are physically co-present. SHA-256 fingerprints are printed and compared aloud. No network is involved. A physical MitM would require impersonating one operator in person. |

---

### 6. Impersonation (attacker claims to be Side A or B)
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | Each node's keystore only contains keys loaded during the physical ceremony. An attacker who generates their own key pair cannot register it without physical access to one of the YubiKeys and the consent of both operators. All handshakes from unknown node IDs are dropped. |

---

### 7. YubiKey theft
| | |
|---|---|
| **Status** | **Trusted / Partial** |
| **Mechanism** | The RSA-2048 private key is non-exportable from PIV slot 9a by hardware design. Physical theft of the device gives access only if the PIN is also known. |
| **Current gap** | The `RealYubiKey` stub does not enforce PIN entry. |
| **Future improvement** | Prompt for PIV PIN in `RealYubiKey.sign()` and `RealYubiKey.decrypt()`. Implement PIV touch policy (require physical button press per signature). |

---

### 8. Session Fernet key at rest
| | |
|---|---|
| **Status** | **Future** |
| **Mechanism** | The Fernet key is held in plaintext in Python heap memory for the session lifetime. |
| **Future improvement** | Zeroize `_fernet_key` after session close. Use `ctypes` or `mlock` for sensitive key material. Re-key on a schedule rather than holding one key indefinitely. |

---

### 9. Crafted or injected fragment
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | Every reassembled payload passes either RSA-PSS verification (HANDSHAKE) or Fernet HMAC-SHA256 verification (MESSAGE). A crafted fragment that passes reassembly will fail its integrity check and be discarded. |

---

### 10. Fragment flood / reassembly buffer exhaustion (DoS)
| | |
|---|---|
| **Status** | **Future** |
| **Mechanism** | The current implementation limits reassembly buffer lifetime to 30 seconds (stale entries are evicted). However, there is no cap on the number of concurrent in-flight sessions per sender. |
| **Future improvement** | Limit in-flight sessions per sender to N (e.g. 10). Drop the oldest session buffer when the limit is exceeded. Add rate limiting on fragment arrival. |

---

### 11. Node ID spoofing
| | |
|---|---|
| **Status** | **Trusted (mock context)** |
| **Mechanism** | The channel is an in-memory mock — there is no real node ID to spoof. In real Meshtastic, node IDs are device-burned hardware addresses. Regardless, spoofing a node ID does not help: all packets must pass cryptographic verification (RSA-PSS signature or Fernet HMAC) to be accepted. |

---

### 12. Lack of forward secrecy
| | |
|---|---|
| **Status** | **Future** |
| **Mechanism** | A single Fernet key is shared for the entire session. If the session key is compromised (e.g. memory dump), all past and future messages in that session are readable. |
| **Future improvement** | Implement an ECDH ratchet (Signal Double Ratchet protocol) for per-message forward secrecy. Each message would derive a new key from a Diffie-Hellman exchange, ensuring past messages are not decryptable even if the current key is leaked. |

---

### 13. Algorithm downgrade
| | |
|---|---|
| **Status** | **Mitigated** |
| **Mechanism** | All cryptographic algorithms are hardcoded (OAEP-SHA256 for key encapsulation, PSS-SHA256 for signatures, Fernet for symmetric encryption). There is no negotiation phase, so there is no downgrade path. |

---

### 14. Side-channel attacks on key material
| | |
|---|---|
| **Status** | **Trusted** |
| **Mechanism** | MockYubiKey uses Python's `cryptography` library which delegates to OpenSSL. OpenSSL uses constant-time implementations for RSA operations. For RealYubiKey, the hardware handles all private key operations internally. |
| **Caveat** | Python's GIL and memory allocator do not provide timing-attack guarantees at the application level. This is acceptable for a LoRa mesh threat model but would need hardening for a high-value target. |

---

### 15. Predictable session_id from seeded RNG
| | |
|---|---|
| **Feature** | MeshtasticChannel.send() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | `self._rng = random.Random(seed)` uses Python's non-cryptographic PRNG. When `seed` is supplied (as in the demo), all session IDs are entirely predictable. Even without an explicit seed, `random.Random` is not cryptographically secure — an attacker who observes a few session_id values can recover the internal state and predict all future ones. |
| **Threat Actor** | Passive observer on the LoRa channel |
| **STRIDE Category** | Tampering / Denial of Service |
| **Likelihood** | Medium |
| **Impact** | Medium — enables session collision attacks and targeted fragment injection |
| **Mitigation** | Replace `self._rng.randint(0, 65535)` in `send()` with `int.from_bytes(os.urandom(2), 'big')`. Remove the `seed` parameter or restrict it to test-only code paths. |

---

### 16. Handshake replay — no nonce binding to ephemeral key offer
| | |
|---|---|
| **Feature** | SideANode.initiate_handshake() / SideBNode._handle_handshake() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | The HANDSHAKE ciphertext is encrypted under B's ephemeral public key, which is consumed once. However, the EPHEMERAL_OFFER itself carries no nonce or timestamp. An attacker who records a valid EPHEMERAL_OFFER and replays it during a future session causes A to encrypt a Fernet key under a stale ephemeral key — but if B has already discarded that private key, the session simply fails. The more dangerous scenario: if B has not yet consumed the ephemeral key (race window), a replayed offer causes A to encrypt under the attacker's chosen ephemeral key (requires the attacker to have previously generated one that B signed, which is not possible without physical access to B's YubiKey). Risk is low in the current trust model but escalates if the transport moves to a real network. |
| **Threat Actor** | Active MitM with recorded traffic |
| **STRIDE Category** | Tampering / Repudiation |
| **Likelihood** | Low |
| **Impact** | Medium |
| **Mitigation** | Embed a monotonic counter or UTC timestamp + random nonce in the EPHEMERAL_OFFER body (before signing). A must verify the timestamp is within an acceptable window and reject offers it has already processed. |

---

### 17. Unbounded fragment_total — memory exhaustion DoS
| | |
|---|---|
| **Feature** | MeshtasticChannel._deliver_fragment() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | `buf[key] = [None] * pkt.fragment_total` allocates a list sized by the untrusted `fragment_total` field in the packet header. `fragment_total` is a uint16 (0–65535). A malicious sender can craft a single fragment with `fragment_total=65535`, causing each receiver to allocate a 65535-element list per such packet. With two receivers and rapid sending, this can exhaust Python heap memory. |
| **Threat Actor** | Any node on the channel (including a compromised node) |
| **STRIDE Category** | Denial of Service |
| **Likelihood** | High |
| **Impact** | High — full process crash |
| **Mitigation** | Add a hard cap: `if pkt.fragment_total > MAX_FRAGMENTS_PER_SESSION: drop and return`. A reasonable cap given 220-byte bodies is `ceil(65536 / 220) + 1 = 299`. Also enforce a per-sender in-flight session cap (see existing THREAT-10). |

---

### 18. sig_len field not bounds-checked — large heap allocation
| | |
|---|---|
| **Feature** | SideANode._handle_ephemeral_offer(), SideBNode._handle_handshake() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | Both handlers parse a 4-byte big-endian `sig_len` field from untrusted payload bytes and immediately use it to slice: `signature = body[4 : 4 + sig_len]`. A malicious packet can set `sig_len = 2^32 - 1`. Python slice semantics silently clamp this to `len(body)`, so no crash occurs — but the slice `body[4 : 4 + sig_len]` will consume an arbitrary amount of the body, and the subsequent `eph_pub_der = body[4 + sig_len:]` will be empty. The RSA verification will then fail against an empty byte string, which is the correct behavior. However, if the parsing logic ever changes to allocate a buffer of `sig_len` bytes before slicing, this becomes a direct heap-allocation DoS. More critically, if `sig_len` is set to a value larger than the actual signature but smaller than the body, the signature slice silently includes part of the public key data, causing a subtly malformed verification rather than a clean rejection — this could in theory be used as an oracle if error messages differ. |
| **Threat Actor** | Any node on the channel |
| **STRIDE Category** | Tampering / Denial of Service |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Mitigation** | Add explicit bounds check: `if sig_len != 256: reject` (RSA-2048 PSS signatures are always exactly 256 bytes). This eliminates the ambiguity entirely and is a single-line fix. |

---

### 19. Ephemeral private key not cryptographically zeroed
| | |
|---|---|
| **Feature** | SideBNode._handle_handshake() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | After decrypting the Fernet key, the code sets `self._eph_private_key = None` and calls `del eph_priv`. Python's garbage collector does not guarantee immediate memory reclamation or zeroing. The private key bytes remain in heap memory until the GC runs and the OS reclaims the pages. A memory dump (from a crash, core dump, swap file, or hibernation image) taken before GC can expose the ephemeral private key, breaking forward secrecy retroactively. The same applies to `_fernet_key` on both sides. |
| **Threat Actor** | Attacker with post-session memory access (forensics, cold-boot, VM snapshot) |
| **STRIDE Category** | Information Disclosure |
| **Likelihood** | Low (requires post-session memory access) |
| **Impact** | High — breaks forward secrecy guarantee |
| **Mitigation** | Use `ctypes.memset` to zero the key bytes before releasing the reference. For `cryptography` library private key objects, call `key.__class__` inspection is not directly possible, but the raw private bytes can be zeroed if extracted first. Short-term: use `mlock` via `ctypes` to prevent the key pages from being swapped. Long-term: use a memory-safe key container (e.g., `SecureBytes` pattern). |

---

### 20. Fernet session key persists in plaintext heap for entire session lifetime
| | |
|---|---|
| **Feature** | SideANode._fernet_key, SideBNode._fernet_key |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** (previously logged as THREAT-8, re-opened with additional detail) |
| **Attack Vector** | `_fernet_key` is a Python `bytes` object stored in the instance for the entire session. It is never zeroized. In addition to the memory dump risk noted in THREAT-8, this key is also exposed via: (1) the `demo.py status` command which accesses `node_a._fernet_key` directly (no redaction); (2) any unhandled exception traceback that includes the frame where the key is used; (3) Python `gc.get_referrers()` introspection if an attacker can execute arbitrary code in the same process. |
| **Threat Actor** | Process-level attacker, forensic investigator |
| **STRIDE Category** | Information Disclosure |
| **Likelihood** | Low–Medium |
| **Impact** | High |
| **Mitigation** | (1) Zeroize on session close using `ctypes.memset`. (2) The `status` command in demo.py should never print `_fernet_key` — currently it only prints `'SET'/'NONE'` which is safe, but direct access to `._fernet_key` from outside the class is a design smell. Add a `has_session_key()` method and remove direct attribute access from demo.py. (3) Re-key on a schedule. |

---

### 21. Session_id counter starts at 0 and increments predictably
| | |
|---|---|
| **Feature** | SideANode._next_session_id(), SideBNode._next_session_id() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** |
| **Attack Vector** | `_session_id_counter` starts at 0 and increments by 1 each call, wrapping at 65536. The first HANDSHAKE from a freshly-initialized node will always carry session_id=1 at the channel transport layer. This makes session IDs predictable and could allow an attacker to pre-position fragment buffers keyed on (sender_id, session_id) before the legitimate session begins, potentially causing reassembly collisions. This is distinct from the channel's own `_rng.randint()` session_id (THREAT-15) — the node-level counter is used to call `fragment()` but the result is re-fragmented by the channel with its own session_id. |
| **Threat Actor** | Active attacker who knows node startup time |
| **STRIDE Category** | Tampering |
| **Likelihood** | Low |
| **Impact** | Low–Medium |
| **Mitigation** | Initialize `_session_id_counter` with `int.from_bytes(os.urandom(2), 'big')` rather than 0. |

---

### 22. RealYubiKey.sign() sends SHA-256 digest, not raw data — PSS verification asymmetry
| | |
|---|---|
| **Feature** | yubikey/real_yubikey.py RealYubiKey.sign() stub |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** (stub only — risk materializes when wired) |
| **Attack Vector** | The `RealYubiKey.sign()` docstring shows the intended implementation passes `hashlib.sha256(data).digest()` to `piv.sign()`. The verifiers in `side_a/node.py` and `side_b/node.py` call `peer_pubkey.verify(signature, data, PSS(...), SHA256())` — which will internally hash `data` with SHA-256 before verifying. If the real YubiKey driver also hashes internally (double-hashing), the signature will always fail verification. If the developer works around this by passing pre-hashed data to `verify()`, they may switch to a raw RSA verify path that bypasses padding checks entirely. Either error breaks the authentication guarantee. |
| **Threat Actor** | Developer error (misconfiguration) |
| **STRIDE Category** | Spoofing / Elevation of Privilege |
| **Likelihood** | Medium (will be encountered at integration time) |
| **Impact** | Critical if worked around incorrectly (signature bypass) |
| **Mitigation** | The `RealYubiKey.sign()` implementation must pass raw `data` bytes to the YubiKey driver and let the hardware perform the SHA-256 internally (i.e., use `HASH_ALGORITHM.SHA256` flag so the device hashes before signing, matching what `cryptography`'s `verify()` expects). Add an integration test that signs a known value and verifies it with the `cryptography` library before deploying. |

---

### 23. No maximum reassembly session count per sender
| | |
|---|---|
| **Feature** | MeshtasticChannel._deliver_fragment() |
| **Date Added** | 2026-04-15 |
| **Status** | **Open** (previously logged as THREAT-10, adding implementation detail) |
| **Attack Vector** | An attacker sending fragments with unique session_ids (cycling through all 65536 values) creates 65536 independent reassembly buffers per receiver, each of which can be sized up to 65535 slots (see THREAT-17). Combined, this allows exhausting memory with O(65536 * 65535) None slots before any 30-second timeout eviction kicks in. The eviction only runs on the next fragment arrival for the same receiver, not on a timer. |
| **Threat Actor** | Any node on the channel |
| **STRIDE Category** | Denial of Service |
| **Likelihood** | High (trivial to exploit) |
| **Impact** | High |
| **Mitigation** | (1) Cap `fragment_total` at 300. (2) Cap concurrent sessions per sender at 10. (3) Run eviction on a background timer thread rather than only on fragment arrival. |

---

## Summary Matrix

| Vector | Status | Short rationale |
|--------|--------|-----------------|
| Eavesdropping | Mitigated | Fernet AES-128-CBC + HMAC |
| Handshake replay | Mitigated | OAEP non-determinism + Fernet TTL |
| Message replay | Mitigated | Fernet timestamp TTL=300s |
| MitM on handshake | Mitigated | YubiKey RSA-PSS signature |
| MitM on ceremony | Trusted | Physical co-presence + fingerprint check |
| Impersonation | Mitigated | Ceremony-only keystore + PSS verification |
| YubiKey theft | Trusted/Partial | Non-exportable key; PIN gap in RealYubiKey |
| Key in memory | Future | Zeroize on session close |
| Fragment injection | Mitigated | PSS / Fernet HMAC rejects tampered payloads |
| Fragment flood DoS | Future | Per-sender session cap not implemented |
| Node ID spoofing | Trusted | Crypto verification makes it harmless |
| No forward secrecy | Mitigated | RSA ephemeral key per session (implemented) |
| Algorithm downgrade | Mitigated | Hardcoded algorithms, no negotiation |
| Side-channel | Trusted | OpenSSL constant-time + YubiKey hardware |
| Predictable session_id (RNG) | Open | random.Random not CSPRNG; seed exposed in demo |
| Handshake replay (nonce gap) | Open | No nonce/timestamp in EPHEMERAL_OFFER |
| Fragment_total DoS | Open | Unbounded list allocation from untrusted field |
| sig_len bounds check | Open | Missing explicit 256-byte assertion |
| Ephemeral key not zeroed | Open | GC-dependent; memory dump risk |
| Fernet key heap exposure | Open | Plaintext bytes for session lifetime |
| Predictable session_id counter | Open | Counter starts at 0 |
| RealYubiKey double-hash risk | Open | Stub comment shows pre-hashing; verify asymmetry |
| Reassembly session count cap | Open | No per-sender cap; timer-based eviction missing |
