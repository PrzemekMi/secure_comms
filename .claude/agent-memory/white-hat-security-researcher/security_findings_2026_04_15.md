---
name: Security Findings 2026-04-15
description: Full initial security review findings — 14 attack vectors, IDs AV-001 to AV-014, severity breakdown included
type: project
---

Initial full security review completed 2026-04-15. All source files read.

**Why:** Baseline security posture before any production hardening.

**Finding severity summary:**
- CRITICAL: AV-001 (session_id predictability from seeded RNG), AV-002 (handshake lacks replay defense without session binding)
- HIGH: AV-003 (fragment_total unbounded — memory DoS), AV-004 (PSS salt_length=MAX_LENGTH verification asymmetry on real HW), AV-005 (ephemeral key not zeroed — GC-dependent), AV-006 (Fernet key survives session in plaintext heap), AV-007 (no per-sender session cap on reassembly buffers)
- MEDIUM: AV-008 (sig_len integer not bounds-checked — large allocation), AV-009 (session_id counter starts at 0, wraps predictably), AV-010 (RealYubiKey PSS sign passes digest not raw data — padding oracle risk when wired), AV-011 (channel._rng seeded publicly in demo — breaks packet loss randomness), AV-012 (demo status command exposes internal state via direct attribute access)
- LOW: AV-013 (no timeout on EPHEMERAL_OFFER — stale ephemeral key reuse window), AV-014 (AES-128 not AES-256 — Fernet is 128-bit key)

**Key recurring patterns to watch:**
- RNG usage: channel uses `random.Random` (not `secrets`/`os.urandom`) — acceptable for simulation, dangerous if ever used for session_id in production
- Memory: sensitive key bytes (`_fernet_key`, `_eph_private_key`) are Python `bytes` objects, not zeroed on deletion
- Packet parsing: all length fields in packet headers should be bounds-checked against MAX before allocating buffers
- THREAT_MODEL.md gaps: handshake replay (THREAT-2) marked Mitigated but lacks nonce binding; session hijacking not in threat model

**How to apply:** When reviewing future changes, check these patterns first. The reassembly buffer and session_id handling are the highest-risk surfaces.
