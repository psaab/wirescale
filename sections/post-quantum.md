# Post-Quantum Cryptographic Migration

> Subsection for SECURITY.md Section 10 (Key Lifecycle Management).
>
> Normative language per RFC 2119 / RFC 8174 when shown in all caps.

## Quantum Threat to Current Cryptography

Wirescale's data-plane encryption relies on WireGuard, which uses Curve25519
(ECDH) for key exchange. A cryptographically relevant quantum computer (CRQC)
running Shor's algorithm breaks Curve25519 in polynomial time, enabling:

- **Active decryption:** A CRQC derives the shared secret from observed
  ephemeral Curve25519 public keys, decrypting sessions in real time.
- **Harvest now, decrypt later (HNDL):** An adversary recording handshakes
  today decrypts them once a CRQC is available. WireGuard's 2-minute rekey
  limits exposure per session, but a persistent observer captures all sessions.

ChaCha20-Poly1305 and BLAKE2s are NOT vulnerable to Shor's algorithm.
Grover's algorithm provides only quadratic speedup against symmetric ciphers,
so 256-bit ChaCha20 retains ~128-bit post-quantum security. The quantum
risk is concentrated entirely in the Curve25519 key exchange.

## Current Mitigation: Pre-Shared Keys

WireGuard's Noise IKpsk2 handshake supports an optional pre-shared key (PSK)
mixed into the key derivation via HKDF. With PSK enabled, the session key
depends on both the ECDH result and the PSK -- an attacker who breaks
Curve25519 but does not possess the PSK cannot derive the session key. This
provides quantum resistance if and only if the PSK is distributed through a
quantum-safe channel.

Wirescale deployments SHOULD enable per-peer PSKs as a near-term quantum
hedge. `wirescale-control` SHOULD distribute PSKs to authorized node pairs
over its mTLS gRPC channel. PSKs MUST be rotated on a configurable schedule
(default: 24 hours, aligned with node key rotation). PSKs MUST NOT be
persisted to disk; they MUST be held in agent process memory only, consistent
with the key escrow policy in Section 10.5.

## Migration Roadmap

### Phase 1: PSK Hardening (current)

Enable WireGuard PSK on all peer pairs, distributed via `wirescale-control`
over mTLS. Rotate on the same schedule as node Curve25519 keys. No WireGuard
protocol changes required.

### Phase 2: Control-Plane Hybrid Key Exchange (near-term)

The gRPC control plane SHOULD migrate to TLS 1.3 with hybrid key exchange
(X25519 + ML-KEM-768, per FIPS 203). This protects control-plane traffic
against HNDL. Implementations MUST NOT use PQ algorithms not yet standardized
by NIST.

### Phase 3: Rosenpass PQ Key Exchange (medium-term)

Deployments MAY use Rosenpass to negotiate a PQ-safe shared secret and inject
it as the WireGuard PSK automatically. Rosenpass uses Classic McEliece and
ML-KEM in a hybrid construction, providing PQ security without modifying the
WireGuard kernel module. This layers cleanly: Rosenpass handles PQ key
exchange; WireGuard handles authenticated encryption.

### Phase 4: Native PQ WireGuard (long-term)

When the upstream Linux kernel WireGuard adopts a post-quantum or hybrid
handshake, Wirescale MUST migrate to the native implementation. Until then,
Phases 1-3 provide defense in depth.

## Monitoring

Operators SHOULD track: PSK coverage (target: 100% of peer pairs), PSK
rotation compliance, control-plane TLS cipher suite, and Rosenpass coverage.
The agent SHOULD expose `wirescale_pq_psk_enabled{peer="..."}` per peer.
