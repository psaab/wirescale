# Cross-Document Contradictions

## 1) Implementation Status vs Present-Tense Guarantees

- `SECURITY.md` describes many controls as active while its own implementation checklist marks core components as not implemented.
- `PERFORMANCE.md` and `ARCHITECTURE.md` similarly describe automated agent behavior not backed by implementation artifacts in this repository.

Impact:
- Readers cannot distinguish design target from shipped behavior.
- Security posture and operational readiness are overstated.

Resolution:
- Add an explicit status banner to each document and per-section status tags: `Implemented`, `Planned`, `Experimental`, `Target`.

## 2) WireGuard Fundamentals Inconsistent Across Docs

- `ARCHITECTURE.md` states WireGuard keypair as `Ed25519` (incorrect; WireGuard uses Curve25519/X25519).
- `SECURITY.md` has an inaccurate handshake detail in responder message semantics.
- `PERFORMANCE.md` contains outdated/over-absolute claims about WG internals and scheduling.

Impact:
- Core crypto and protocol explanations are unreliable.

Resolution:
- Standardize one protocol-accuracy section sourced from WireGuard primary docs and link it from all documents.

## 3) MTU and Encapsulation Math Conflict

- `PERFORMANCE.md` uses a 72-byte IPv6-underlay WireGuard overhead model in MTU derivations.
- `ARCHITECTURE.md` elsewhere aligns with an 80-byte IPv6-underlay overhead model.

Impact:
- Incorrect MTU/MSS recommendations can cause fragmentation, PMTUD issues, and throughput regression.

Resolution:
- Establish one normative MTU formula table with explicit underlay variants and update all references.

## 4) NAT64/DNS64 Semantics Are Mixed With Non-Equivalent Ingress Patterns

- `ROUTABLE-PREFIX.md` uses NAT64 terminology for inbound IPv4-to-pod flows, which does not match standard NAT64 directionality.
- `ARCHITECTURE.md` and `ROUTABLE-PREFIX.md` also mix well-known prefix usage with internal mesh behavior assumptions.

Impact:
- Translation design is ambiguous and partially incompatible with standards usage expectations.

Resolution:
- Separate models cleanly:
  - IPv6 client -> IPv4 server (`DNS64 + NAT64`)
  - IPv4 client -> IPv6 service (`NAT46/SIIT-DC/reverse proxy`)

## 5) Encryption Scope Contradictions

- `ARCHITECTURE.md` claims all inter-node traffic is encrypted, while location-aware mode describes unencrypted intra-zone native routing.
- `ROUTABLE-PREFIX.md` has inconsistent worker-vs-gateway WireGuard responsibility for cross-site mode.

Impact:
- Threat model and compliance guarantees are unclear.

Resolution:
- Define explicit traffic classes and encryption policy matrix by mode:
  - same-node
  - same-site cross-node
  - cross-site
  - external egress

## 6) Security Defaults Contradict Kubernetes Baseline Semantics

- `ROUTABLE-PREFIX.md` and `SECURITY.md` imply default-deny is always active.
- Kubernetes baseline is permissive unless policy selects pods and deny rules are applied.

Impact:
- Operators may assume protections that are not present.

Resolution:
- Rewrite with conditional language and explicit enablement requirements.

## 7) Addressing Examples and Prefix Hierarchy Issues

- `ARCHITECTURE.md` includes invalid IPv6 examples (`fd00:ws...` style hextets).
- `ROUTABLE-PREFIX.md` prefix hierarchy examples are internally inconsistent and include documentation-prefix confusion.

Impact:
- High risk of copy-paste misconfiguration.

Resolution:
- Replace all examples with syntactically valid, containment-correct prefixes.
- Clearly label doc/test prefixes vs production-routable allocations.

## 8) Benchmark Claims Lack Reproducibility

- `PERFORMANCE.md`, `ROUTABLE-PREFIX.md`, and `SECURITY.md` include absolute throughput/latency/pps claims without reproducible method context.

Impact:
- Performance and security claims are not independently verifiable.

Resolution:
- Attach benchmark appendix fields to every numeric claim:
  - hardware
  - kernel
  - NIC
  - packet profile
  - tool/command
  - variance/confidence
