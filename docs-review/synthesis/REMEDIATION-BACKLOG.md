# Remediation Backlog

Priority-ordered remediation plan synthesized from all four reports.

## P0: Correctness and Security Integrity (blockers)

1. Fix WireGuard cryptography/protocol inaccuracies.
- Correct key type language to Curve25519/X25519.
- Correct handshake sequence details.
- Align all documents to one protocol-accuracy block.

2. Fix MTU/overhead model inconsistencies.
- Replace IPv6-underlay overhead with the correct 80-byte model where applicable.
- Recompute derived MTU/MSS tables in `PERFORMANCE.md`.
- Cross-check references in `ARCHITECTURE.md` and `ROUTABLE-PREFIX.md`.

3. Correct invalid and inconsistent IPv6 examples.
- Replace invalid hextets (e.g., symbolic strings inside addresses).
- Ensure prefix containment math is correct across site/rack/pod examples.
- Explicitly distinguish documentation prefixes from production-routable prefixes.

4. Remove or rewrite incorrect NAT64 ingress framing.
- Replace “NAT64 ingress” wording for IPv4-client inbound paths.
- Split translation patterns by direction and attach correct standards references.

5. Resolve cross-site encryption architecture contradiction.
- Choose one authoritative model per mode (`worker wg0` vs `gateway-only transit`).
- Rewrite packet-flow sections to match selected model with no mixed narratives.

## P1: Claim Fidelity and Operational Truthfulness

1. Introduce explicit implementation-status labeling in all docs.
- Add top-level banner per doc.
- Add per-section tags: `Implemented`, `Planned`, `Experimental`, `Target`.

2. Remove unsupported present-tense automation claims.
- Any “agent automatically does X” statement must either link to implementation or be marked planned.

3. Normalize default-deny language against Kubernetes semantics.
- Make policy behavior conditional on concrete policy installation and selector coverage.

4. Replace absolute phrasing with conditional phrasing where required.
- Remove/qualify words like `always`, `never`, `zero`, `mandatory`, `cannot` unless universally true.

5. Fix RBAC and control-plane assertions in `SECURITY.md`.
- Align narrative with actual permissions shown.
- Explicitly document current risk and compensating controls.

## P2: Performance and Benchmark Quality

1. Add benchmark evidence blocks to every quantitative claim.
- Hardware, kernel, NIC, packet profile, method, variance, test date.

2. Demote uncited numbers to targets.
- Use labels such as `Target` or `Estimate` until verified.

3. Clarify kernel-version-dependent behavior.
- Version-gate NAPI, GRO/GSO, and tuning claims.

4. Resolve NAT64 hookpoint ambiguity in `PERFORMANCE.md`.
- Pick one canonical attach point and align diagrams + code snippets.

## P3: Documentation UX and Maintainability

1. Add a shared “Normative Assumptions” section referenced by all docs.
- Routing assumptions
- Threat model scope
- Fabric capabilities
- Translation directionality

2. Add a shared “Reference Architecture Modes” section.
- Full-mesh encrypted
- Location-aware selective encryption
- Cross-site modes

3. Add lint-style checks for docs examples.
- Validate IPv6 syntax and prefix containment in code blocks.
- Flag uncited numeric claims.

4. Add a changelog trail for major architecture claim updates.
- Keep a short “what changed and why” section per document revision.

## Suggested Execution Order

1. P0 items 1-5 in one review cycle.
2. P1 items 1-5 immediately after, in same PR series if possible.
3. P2 quantitative cleanup once baseline correctness is restored.
4. P3 maintainability hardening as a follow-up quality pass.
