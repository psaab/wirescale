# Suggested PR Plan for Documentation Remediation

This document converts the remediation backlog into a small sequence of focused pull requests.

## PR 1 — Protocol and Addressing Correctness (P0)

**Goal:** fix factual correctness issues that could lead to incorrect implementations.

**Scope:**
- Correct WireGuard protocol terminology and handshake details.
- Fix invalid IPv6 address examples and prefix-containment errors.
- Correct NAT64/DNS64 directionality wording for ingress vs egress paths.

**Primary files:**
- `ARCHITECTURE.md`
- `ROUTABLE-PREFIX.md`
- `SECURITY.md`

**Acceptance criteria:**
- No invalid IPv6 literals remain in examples.
- WireGuard protocol description is internally consistent across all docs.
- Translation direction terminology is consistent and unambiguous.

## PR 2 — Encryption and Packet-Flow Model Alignment (P0)

**Goal:** remove contradictions in cross-site encryption and packet traversal narratives.

**Scope:**
- Choose one authoritative cross-site model (`worker wg0` vs `gateway-only transit`) and apply it everywhere.
- Align packet-flow text and diagrams to the selected model.

**Primary files:**
- `ARCHITECTURE.md`
- `ROUTABLE-PREFIX.md`
- `PERFORMANCE.md`

**Acceptance criteria:**
- One coherent cross-site flow model is documented.
- No conflicting statements remain about worker `wg0` requirements.

## PR 3 — MTU and Overhead Recalculation (P0/P2 bridge)

**Goal:** ensure overhead math and derived MTU/MSS guidance are correct and consistent.

**Scope:**
- Replace incorrect WireGuard-over-IPv6 overhead assumptions with the correct model where applicable.
- Recompute MTU/MSS tables and examples.
- Align all cross-references to a single overhead baseline.

**Primary files:**
- `PERFORMANCE.md`
- `ARCHITECTURE.md`
- `ROUTABLE-PREFIX.md`

**Acceptance criteria:**
- MTU/MSS numbers are mathematically consistent with stated assumptions.
- No contradictory overhead values remain across documents.

## PR 4 — Truth-State Labeling and Security Claim Qualification (P1)

**Goal:** separate implemented behavior from planned behavior and reduce overstatement risk.

**Scope:**
- Add top-level implementation-status banners per document.
- Add per-section tags (`Implemented`, `Planned`, `Experimental`, `Target`) where needed.
- Replace absolute security language with conditional phrasing unless universally true.
- Align RBAC narrative with explicit permissions shown.

**Primary files:**
- `SECURITY.md`
- `ARCHITECTURE.md`
- `PERFORMANCE.md`
- `ROUTABLE-PREFIX.md`

**Acceptance criteria:**
- Readers can distinguish current behavior from intent in every document.
- Security controls are not presented as unconditional when prerequisites exist.

## PR 5 — Performance Claims Evidence Pass (P2)

**Goal:** attach reproducibility context to quantitative claims and demote unsupported numbers.

**Scope:**
- Add benchmark evidence blocks for quantitative performance claims.
- Mark uncited numbers as targets/estimates until validated.
- Version-scope kernel-dependent tuning claims.

**Primary files:**
- `PERFORMANCE.md`

**Acceptance criteria:**
- Every hard number has reproducibility metadata or is clearly labeled as a target.
- Kernel-version-sensitive guidance is explicitly scoped.

## PR 6 — Shared Reference Sections and Doc Guardrails (P3)

**Goal:** improve long-term consistency and maintenance.

**Scope:**
- Add shared “Normative Assumptions” and “Reference Architecture Modes” sections referenced by all docs.
- Add lightweight validation checks for examples and numeric-claim sourcing in documentation workflows.

**Primary files:**
- `ARCHITECTURE.md`
- `PERFORMANCE.md`
- `ROUTABLE-PREFIX.md`
- `SECURITY.md`

**Acceptance criteria:**
- Core assumptions and architecture modes are defined once and referenced consistently.
- Documentation regressions are easier to detect in review.
