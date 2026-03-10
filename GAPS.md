# Wirescale: Documentation and Design Gaps

> Tracking document for known gaps in the Wirescale design documentation.
> Items are checked off as they are addressed in the relevant documents.

---

## Architectural Gaps

- [x] **Cross-cluster service discovery and load balancing** (Critical)
  Wirescale replaces ClusterMesh but has no replacement for multi-cluster
  service discovery (ServiceExport/ServiceImport, global services, cross-
  cluster service VIPs). This is the #1 real-world use case gap.
  Added: ARCHITECTURE.md Section 10 (WirescaleServiceExport/Import CRDs,
  on-demand resolution via control hierarchy, VIP strategies, topology-aware
  LB, health checking, Cilium integration).

- [x] **Cross-cluster IPv4 address collisions**
  CLAT maps `100.64.N.P` deterministically, but two pods in different
  clusters can share the same IPv4 address. Pod-to-pod IPv4 across
  clusters is ambiguous. Need to define whether cross-cluster IPv4 is
  supported and how collisions are resolved (cluster-scoped CGNAT ranges,
  or IPv4 is intra-cluster only).
  Added: ARCHITECTURE.md Section 8 subsection (cross-cluster IPv4 explicitly
  unsupported; CGNAT is cluster-scoped; cross-cluster uses IPv6 only).

- [x] **Host-network pods (`hostNetwork: true`)**
  No veth pair, no CLAT, no per-pod eBPF. Identity attribution, policy
  enforcement, and IPv4 compatibility are undefined for host-network pods.
  Common for ingress controllers, monitoring agents, kube-proxy.
  Added: ARCHITECTURE.md Section 11 (identity model, WireGuard data path,
  CLAT non-applicability, policy enforcement via nftables/Cilium host firewall).

- [x] **Multicast and NDP through WireGuard**
  IPv6 NDP uses multicast. In ULA overlay mode or `always` encryption,
  multicast doesn't traverse WireGuard (L3 point-to-point). NDP on the
  rack /64 is fine for native routing, but overlay mode needs explicit
  handling (proxy NDP, unicast NDP, or NDP suppression).
  Added: ARCHITECTURE.md Section 6 subsection (NDP suppression via explicit
  routes, static neighbor entries, eBPF drop of NDP on wg0, mDNS/MLD notes).

- [x] **StatefulSet stable network identities**
  Pods rescheduled to a different node get a different /64 prefix and
  different IP. Headless service DNS and StatefulSet ordinal-based
  discovery may break. Need to document interaction with stable identity
  patterns.
  Added: ARCHITECTURE.md Section 9 subsection (stable IPs are non-goal;
  DNS updates within 5s; operator guidance: use DNS names, lower TTLs).

---

## Operational Gaps

- [x] **Upgrade and migration strategy** (Critical)
  No document covers: rolling agent upgrades, control plane upgrades,
  CRD schema migration, migration from Cilium-only to Cilium+Wirescale,
  or migration from Wirescale standalone to Cilium+Wirescale.
  Added: OPERATIONS.md Section 1 (rolling upgrades, CRD migration,
  three migration paths, canary deployments, version skew policy).

- [x] **Capacity planning guidance**
  Scaling tables give theoretical limits but no concrete sizing guide.
  Controller replicas per cluster size, agent memory requirements, XDP
  CPU at various link speeds, directory sizing.
  Added: OPERATIONS.md Section 2 (controller sizing table, agent resources,
  XDP CPU budget, directory/etcd sizing, BPF map sizing, scaling decisions).

- [x] **Monitoring and alerting runbook**
  Prometheus metrics are defined but no guidance on healthy vs. degraded
  thresholds, what to alert on, or how to diagnose common issues.
  Added: OPERATIONS.md Section 3 (health thresholds, 6 alerts, 4
  troubleshooting runbooks with diagnosis/resolution steps).

- [x] **Thundering herd on cold start**
  Mass agent restart (rolling update, DR) causes simultaneous control
  plane queries. Need agent-side jitter, exponential backoff, and
  circuit-breaking. Not documented.
  Added: PERFORMANCE.md Section 5 (jittered startup, exponential backoff,
  circuit breaker, control-side rate limiting, pre-warming peer cache,
  TCP SYN retry budget interaction).

- [x] **Backup and disaster recovery**
  What state needs backup? Global directory is critical. Controller state
  is derived from k8s API. Agent state is ephemeral. DR procedures
  undefined.
  Added: OPERATIONS.md Section 4 (state classification, backup procedures,
  recovery procedures, RPO/RTO targets, multi-region quorum handling).

- [x] **Testing strategy**
  No conformance test suite, integration test plan, or performance
  regression test framework documented.
  Added: OPERATIONS.md Section 5 (conformance suite, kind/k3d integration
  framework, performance regression CI gates, chaos testing scenarios).

---

## Security Gaps

- [x] **BPF map access control**
  Identity cache, policy map, and peer cache pinned under `/sys/fs/bpf/`
  are readable by `CAP_BPF`/`CAP_SYS_ADMIN`. Container escape exposes
  the full local policy and identity state. Need to document pinning
  strategy, filesystem permissions, and whether maps should be fd-only.
  Added: SECURITY.md Section 14 (pinning strategy, fd-only maps,
  filesystem permissions, audit rules, monitoring).

- [x] **eBPF program supply chain**
  Compromised agent image could load malicious eBPF that bypasses policy.
  No discussion of program signing, verification, or tamper detection.
  Added: SECURITY.md Section 13 threat T18 (image signing, eBPF hash
  verification, runtime audit, read-only filesystem, least-privilege).

- [x] **Metadata leakage from pull-based model**
  wirescale-control sees every peer resolution request, exposing the
  complete communication graph. Trade-off vs. push model (diffused
  metadata). Should be acknowledged and mitigated (query log retention
  policy, access controls on logs).
  Added: SECURITY.md Section 13 threat T19 (query log retention limits,
  access control, optional batch anonymization, audit of log access).

- [x] **Post-quantum migration**
  WireGuard uses Curve25519 (not quantum-resistant). No discussion of
  hybrid key exchange or migration planning for post-quantum crypto.
  Added: SECURITY.md Section 10 subsection (HNDL threat, PSK mitigation,
  four-phase migration roadmap: PSK → hybrid TLS → Rosenpass → native PQ).

- [x] **Regulatory compliance mapping**
  PCI-DSS and HIPAA mentioned but no control-to-feature mapping.
  Added: SECURITY.md new section (PCI-DSS v4.0 mapping, HIPAA Security
  Rule mapping, SOC 2 Type II mapping, cross-framework summary, auditor guidance).

---

## Performance Edge Cases

- [x] **IPv6 extension headers in eBPF**
  Pseudocode parses fixed IPv6 header only. Real traffic has extension
  header chains that require unrolled bounds-checked parsing in eBPF.
  Docs should acknowledge this implementation complexity.
  Added: PERFORMANCE.md Section 3 + SECURITY.md Section 7 (unrolled parsing,
  6-header depth, Fragment header special case, fallback strategies, perf cost).

- [x] **QUIC and UDP protocols through cold paths**
  Cold-path analysis covers TCP retransmit budget. QUIC has different
  retry semantics and 0-RTT that interact differently with packet
  queuing during peer setup.
  Added: PERFORMANCE.md Section 5 subsection (UDP packet queue, QUIC Initial/
  0-RTT/Retry handling, protocol comparison table with cold-path risk).

- [x] **NUMA-aware packet processing**
  At 40-100G, WireGuard kthreads, eBPF programs, and NIC interrupts
  should be on the same NUMA node. Kernel tuning section covers RSS/RPS
  but not NUMA pinning.
  Added: PERFORMANCE.md Section 12 subsection (IRQ affinity, kthread pinning,
  NUMA-local BPF maps, XDP redirect boundaries, monitoring tools).

---

## Documentation Consistency

- [ ] **Example prefix inconsistency** (Quick win)
  Different prefixes across documents:
  - ARCHITECTURE.md: `3fff:1d:...`
  - ROUTABLE-PREFIX.md: `3fff:1234:...`
  - CILIUM-INTEGRATION.md: `3fff:0a00:...`
  - PERFORMANCE.md: `fd00:1d:...` and `3fff:1:...`
  Should standardize on one example allocation across all docs.
  Target: all documents.
  **Planned:** PREFIX-STANDARD.md defines canonical prefixes and per-document
  change mappings. Apply pending.

- [ ] **ULA prefix length inconsistency**
  ARCHITECTURE.md uses `/32` per cluster (ULA). PERFORMANCE.md Section 8
  uses `/48` for both modes. Need to reconcile.
  Target: ARCHITECTURE.md, PERFORMANCE.md, ROUTABLE-PREFIX.md.
  **Planned:** PREFIX-STANDARD.md standardizes on `/48` per cluster for
  both GUA and ULA. Apply pending.
