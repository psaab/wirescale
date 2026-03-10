# Wirescale: Closing Cilium's Security Isolation Gaps

> Cilium is an excellent intra-cluster CNI with strong L3-L7 policy
> enforcement. But as the sole security layer, it has structural gaps
> that limit isolation guarantees at scale: coarse identity granularity,
> unbounded blast radius from push-based state distribution, no
> hierarchical trust boundaries, all-or-nothing encryption, and
> TC-level ingress filtering that cannot match XDP drop rates.
>
> This document identifies each gap, explains why it matters for
> isolation, and describes how Wirescale's three-tier architecture
> closes it.
>
> Status: design document. Unless explicitly linked to implementation
> artifacts, behavior described here should be treated as target
> architecture.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are
> to be interpreted as described in RFC 2119 and RFC 8174 when shown
> in all caps.

**Companion documents:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Core Wirescale architecture
- [SECURITY.md](SECURITY.md) -- Wirescale security and dynamic access control
- [CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md) -- Component ownership when
  Cilium is the intra-cluster CNI
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Gap 1: Identity Granularity](#2-gap-1-identity-granularity)
3. [Gap 2: Blast Radius of State Distribution](#3-gap-2-blast-radius-of-state-distribution)
4. [Gap 3: No Hierarchical Trust Boundaries](#4-gap-3-no-hierarchical-trust-boundaries)
5. [Gap 4: All-or-Nothing Encryption](#5-gap-4-all-or-nothing-encryption)
6. [Gap 5: TC-Level Ingress Filtering](#6-gap-5-tc-level-ingress-filtering)
7. [Gap 6: No Time-Bounded Access Control](#7-gap-6-no-time-bounded-access-control)
8. [Gap 7: No External Peer Admission](#8-gap-7-no-external-peer-admission)
9. [Gap 8: Cross-Cluster Authentication](#9-gap-8-cross-cluster-authentication)
10. [Gap 9: Control Plane Compromise Blast Radius](#10-gap-9-control-plane-compromise-blast-radius)
11. [Gap 10: Graceful Degradation Under Attack](#11-gap-10-graceful-degradation-under-attack)
12. [Combined Isolation Model](#12-combined-isolation-model)
13. [Deployment Checklist](#13-deployment-checklist)

---

## 1. Executive Summary

Cilium provides strong intra-cluster security: eBPF-based L3/L4 policy
on every veth, L7 filtering via Envoy, WireGuard encryption, and
Hubble for flow visibility. For a single cluster at moderate scale
with no cross-cluster requirements, Cilium alone may be sufficient.

At scale, across clusters, or under adversarial conditions, ten
structural gaps emerge. Each gap weakens isolation in a specific,
exploitable way. The table below summarizes them:

| # | Gap | Cilium Limitation | Isolation Impact | Wirescale Closure |
|---|-----|-------------------|-----------------|-------------------|
| 1 | Identity granularity | Label-hash only (32-bit) | Pods with same labels share identity regardless of SA, node, or cluster | Structured tuple: (cluster, namespace, SA, labels, node) |
| 2 | Blast radius of state | Push all identities to all nodes | Any compromised node exposes complete identity map | Pull-based: each node knows only active flows |
| 3 | No hierarchical trust | Single cluster CA, flat ClusterMesh | Cluster CA compromise = total compromise; no tiered containment | Three-tier: global directory CA → cluster CA → node certs |
| 4 | All-or-nothing encryption | WireGuard on/off per cluster | Either encrypt everything (20-40% perf hit intra-site) or nothing | Selective: cross-site, cross-cluster, per-flow, or never |
| 5 | TC-level ingress | Host firewall at TC hook | 2-5 Mpps/core; sk_buff already allocated before drop | XDP on eth0: 14-26 Mpps/core; drop before kernel stack |
| 6 | No time-bounded access | Policies are permanent until deleted | Forgotten rules accumulate; no automatic expiry | WirescaleAccessGrant: mandatory expiry, approval workflow |
| 7 | No external peer admission | ClusterMesh is k8s-to-k8s only | Non-k8s nodes (laptops, CI) have no controlled mesh entry | WirescaleExternalPeer: pre-auth, admin approval, revocation |
| 8 | Cross-cluster auth | Pre-configured etcd endpoints | No federated CA; no mutual authentication between clusters | Hierarchical CA federation via global directory |
| 9 | Control plane blast radius | Operator + agent have full CRD access | Compromise exposes all identities + policies cluster-wide | PDP/PEP split; control has no private keys; pull limits exposure |
| 10 | Degradation under attack | etcd down = identity distribution stops | New pods unreachable; policy updates stall | Cached pull model; stale entries usable; data plane independent |

---

## 2. Gap 1: Identity Granularity

### The Problem

Cilium's identity is a 32-bit numeric ID derived from a hash of a
pod's **label set**. All pods with identical labels share the same
identity number, regardless of:

- Which ServiceAccount they run as
- Which node they run on
- Which cluster they belong to
- Which namespace they are in (labels can collide across namespaces)

```
Pod "payment-api-abc" in ns payments:
  labels: {app: api, tier: backend}
  SA: payment-sa
  -> Cilium identity: 48291

Pod "logging-api-xyz" in ns monitoring:
  labels: {app: api, tier: backend}
  SA: logging-sa
  -> Cilium identity: 48291  (SAME -- label set matches)
```

These two pods have completely different trust levels. One processes
payments, the other collects logs. But Cilium's policy engine treats
them as **identical** for L3/L4 decisions.

### Why This Breaks Isolation

**Scenario:** An attacker compromises `logging-api-xyz` in the
monitoring namespace. Because it shares Cilium identity 48291 with
`payment-api-abc`, any policy that allows traffic to identity 48291
implicitly allows traffic from the compromised logging pod to
payment-processing destinations:

```
CiliumNetworkPolicy:
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api
            tier: backend
      ports:
        - port: 8443
          protocol: TCP

Effect: BOTH payment-api AND logging-api can reach port 8443
        on the target. Compromising logging-api grants lateral
        movement to anything that trusts identity 48291.
```

**Namespace collision:** Cilium does include the namespace in the
identity tuple as of recent versions, but only as a label
(`k8s:io.kubernetes.pod.namespace`). Policies that select by
application labels without namespace selectors remain vulnerable to
cross-namespace identity collision.

### How Wirescale Closes This Gap

Wirescale's identity is a structured tuple:

```
(cluster_id, namespace, serviceAccount, labels, node)
```

Two pods with identical labels but different ServiceAccounts, nodes, or
namespaces have **different identities**. The BPF policy map keys include
all dimensions:

```
Wirescale identity for payment-api-abc:
  cluster:  us-east-prod
  ns:       payments
  sa:       payment-sa
  labels:   {app: api, tier: backend}
  node:     worker-7
  -> numeric identity: 1042

Wirescale identity for logging-api-xyz:
  cluster:  us-east-prod
  ns:       monitoring
  sa:        logging-sa
  labels:   {app: api, tier: backend}
  node:     worker-12
  -> numeric identity: 5891  (DIFFERENT)
```

Policy can now distinguish between the two:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: allow-payment-api-only
  namespace: database
spec:
  podSelector:
    matchLabels:
      app: payment-db
  ingress:
    - from:
        - serviceAccountSelector:
            names: [payment-sa]
            namespaces: [payments]
      ports:
        - protocol: TCP
          port: 5432
```

The compromised `logging-api` pod cannot reach `payment-db` because it
runs under `logging-sa`, not `payment-sa`. Even if labels match, the
ServiceAccount dimension blocks lateral movement.

### Combined Model

With Cilium as CNI, both identity systems coexist:

- **Cilium ipcache:** label-based identity for intra-cluster L3/L4 and
  L7 policy. Handles the fast path for the majority of intra-cluster
  traffic.
- **Wirescale identity cache:** structured tuple for cross-cluster
  identity, ServiceAccount-scoped policy, and any policy that requires
  finer granularity than labels alone.

For policies that reference ServiceAccount selectors, cluster selectors,
or node selectors, the Wirescale enforcement engine evaluates the richer
identity. Cilium's enforcement handles label-only policies at native
speed.

### Recommendation

Deployments that handle multi-tenant workloads, PCI-scoped traffic, or
sensitive cross-namespace communication SHOULD use Wirescale's
ServiceAccount-aware identity in addition to Cilium's label-based
identity. This provides defense-in-depth: Cilium catches the broad
strokes, Wirescale enforces the fine-grained boundaries.

---

## 3. Gap 2: Blast Radius of State Distribution

### The Problem

Cilium distributes identity and policy state via a push model: every
node watches `CiliumIdentity` CRDs and populates its local ipcache
with **all** identity-to-IP mappings in the cluster. With ClusterMesh,
this extends to all identities across all connected clusters.

```
Cilium push model (single cluster, 10K nodes, 100K pods):
  Every node holds: ~100K identity entries
  Every CiliumIdentity CRD change: propagates to all 10K nodes
  Total watch events/sec at 1% pod churn: ~280 events/sec/node

Cilium push model (10 clusters via ClusterMesh, 1M total pods):
  Every node holds: ~1M identity entries from all clusters
  State per node: ~100 MB (identity map alone)
  Background sync bandwidth: continuous
```

### Why This Breaks Isolation

**Compromised node exposure:** If an attacker compromises any single
node, they gain access to the complete identity map of the entire
cluster (and all ClusterMesh-connected clusters). This map reveals:

- Every pod IP and its label-based identity
- Every namespace and its pods
- The complete topology of services and their backends

This is a reconnaissance goldmine. The attacker knows exactly what
exists, where it runs, and what identity it has -- across every
connected cluster.

```
Attacker compromises worker-42:
  Reads /sys/fs/bpf/tc/globals/cilium_ipcache
  -> Complete IP-to-identity map for ALL pods in ALL clusters
  -> Knows every service, every backend, every identity number
  -> Can craft targeted attacks against specific high-value services
  -> Cross-cluster topology fully exposed via ClusterMesh sync
```

**State synchronization as attack surface:** The etcd watchers that
distribute CiliumIdentity CRDs are a broadcast channel. An attacker
who can inject CRDs (via API server compromise or etcd manipulation)
can push fraudulent identities to every node simultaneously. The blast
radius is total: all nodes, all clusters.

### How Wirescale Closes This Gap

Wirescale's pull-based model fundamentally limits what any single node
knows:

```
Wirescale pull model (same scale: 10K nodes, 100K pods):
  Each node holds: ~1K identity entries (active flows only)
  Identity lookups: on-demand, cached with TTL
  Background sync: zero (no watches, no push)

Wirescale pull model (10 clusters, 1M total pods):
  Each node holds: ~1K identity entries (unchanged)
  Cross-cluster entries: only for active cross-cluster flows
  No ClusterMesh. No etcd sync. No broadcast.
```

**Compromised node exposure (Wirescale):**

```
Attacker compromises worker-42:
  Reads BPF identity_cache map
  -> ~1K entries for pods this node actively communicates with
  -> No knowledge of pods on other nodes that don't talk to worker-42
  -> No cross-cluster topology (unless worker-42 has active cross-cluster flows)
  -> Reconnaissance value: minimal (active peers only, not fleet topology)
```

| Metric | Cilium (Push) | Wirescale (Pull) | Reduction |
|--------|--------------|-----------------|-----------|
| Identity entries exposed per compromised node | ALL (100K+) | ~1K (active only) | 100x+ |
| Cross-cluster topology exposed | ALL clusters | Active flows only | Orders of magnitude |
| Injected identity propagation | All nodes instantly | Only querying nodes, cached with TTL | Contained |
| Reconnaissance value of one node | Complete fleet map | Local communication partners | Minimal |

### Combined Isolation

With Cilium as CNI + Wirescale for cross-cluster:

- **Intra-cluster:** Cilium's ipcache still holds all local identities
  (this is unavoidable for Cilium's policy engine). The exposure per
  compromised node is bounded by local cluster size.
- **Cross-cluster:** Wirescale's pull model replaces ClusterMesh.
  Cross-cluster identities are resolved on demand and cached with TTL.
  A compromised node reveals only its active cross-cluster peers, not
  the topology of remote clusters.

The net effect: compromising a node in a 10-cluster deployment exposes
local cluster identities (Cilium, ~100K) but NOT the identities of the
other 9 clusters (~900K). Without Wirescale, ClusterMesh would expose
all ~1M.

### Recommendation

Deployments where node compromise is a credible threat (multi-tenant,
internet-facing, regulated) SHOULD use Wirescale's pull-based model for
cross-cluster identity to limit the blast radius of any single node
compromise. Even within a single cluster, operators SHOULD evaluate
whether the complete identity map on every node is an acceptable
information exposure.

---

## 4. Gap 3: No Hierarchical Trust Boundaries

### The Problem

Cilium operates within a single trust domain per cluster. The Cilium
agent and operator share a single cluster CA (or rely on the Kubernetes
API server's CA). ClusterMesh extends this by pre-configuring etcd
endpoints between clusters -- but there is no hierarchical certificate
chain, no tiered trust, and no concept of a "root of trust" that spans
clusters.

```
Cilium trust model:
  Cluster A: single CA -> signs all node/agent certs
  Cluster B: single CA -> signs all node/agent certs
  ClusterMesh: pre-configured etcd endpoints (no mutual CA validation)

  Cluster A CA compromised:
    -> ALL nodes in Cluster A can be impersonated
    -> ClusterMesh: Cluster A's identities propagate to Cluster B
    -> Cluster B trusts Cluster A's identities (no independent validation)
    -> Blast radius: Cluster A + all ClusterMesh-connected clusters
```

There is no mechanism for:
- A global root of trust that issues per-cluster intermediate CAs
- Mutual authentication between cluster controllers
- Revoking a single cluster from a federation without reconfiguring all
  others
- Tiered containment where cluster CA compromise does not propagate

### Why This Breaks Isolation

**Flat trust = flat blast radius.** When Cluster A's CA is compromised,
the attacker can forge certificates for any node in Cluster A. If
ClusterMesh connects Cluster A to Clusters B, C, and D, the forged
identities propagate via etcd sync to all connected clusters. There is
no trust boundary between them.

**No mutual authentication:** ClusterMesh does not require Cluster B to
validate Cluster A's CA against an independent root. The connection is
pre-configured and trusted implicitly.

**No selective revocation:** Removing a compromised cluster from a
ClusterMesh federation requires reconfiguring the etcd endpoints on
every remaining cluster. There is no "remove from directory" operation.

### How Wirescale Closes This Gap

Wirescale implements a three-level certificate hierarchy:

```
Level 1: Global Directory CA
  - Self-signed root (or externally rooted at org PKI)
  - Issues intermediate certificates to each cluster CA
  - Maintains registry: cluster_id -> cluster_CA_cert
  - Can revoke a cluster by removing its entry

Level 2: Cluster CA (per-cluster, issued by Level 1)
  - Signs node and agent certificates within its cluster
  - Managed by wirescale-control
  - Compromise affects ONLY this cluster
  - Revocable by global directory without affecting others

Level 3: Node Certificates (per-node, issued by Level 2)
  - Used for mTLS between agent and controller
  - Short-lived (default 24h, auto-renewed)
  - Revocable by controller without affecting other nodes
```

**Blast radius containment:**

| Compromise | Cilium (Flat) | Wirescale (Hierarchical) |
|------------|--------------|------------------------|
| Single node key | Node + its pods | Node + its pods (same) |
| Cluster CA | ALL nodes in cluster + ClusterMesh peers | ALL nodes in that cluster only |
| Cross-cluster propagation | Automatic via etcd sync | Blocked: other clusters validate via directory |
| Global directory compromise | N/A | Can inject fake clusters; intra-cluster unaffected |
| Recovery from cluster CA compromise | Reissue all certs + reconfigure all ClusterMesh peers | Revoke in directory; other clusters immediately stop trusting |

**Cross-cluster mutual authentication:**

```
Cluster A controller contacts Cluster B controller:
  1. A presents its cluster certificate (signed by directory CA)
  2. B validates A's cert chain: A cert -> A cluster CA -> directory CA
  3. B presents its cluster certificate
  4. A validates B's cert chain: B cert -> B cluster CA -> directory CA
  5. Both sides are mutually authenticated

If A's cluster CA is compromised:
  - Attacker can forge A-internal certs
  - Attacker CANNOT forge certs that chain to the directory CA
    (unless they also compromise the directory)
  - B validates A's cluster CA against what the directory registered
  - If the directory revokes A's entry, B immediately rejects A
```

**Selective revocation:**

```bash
# Revoke compromised cluster -- single operation
wirescale-directory revoke-cluster compromised-cluster-id

# Effect:
# - All other clusters querying the directory for this cluster get "not found"
# - Existing cross-cluster sessions time out (WireGuard rekey timer)
# - Intra-cluster operations in the compromised cluster continue
#   (but are no longer trusted by the federation)
# - No reconfiguration needed on any other cluster
```

### Recommendation

Multi-cluster deployments MUST use Wirescale's hierarchical trust chain
instead of ClusterMesh's flat trust model. Single-cluster deployments
with high security requirements SHOULD still deploy Wirescale's
cluster CA under a directory CA to enable future federation without
trust model changes.

---

## 5. Gap 4: All-or-Nothing Encryption

### The Problem

Cilium's WireGuard encryption has exactly two modes:

1. **Enabled:** All inter-node pod traffic is encrypted via `cilium_wg0`
2. **Disabled:** No WireGuard encryption

There is no concept of:
- Encrypting only cross-site traffic (different physical locations)
- Encrypting only cross-cluster traffic (different trust domains)
- Per-flow encryption based on policy (PCI workloads vs. bulk data)

```
Multi-site deployment with Cilium WireGuard enabled:
  Site A (DC-East) <-> Site A (DC-East): encrypted (unnecessary)
  Site A (DC-East) <-> Site B (DC-West): encrypted (necessary)

  Intra-site traffic pays 20-40% throughput cost for encryption
  that provides no security benefit (same trusted fabric).

Multi-site deployment with Cilium WireGuard disabled:
  Site A <-> Site A: unencrypted (acceptable)
  Site A <-> Site B: unencrypted (UNACCEPTABLE -- untrusted WAN)

  Cross-site traffic has no encryption over untrusted transit.
```

Operators are forced to choose between security and performance. There
is no middle ground.

### Why This Breaks Isolation

**Forced tradeoff:** In practice, operators who need cross-site
encryption enable WireGuard globally, accepting the ~20-40%
throughput reduction on ALL inter-node traffic, including traffic
that never leaves the trusted datacenter fabric. At 10 Gbps, this is
~2-4 Gbps of wasted capacity per link.

**Or they don't encrypt at all:** Some operators disable WireGuard to
preserve intra-site performance, leaving cross-site traffic exposed.
This is a real-world pattern: the "security tax" of all-or-nothing
encryption pushes operators toward no encryption.

**No policy-driven encryption:** PCI-DSS, HIPAA, and SOC2 require
encryption of specific traffic classes (cardholder data, PHI). Cilium
cannot express "encrypt only traffic to/from PCI-scoped pods." It's
all or nothing.

### How Wirescale Closes This Gap

Wirescale supports four encryption modes, configurable per-mesh and
overridable per-policy:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
spec:
  encryption:
    mode: cross-site    # or: always, cross-cluster, policy, never

    sites:
      - name: dc-east
        clusters: [cluster-1, cluster-4]
      - name: dc-west
        clusters: [cluster-2]
```

| Mode | Intra-Site | Cross-Site | Cross-Cluster (Same Site) | Per-Flow Override |
|------|-----------|-----------|--------------------------|-------------------|
| `never` | Plain | Plain | Plain | No |
| `cross-cluster` | Plain | Encrypted | Encrypted | Yes (policy) |
| `cross-site` | Plain | Encrypted | Plain (same site) | Yes (policy) |
| `always` | Encrypted | Encrypted | Encrypted | No |
| `policy` | Per-flow | Per-flow | Per-flow | Yes (default) |

**Per-flow policy encryption:**

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: encrypt-pci-traffic
  namespace: payments
spec:
  podSelector:
    matchLabels:
      pci: "true"
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: payment-gateway
      ports:
        - protocol: TCP
          port: 8443
      encryption: required     # THIS flow must be encrypted
```

The eBPF program on each pod's veth checks the `encrypt_map` BPF map
to determine per-destination encryption requirements:

```c
// Simplified decision logic
if (is_same_node(dst))       return PLAIN;   // local delivery
if (encrypt_map[dst] == REQUIRED) return REDIRECT_WG0;
if (mesh_mode == CROSS_SITE && is_same_site(dst)) return PLAIN;
if (mesh_mode == CROSS_SITE && !is_same_site(dst)) return REDIRECT_WG0;
// ... etc
```

### Performance Impact

| Scenario | Cilium (all-or-nothing) | Wirescale (selective) |
|----------|------------------------|---------------------|
| Intra-site, non-PCI | Encrypted (-20-40%) | Plain (line rate) |
| Intra-site, PCI | Encrypted | Encrypted (same) |
| Cross-site | Encrypted | Encrypted (same) |
| Aggregate throughput (80% intra-site) | ~60-80% of line rate | ~95% of line rate |

For a 10 Gbps link where 80% of traffic is intra-site: Cilium delivers
~6-8 Gbps effective. Wirescale's selective encryption delivers ~9.2 Gbps
effective. The gap widens at higher link speeds.

### Recommendation

Multi-site deployments MUST use Wirescale's selective encryption.
Deployments with compliance requirements (PCI, HIPAA) SHOULD use
`policy` mode to encrypt only regulated traffic, preserving line-rate
performance for the majority of flows.

---

## 6. Gap 5: TC-Level Ingress Filtering

### The Problem

Cilium's host firewall operates at the TC hook -- after the kernel has
already processed the packet through the NIC driver, allocated an
`sk_buff`, and entered the network stack:

```
Cilium ingress path:
  Physical NIC -> NIC driver -> sk_buff allocation -> kernel stack
    -> TC hook -> Cilium host firewall eBPF program
    -> DROP or PASS

  By the time the firewall sees the packet:
  - sk_buff memory has been allocated (~256 bytes per packet)
  - The packet has been processed by the NIC driver
  - Softirq context has been entered
  - GRO may have coalesced packets
```

### Why This Breaks Isolation

For pods with globally routable addresses (GUA, see
[ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md)), every pod is reachable from
the internet. DDoS attacks can target pod addresses directly.

**TC-level filtering under DDoS:**

```
DDoS: 10 Mpps attack against pod 3fff:1234:0001:0001::a

Cilium TC host firewall:
  - NIC receives 10 Mpps
  - Kernel allocates 10M sk_buffs/sec (~2.5 GB/sec of memory churn)
  - TC eBPF program drops packets at 2-5 Mpps/core
  - Remaining 5-8 Mpps overwhelm the kernel stack
  - Legitimate traffic competes with attack traffic for CPU
  - Result: service degradation or outage

  Effective drop rate: 2-5 Mpps/core
  Memory pressure: severe (sk_buff allocation for every attack packet)
```

Cilium does use XDP for service load-balancing (DSR mode), but NOT for
host-level ingress firewalling. The host firewall remains TC-based.

### How Wirescale Closes This Gap

Wirescale installs an XDP program on the physical NIC (`eth0`) that
drops external-to-pod traffic at the **driver level**, before `sk_buff`
allocation, before the kernel network stack:

```
Wirescale XDP ingress path:
  Physical NIC -> XDP program (driver level)
    -> DROP or PASS

  The XDP program runs before:
  - sk_buff allocation (no memory allocated for dropped packets)
  - Kernel network stack entry
  - Any softirq processing
  - GRO coalescing
```

**XDP filtering under DDoS:**

```
DDoS: 10 Mpps attack against pod 3fff:1234:0001:0001::a

Wirescale XDP ingress firewall:
  - NIC receives 10 Mpps
  - XDP program runs at driver level
  - External src + local pod dst + no allow rule -> XDP_DROP
  - Dropped at 14-26 Mpps/core (no sk_buff, no kernel stack)
  - Single core handles the full 10 Mpps attack
  - Legitimate traffic enters kernel stack unimpeded
  - Result: no service degradation

  Effective drop rate: 14-26 Mpps/core
  Memory pressure: zero (no sk_buff for dropped packets)
```

### Comparison

| Property | Cilium TC Host Firewall | Wirescale XDP Firewall |
|----------|------------------------|----------------------|
| Hook point | TC (after sk_buff alloc) | XDP (driver level) |
| Drop rate per core | 2-5 Mpps | 14-26 Mpps |
| Memory per dropped packet | ~256 bytes (sk_buff) | 0 bytes |
| DDoS at 10 Mpps | Service degradation | Single core handles it |
| DDoS at 50 Mpps | Outage | 2-3 cores handle it |
| Per-pod granularity | Yes (endpoint identity) | Yes (dst prefix match) |
| Configuration | CiliumClusterwideNetworkPolicy | BPF map (policy-driven) |

### Combined Defense

Both layers run simultaneously without conflict. XDP runs before TC:

```
Physical NIC
  |
  v
XDP (Wirescale): Drop external attacks at driver level
  | (only passed packets continue)
  v
Kernel stack -> sk_buff allocation
  |
  v
TC (Cilium): Per-pod L3/L4/L7 policy enforcement
  |
  v
Pod veth
```

Wirescale's XDP handles the volumetric attack. Cilium's TC handles the
fine-grained per-pod policy for traffic that passes XDP. The two layers
are complementary, not competing.

### Recommendation

Deployments with internet-routable pod addresses MUST install
Wirescale's XDP ingress firewall alongside Cilium's TC-based host
firewall. The XDP layer is the only defense that can sustain line-rate
drops under volumetric DDoS without kernel stack degradation.

---

## 7. Gap 6: No Time-Bounded Access Control

### The Problem

Cilium's `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`
are permanent until explicitly deleted. There is no native mechanism
for:

- Access that automatically expires after a fixed duration
- Maintenance windows that open and close on schedule
- Approval-gated access with audit trail
- Emergency debug access with mandatory timeout

```
Real-world scenario:

  1. 2:00 AM: On-call engineer creates CiliumNetworkPolicy to allow
     DBA access to production database for incident response
  2. 4:00 AM: Incident resolved. Engineer forgets to delete policy.
  3. Weeks later: The policy still exists. DBA tool has permanent
     access to production database that was intended to be temporary.
  4. Months later: Compliance audit discovers 47 "temporary" policies
     that were never cleaned up.
```

This is not a theoretical risk. Policy accumulation is one of the most
common causes of security drift in Kubernetes environments.

### How Wirescale Closes This Gap

Wirescale provides `WirescaleAccessGrant` -- a CRD with mandatory
time bounds, optional approval workflows, and automatic expiry:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleAccessGrant
metadata:
  name: incident-12345-db-access
  namespace: production
spec:
  requestor:
    serviceAccount:
      name: dba-tools
      namespace: oncall
  target:
    podSelector:
      matchLabels:
        app: payment-db
    ports:
      - protocol: TCP
        port: 5432
  duration: 2h                    # MANDATORY: auto-expires
  approval:
    required: true
    approvers:
      - user: oncall-lead@example.com
status:
  state: approved
  approvedBy: oncall-lead@example.com
  expiresAt: "2026-03-10T04:05:00Z"
```

**Lifecycle guarantees:**

```
T+0:     Grant created (state: pending)
T+5min:  Approver approves (state: approved, BPF rules pushed)
T+2h:    wirescale-control expires the grant:
           - state -> expired
           - BPF rules removed from all affected nodes
           - Audit event emitted
           - No human action needed

If not approved within 30 minutes: state -> denied (auto-reject)
If revoked early: state -> revoked, BPF rules immediately removed
```

**Key properties:**
- `duration` is mandatory. You cannot create a grant without a time bound.
- The controller's reconciliation loop enforces expiry even if the
  controller restarts.
- Every state transition is audit-logged with actor, timestamp, and
  affected pods.
- Grants cannot be silently extended; a new grant must be created and
  approved.

### Recurring Maintenance Windows

For scheduled operations (weekly database maintenance, nightly batch
jobs):

```yaml
spec:
  schedule:
    start: "2026-03-10T02:00:00Z"
    end: "2026-03-10T06:00:00Z"
    recurring: "RRULE:FREQ=WEEKLY;BYDAY=TH"
```

The controller activates and deactivates the BPF rules on schedule.
No human intervention. No forgotten cleanup.

### Recommendation

All temporary access SHOULD be created via `WirescaleAccessGrant` rather
than permanent `CiliumNetworkPolicy` or `WirescalePolicy` objects. The
mandatory expiry eliminates policy drift by construction.

---

## 8. Gap 7: No External Peer Admission

### The Problem

Cilium's network model is Kubernetes-to-Kubernetes. ClusterMesh
connects k8s clusters to other k8s clusters. There is no mechanism for:

- Developer laptops to join the mesh with controlled admission
- CI/CD runners outside the cluster to access in-cluster services
- Non-Kubernetes infrastructure (bare-metal servers, VMs) to
  participate in the mesh with identity and policy

```
Common workaround: VPN or SSH tunnel to a bastion host, then
kubectl port-forward to the target pod. This:
  - Bypasses all network policy (port-forward runs inside the pod)
  - Has no identity attribution (traffic appears to come from the pod)
  - Cannot be time-bounded or audited at the network layer
  - Is the de facto standard because Cilium has no alternative
```

### How Wirescale Closes This Gap

`WirescaleExternalPeer` provides a controlled admission path for
non-k8s nodes:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleExternalPeer
metadata:
  name: dev-laptop-alice
spec:
  publicKey: "eHl6MTIz..."
  endpoint: "[3fff:0e01::1]:51820"
  allowedIPs:
    - "3fff:1d:e1:1::1/128"
  authKeyRef:
    name: external-peer-keys
    key: dev-laptop-alice
status:
  approved: true
  lastSeen: "2026-03-10T09:55:00Z"
```

**Admission flow:**

```
1. Admin generates pre-auth key:
   kubectl wirescale generate-key --peer dev-laptop-alice

2. Developer receives key out-of-band (Slack, email, vault)

3. Developer runs wirescale-join on laptop:
   wirescale-join --auth-key <token> --control control.cluster.example.com:9443

4. wirescale-control validates:
   - Is the auth key valid and not expired?
   - Is the WirescaleExternalPeer object approved?
   - Does the presented public key match?

5. If valid: peer is admitted with scoped AllowedIPs
   - WireGuard tunnel established
   - Identity assigned: (external, dev-laptop-alice, labels)
   - Policy applies: only allowed destinations reachable

6. All traffic is:
   - Encrypted (WireGuard)
   - Identity-attributed (external peer identity)
   - Policy-enforced (same eBPF engine as pod traffic)
   - Audited (same connection log format)
```

**Versus bastion/port-forward:**

| Property | Bastion + Port-Forward | WirescaleExternalPeer |
|----------|----------------------|----------------------|
| Policy bypass | Yes (port-forward is in-pod) | No (BPF policy enforced) |
| Identity attribution | None (appears as pod traffic) | Full (external peer identity) |
| Time-bounded | No | Yes (via AccessGrant) |
| Audit trail | SSH log only | Full network flow audit |
| Multi-service access | One port-forward per service | Native routing to all allowed pods |
| Revocation | Kill SSH session | Remove from control registry |

### Recommendation

Deployments that require developer access to in-cluster services or
integration with non-k8s infrastructure MUST use
`WirescaleExternalPeer` for identity-attributed, policy-enforced mesh
access. Bastion + port-forward patterns SHOULD be replaced.

---

## 9. Gap 8: Cross-Cluster Authentication

### The Problem

Cilium ClusterMesh connects clusters by pre-configuring etcd endpoints:

```yaml
# ClusterMesh: manual endpoint configuration
cluster1:
  endpoints:
    - https://clustermesh-apiserver-1.cluster2.example.com:2379
  ca-file: /var/lib/cilium/clustermesh/cluster2-ca.crt
```

There is no:
- Mutual authentication protocol between clusters
- Federated certificate authority
- Directory service for cluster discovery
- Automatic rotation of cross-cluster credentials
- Revocation mechanism that doesn't require manual reconfiguration of
  all remaining clusters

Each cluster must be manually configured to trust each other's etcd
endpoint. Adding cluster N+1 requires updating N existing clusters.
Removing a compromised cluster requires reconfiguring N-1 clusters.

### How Wirescale Closes This Gap

The global directory provides federated cluster authentication:

```
Adding a new cluster:
  1. Cluster registers with global directory (one operation)
  2. All other clusters discover it via directory queries
  3. Cross-cluster connections use mutual TLS with CA certs
     validated against the directory's registry
  4. No reconfiguration of existing clusters needed

Removing a compromised cluster:
  1. Admin revokes cluster in global directory (one operation)
  2. All other clusters get "not found" on next directory query
  3. Existing cross-cluster sessions time out
  4. No reconfiguration of remaining clusters needed
```

**Authentication chain for cross-cluster communication:**

```
Cluster A controller -> Global directory: "info for Cluster B?"
  Directory validates A's cluster cert (signed by directory CA)
  Directory returns B's CA cert, endpoints

Cluster A controller -> Cluster B controller: mutual TLS
  A presents cert: A-controller cert -> A cluster CA -> directory CA
  B validates: checks A's cluster CA is registered in directory
  B presents cert: B-controller cert -> B cluster CA -> directory CA
  A validates: checks B's cluster CA is registered in directory

  Both sides mutually authenticated.
  Credential rotation is automatic (certificate renewal).
  Revocation is instant (directory entry removal).
```

| Operation | ClusterMesh | Wirescale Directory |
|-----------|-------------|-------------------|
| Add cluster N+1 | Update N clusters' configs | Register in directory (1 operation) |
| Remove compromised cluster | Update N-1 configs | Revoke in directory (1 operation) |
| Rotate cross-cluster creds | Manual cert redistribution | Automatic (cert renewal via directory CA) |
| Discover new cluster | Pre-configured | On-demand via directory query |
| Mutual authentication | Implicit (etcd TLS) | Explicit (federated CA chain) |

### Recommendation

Multi-cluster deployments MUST use Wirescale's global directory for
cross-cluster authentication. The directory provides O(1) cluster
addition and removal versus ClusterMesh's O(N) reconfiguration cost.

---

## 10. Gap 9: Control Plane Compromise Blast Radius

### The Problem

Cilium's control plane consists of the Cilium operator and per-node
Cilium agent. The operator has broad RBAC permissions to manage all
Cilium CRDs, and every agent watches all `CiliumIdentity` and
`CiliumEndpoint` CRDs across the cluster.

**If the Cilium operator is compromised:**

```
Attacker controls Cilium operator:
  CAN:
  - Create/modify/delete ANY CiliumIdentity (forge identities)
  - Create/modify/delete ANY CiliumNetworkPolicy (open all traffic)
  - Modify CiliumNode CRDs (corrupt WireGuard peer info)
  - Read ALL identity-to-IP mappings (complete topology)
  - Push forged identities to ALL nodes via CRD modification

  Effect: Complete control over network identity and policy for
  the entire cluster. All nodes receive forged state via CRD watches.
```

The blast radius is total because the push model means all nodes
consume all state. A single compromised component can corrupt the
security posture of every node simultaneously.

### How Wirescale Closes This Gap

Wirescale's PDP/PEP split and pull-based model limit what any single
compromise can achieve:

**wirescale-control compromise:**

```
Attacker controls wirescale-control:
  CAN:
  - Serve incorrect identity mappings to querying nodes
  - Authorize fraudulent peer connections
  - Weaken compiled policies for nodes that pull updates

  CANNOT:
  - Decrypt ANY data-plane traffic (no private keys in control)
  - Inject packets into existing WireGuard sessions
  - Impersonate one node to another (WireGuard mutual auth is
    independent of control once handshake completes)
  - Affect nodes that do not actively query (pull model)
  - Access WireGuard private keys (memory-only, node-local)
```

**Critical difference: data plane independence.**

Once a WireGuard handshake completes, the session is authenticated
purely by the Curve25519 keypair. The control plane is not involved.
Even a fully compromised control plane cannot:
- Read encrypted traffic
- Inject traffic into established sessions
- Impersonate nodes in existing tunnels

Cilium's model is similar (the agent manages WireGuard locally), but
the push-based identity distribution means a compromised operator can
corrupt identity on all nodes simultaneously. Wirescale's pull-based
model means only nodes that actively query receive corrupted data, and
only for the specific identities they request.

| Compromise Scenario | Cilium Impact | Wirescale Impact |
|--------------------|--------------|-----------------|
| Operator/control compromise | All nodes get forged identities via CRD push | Only querying nodes get forged identities |
| Forged identity window | Permanent until detected | TTL-bounded (default 60s per cache entry) |
| Data-plane traffic exposure | None (WireGuard keys are node-local) | None (same) |
| Existing session impact | None (WireGuard is independent) | None (same) |
| Recovery | Restart operator, recreate CRDs | Restart control; agents re-query and get correct data |

### Recommendation

Wirescale's control plane SHOULD be deployed with:
- Restricted RBAC (agent has NO CRD access; all operations via gRPC)
- Rate limiting on control APIs (detect anomalous query patterns)
- Audit logging on all control operations
- Short TTL on cached identity entries (limit window of corruption)

---

## 11. Gap 10: Graceful Degradation Under Attack

### The Problem

When Cilium's control plane components fail (operator crash, etcd
outage, API server overload), the identity distribution pipeline stops:

```
Cilium degradation under control plane failure:

  API server down:
  - No new CiliumIdentity CRDs created
  - No new CiliumNetworkPolicy updates
  - No CiliumNode updates
  - New pods: no identity assigned, no policy, traffic dropped or
    allowed depending on default
  - Existing pods: last-known identity and policy (stale but usable)

  etcd down (ClusterMesh):
  - Cross-cluster identity sync halts
  - New cross-cluster connections may fail
  - Existing cross-cluster identities stale

  Cilium operator crash:
  - IPAM stops: new nodes get no pod CIDRs
  - Identity GC stops: deleted pod identities accumulate
```

The push model depends on a functioning pipeline from API server
through operator to agent. Any break in this pipeline halts state
distribution.

### How Wirescale Closes This Gap

Wirescale's pull-based model is designed for graceful degradation:

```
wirescale-control down:
  CONTINUES WORKING:
  - All existing WireGuard sessions (independent of control)
  - All cached identities (stale entries usable beyond TTL)
  - All cached policies (last-known rules enforced)
  - All existing peer connections (no control involvement in data plane)
  - Intra-node pod communication (no control needed)

  DEGRADED:
  - New peer establishment: delayed until control recovers
  - New identity resolution: returns cache miss (drop or queue)
  - Policy updates: last-known policy continues
  - New pod registration: delayed

  AGENT BEHAVIOR:
  - MUST NOT remove cached entries when control is unreachable
  - MUST extend TTL on existing entries during control outage
  - MUST log control unavailability as a metric
  - MUST continue enforcing last-known policy
```

**Key difference: the data plane is self-sustaining.**

Once WireGuard sessions are established and identity/policy caches are
populated, the data plane operates with zero control-plane involvement.
A control plane outage affects only new connections and policy changes,
not existing traffic.

```
Degradation comparison under 30-minute control plane outage:

Cilium:
  - Existing pods: traffic continues (last-known identity/policy)
  - New pods: no identity, no policy, potentially dropped or misrouted
  - New cross-cluster: ClusterMesh etcd sync stalled
  - Cross-cluster new connections: may fail

Wirescale:
  - Existing pods: traffic continues (cached identity/policy)
  - New pods: can communicate with pods on same node; cross-node
    delayed until control recovers
  - Existing cross-cluster: continues (WireGuard sessions independent)
  - Cross-cluster new connections: delayed (cache miss for new peers)
  - All cached entries remain valid during outage (extended TTL)
```

### Recommendation

Wirescale-control SHOULD be deployed as an HA service (3+ replicas)
with circuit breakers. Agents MUST implement graceful degradation as
specified: extend TTL during outage, continue enforcing last-known
policy, log degradation metrics.

---

## 12. Combined Isolation Model

When Cilium and Wirescale are deployed together, the combined security
model provides layered isolation that neither system achieves alone:

```
Layer 0: Hierarchical Trust (Wirescale)
  Global directory CA → Cluster CA → Node certs
  Tiered blast radius containment
  Cross-cluster mutual authentication via federated CAs

Layer 1: Node Authentication (Both)
  Cilium: agent authenticates to API server
  Wirescale: agent authenticates to control via mTLS
  Both: node must be valid before participating

Layer 2: Data-Plane Encryption (Both)
  Cilium: cilium_wg0 (intra-cluster, full-mesh)
  Wirescale: wg0 (cross-cluster, on-demand + selective encryption)
  Combined: all inter-node traffic encrypted; cross-site selective

Layer 3: Ingress DDoS Protection (Wirescale)
  XDP on eth0: 14-26 Mpps drop rate for external-to-pod traffic
  Runs before Cilium's TC hooks -- first line of defense

Layer 4: L3/L4 Policy (Cilium)
  TC eBPF on every pod veth
  CiliumNetworkPolicy enforcement
  High-performance per-packet filtering

Layer 5: L7 Policy (Cilium)
  Envoy proxy for HTTP, gRPC, DNS, Kafka
  FQDN-based egress control
  (Wirescale has no L7 equivalent)

Layer 6: Identity-Aware Policy (Both)
  Cilium: label-based identity (fast, broad)
  Wirescale: (cluster, namespace, SA, labels, node) identity (precise)
  Combined: broad coverage + fine-grained sensitive-flow control

Layer 7: Time-Bounded Access (Wirescale)
  WirescaleAccessGrant with mandatory expiry
  Approval workflow with audit trail
  Automatic cleanup -- no policy drift

Layer 8: Cross-Cluster Isolation (Wirescale)
  Pull-based identity: minimal exposure per node
  Signaling gateways: control plane only, not data path
  Dual-side policy enforcement: both clusters must allow

Layer 9: External Peer Control (Wirescale)
  WirescaleExternalPeer: controlled admission
  Pre-auth + approval + identity + policy
  Replaces bastion/port-forward antipattern

Layer 10: Audit (Both)
  Cilium: Hubble (L3-L7 flow events, drop reasons, metrics)
  Wirescale: control-plane audit (peer auth, identity resolution,
    policy compilation, access grants, cross-cluster operations)
  Combined: complete visibility from packet drops to policy decisions
```

### What Each System Contributes

```
Cilium provides:
  + Intra-cluster L3/L4/L7 policy (best in class)
  + Hubble observability (best in class)
  + Bandwidth management (EDT + BBR)
  + Intra-cluster WireGuard (standard)
  + FQDN egress control

Wirescale provides:
  + Cross-cluster isolation (pull-based, bounded blast radius)
  + Hierarchical trust (three-tier CA, selective revocation)
  + Selective encryption (cross-site/cross-cluster/per-flow)
  + XDP DDoS protection (14-26 Mpps/core)
  + Time-bounded access (mandatory expiry)
  + External peer admission (identity + policy + audit)
  + ServiceAccount-aware identity (finer than labels)
  + IPv4 compatibility (CLAT/NAT64/DNS64)
  + Graceful degradation (pull-based caching)
```

---

## 13. Deployment Checklist

For operators deploying Cilium + Wirescale with maximum isolation:

### Identity and Policy

- [ ] Deploy Cilium with `CiliumNetworkPolicy` for intra-cluster L3-L7
- [ ] Deploy Wirescale `WirescalePolicy` for ServiceAccount-scoped and
      cross-cluster policies
- [ ] Ensure default-deny ingress baseline is installed (either
      CiliumClusterwideNetworkPolicy or WirescalePolicy)
- [ ] Verify identity granularity: policies referencing ServiceAccounts
      use Wirescale identity, not Cilium label-only identity

### Encryption

- [ ] Configure Wirescale encryption mode (`cross-site` or
      `cross-cluster`) -- do NOT rely on Cilium's all-or-nothing
- [ ] For compliance workloads: add `encryption: required` to relevant
      WirescalePolicy objects
- [ ] Disable Cilium WireGuard if using `cross-site` mode (avoid
      double encryption intra-site); OR enable Cilium WireGuard for
      intra-cluster and Wirescale for cross-cluster

### Trust and Authentication

- [ ] Deploy `wirescale-directory` with multi-region HA
- [ ] Register all clusters with the directory (three-tier CA chain)
- [ ] Verify cross-cluster mutual TLS authentication works
- [ ] Test cluster revocation: can a compromised cluster be removed
      with a single directory operation?

### Ingress Protection

- [ ] Verify Wirescale XDP ingress firewall is installed on `eth0`
      on all nodes with GUA-addressed pods
- [ ] Test DDoS drop rate (should sustain 14+ Mpps/core)
- [ ] Verify Cilium TC host firewall runs after XDP (defense in depth)

### Access Control

- [ ] Replace all "temporary" CiliumNetworkPolicies with
      WirescaleAccessGrant objects
- [ ] Verify automatic expiry: create a grant, wait for duration,
      confirm BPF rules are removed
- [ ] Set up approval workflow for production access grants

### External Peers

- [ ] Replace bastion + port-forward patterns with
      WirescaleExternalPeer
- [ ] Verify external peer identity appears in audit logs
- [ ] Verify policy enforcement applies to external peer traffic

### Monitoring

- [ ] Hubble enabled for intra-cluster flow visibility
- [ ] Wirescale control-plane audit logging enabled
- [ ] Prometheus scraping both Cilium and Wirescale metrics
- [ ] Alerting on: control plane unavailability, identity cache miss
      spike, cross-cluster resolution failures, access grant expiry
      failures

### Degradation Testing

- [ ] Kill wirescale-control: verify existing traffic continues,
      verify new connections are delayed (not dropped permanently)
- [ ] Kill Cilium operator: verify existing policy holds
- [ ] Partition a cluster from the directory: verify intra-cluster
      operations continue, cross-cluster new connections degrade
- [ ] Simulate node compromise: verify blast radius matches
      expectations (local identities exposed, not remote cluster
      topology)
