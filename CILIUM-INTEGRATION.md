# Wirescale: Cilium Integration Architecture

> How Cilium and Wirescale complement each other: Cilium as the
> intra-cluster CNI, Wirescale's three-tier hierarchy for cross-cluster
> connectivity at hyperscale.
>
> **Key message:** Cilium is excellent within a cluster. Wirescale's
> three-tier hierarchy and on-demand model replaces ClusterMesh for
> cross-cluster connectivity at hyperscale. The two are complementary,
> not competing.
>
> Status: design comparison document. Unless explicitly linked to
> implementation artifacts, behavior described here should be treated
> as target architecture.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are
> to be interpreted as described in RFC 2119 and RFC 8174 when shown
> in all caps.

**Companion documents:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Core Wirescale architecture
  (three-tier hierarchy, on-demand peering, ULA overlay)
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
- [SECURITY.md](SECURITY.md) -- Network security and dynamic access control
- [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) -- Globally routable /64-per-host
  design
- [CILIUM-SECURITY-GAPS.md](CILIUM-SECURITY-GAPS.md) -- Security isolation
  gaps in Cilium-only deployments and how Wirescale closes them
- [EGRESS.md](EGRESS.md) -- Internet egress architecture (NPTv6, NAT64,
  FQDN policy, egress observability)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Three-Tier Hierarchy Meets Cilium](#2-three-tier-hierarchy-meets-cilium)
3. [Component Ownership: Cilium vs Wirescale](#3-component-ownership-cilium-vs-wirescale)
4. [Intra-Cluster: Cilium's Role Is Unchanged](#4-intra-cluster-ciliums-role-is-unchanged)
5. [Multi-Cluster: ClusterMesh vs Global Directory](#5-multi-cluster-clustermesh-vs-global-directory)
6. [Signaling Gateway Model](#6-signaling-gateway-model)
7. [Data Plane Comparison](#7-data-plane-comparison)
8. [Identity Model: Push vs Pull](#8-identity-model-push-vs-pull)
9. [Ingress Security for Internet-Routable Pods](#9-ingress-security-for-internet-routable-pods)
10. [Performance and Scaling Analysis](#10-performance-and-scaling-analysis)
11. [Component-by-Component Diff](#11-component-by-component-diff)
12. [Deployment Decision Matrix](#12-deployment-decision-matrix)

---

## 1. Executive Summary

When Cilium is the CNI within a cluster, the Wirescale architecture
changes from a full CNI replacement to a **cross-cluster connectivity
and IPv4 compatibility layer**. Cilium absorbs the entire intra-cluster
data plane: veth/netkit management, kernel route programming, WireGuard
encryption, eBPF policy enforcement, and observability. Wirescale's
three-tier control hierarchy provides what Cilium cannot: on-demand
cross-cluster peering, federated identity without global state sync,
and IPv4 compatibility for IPv6-only clusters.

### What Cilium Handles (Intra-Cluster)

| Function | Mechanism |
|----------|-----------|
| CNI binary (veth/netkit creation, IP assignment) | Cilium CNI |
| WireGuard intra-cluster encryption | Cilium agent (`cilium_wg0`) |
| eBPF policy enforcement (L3/L4) | TC/netkit eBPF on lxc interfaces |
| L7 policy (HTTP, gRPC, DNS) | Cilium + Envoy |
| Identity model (intra-cluster) | Cilium security identities + ipcache |
| Observability | Hubble |
| Kernel route programming | Cilium agent |
| Bandwidth management | Cilium EDT + BBR |

### What Wirescale Handles (Cross-Cluster + IPv4)

| Function | Why Cilium Cannot Do It |
|----------|------------------------|
| **Cross-cluster identity resolution** | ClusterMesh requires O(clusters x pods) state sync |
| **On-demand cross-cluster WireGuard** | ClusterMesh has no on-demand peering concept |
| **Signaling gateways** | ClusterMesh is data-path, not signaling-only |
| **CLAT (per-pod IPv4 via TUN)** | Cilium has no CLAT support |
| **Per-node stateless NAT64** | Cilium NAT46x64 is gateway-centric and stateful |
| **DNS64 (CoreDNS plugin)** | Cilium does not provide DNS64 |
| **Profile-based encryption** (`trusted-site`, `encrypted-routable`) | Cilium WireGuard is all-or-nothing per cluster |
| **XDP ingress firewall for GUA pods** | Cilium host firewall is TC-based, not XDP |
| **External peer mesh (non-k8s nodes)** | Cilium ClusterMesh is k8s-to-k8s only |

### Net Result

```
Cilium:      CNI + intra-cluster WireGuard + L3-L7 policy + Hubble + bandwidth
Wirescale:   Cross-cluster connectivity + CLAT/NAT64/DNS64 + signaling gateways
Fabric:      BGP routing for rack /64 and pod /64 (unchanged)
```

---

## 2. Three-Tier Hierarchy Meets Cilium

Wirescale uses a three-tier control hierarchy that fundamentally changes
how cross-cluster connectivity works. Each tier has a distinct role, and
Cilium integration affects each tier differently.

### Tier 1: Global Directory (`wirescale-directory`)

The global directory is the root of trust for cross-cluster operations.
It maintains O(clusters) state:

```
wirescale-directory state per cluster entry:
  cluster_id:         "us-east-prod"
  gateway_endpoints:  [203.0.113.1:51820, 203.0.113.2:51820]
  prefix_allocation:  3fff:1234:0001::/48
  cluster_ca_cert:    <PEM>
  last_heartbeat:     <timestamp>
```

**With Cilium:** The global directory is completely independent of
Cilium. It does not interact with Cilium components at all. Its scope is
cross-cluster: mapping cluster IDs to gateway endpoints, prefix
allocations, and CA certificates. Cilium has no equivalent -- ClusterMesh
requires pre-configured etcd endpoints rather than a directory service.

### Tier 2: Cluster Controller (`wirescale-control`)

The cluster controller is per-cluster. It knows all local nodes and
pods, handles identity and policy within the cluster, and serves as the
local authority for authentication and authorization.

**With Cilium:** The cluster controller's scope narrows significantly.
Cilium handles intra-cluster identity (CiliumIdentity CRDs), intra-cluster
policy (CiliumNetworkPolicy), and intra-cluster WireGuard peer management.
The cluster controller retains:

- **Cross-cluster peer brokering** -- resolving remote cluster endpoints
  via the global directory
- **Cross-cluster identity resolution** -- pull-based queries for remote
  pod identities
- **External peer management** -- non-k8s nodes outside Cilium's scope
- **NAT64/CLAT coordination** -- IPv4 compatibility layer
- **Profile-based encryption decisions** -- which flows require WireGuard
  per the active deployment profile

### Tier 3: Node Agent (`wirescale-agent`)

The node agent runs on every node with minimal state. It maintains only
active peers and uses pull-based caching for identity and policy.

**With Cilium:** The node agent's scope reduces to:

```
wirescale-agent responsibilities (with Cilium):
  1. CLAT engine -- create clat0 TUN in each pod's netns, assign 100.64.N.P
  2. NAT64 engine -- per-node stateless SIIT translation
  3. DNS64 -- ensure CoreDNS has dns64 plugin configured
  4. XDP ingress firewall -- eth0 XDP program for GUA pod protection
  5. Cross-site WireGuard -- on gateway nodes only, on-demand peers
  6. Control client -- pull-based queries to wirescale-control

NOT responsible for (Cilium handles):
  - veth/netkit creation (Cilium CNI)
  - IPv6 address assignment (Cilium IPAM)
  - Intra-cluster WireGuard (Cilium agent)
  - L3/L4/L7 policy enforcement (Cilium eBPF + Envoy)
  - Observability (Hubble)
  - Host route installation (Cilium CNI)
```

### Three-Tier Architecture Diagram (with Cilium)

```
+=====================================================================+
|                    TIER 1: GLOBAL DIRECTORY                          |
|                                                                     |
|  wirescale-directory                                                |
|    cluster_id -> {gateways, prefix, CA_cert}                        |
|    O(clusters) state -- tens to hundreds of entries                  |
|    Root of trust for cross-cluster authentication                   |
+=====================================================================+
         |                                           |
    directory queries                          directory queries
         |                                           |
+=========================+             +=========================+
| TIER 2: CLUSTER A       |             | TIER 2: CLUSTER B       |
|                          |             |                          |
| +----------------------+ |             | +----------------------+ |
| | wirescale-control    | |             | | wirescale-control    | |
| |  Cross-cluster peer  | |             | |  Cross-cluster peer  | |
| |  broker, external    |<-- on-demand -->|  broker, external    | |
| |  identity, CLAT/NAT64|  resolution   | |  identity, CLAT/NAT64| |
| +----------------------+ |             | +----------------------+ |
|                          |             |                          |
| +----------------------+ |             | +----------------------+ |
| | Cilium operator      | |             | | Cilium operator      | |
| |  Intra-cluster IPAM, | |             | |  Intra-cluster IPAM, | |
| |  identity, policy    | |             | |  identity, policy    | |
| +----------------------+ |             | +----------------------+ |
+=========================+             +=========================+
         |                                           |
+=========================+             +=========================+
| TIER 3: NODE AGENTS      |             | TIER 3: NODE AGENTS      |
|                          |             |                          |
| Cilium agent:            |             | Cilium agent:            |
|   CNI, WG, policy,      |             |   CNI, WG, policy,      |
|   Hubble, bandwidth     |             |   Hubble, bandwidth     |
|                          |             |                          |
| wirescale-agent:         |             | wirescale-agent:         |
|   CLAT, NAT64, XDP,     |             |   CLAT, NAT64, XDP,     |
|   cross-site WG (gw),   |             |   cross-site WG (gw),   |
|   control client         |             |   control client         |
+=========================+             +=========================+
```

---

## 3. Component Ownership: Cilium vs Wirescale

### Per-Node Components

```
+------------------------------------------------------------+
| Cilium agent (DaemonSet)                                   |
|                                                            |
|  +------------------+  +------------------+  +-----------+ |
|  | Cilium CNI       |  | cilium_wg0       |  | Policy    | |
|  | - lxc/netkit     |  | - kernel WG      |  | Enforcer  | |
|  | - IPv6 addr      |  | - intra-cluster  |  | (eBPF on  | |
|  | - host routes    |  |   peer mgmt      |  |  lxc/nk)  | |
|  +------------------+  +------------------+  +-----------+ |
|                                                            |
|  +------------------+  +------------------+  +-----------+ |
|  | Hubble           |  | Envoy (L7)       |  | Bandwidth | |
|  | - flow events    |  | - HTTP/gRPC      |  | Manager   | |
|  | - gRPC server    |  | - FQDN egress    |  | (EDT+BBR) | |
|  +------------------+  +------------------+  +-----------+ |
+------------------------------------------------------------+

+------------------------------------------------------------+
| wirescale-agent (DaemonSet, reduced scope)                 |
|                                                            |
|  +------------------+  +------------------+                |
|  | NAT64 Engine     |  | CLAT Engine      |                |
|  | (eBPF on nat64   |  | (per-pod IPv4    |                |
|  |  interface)      |  |  via clat0 TUN)  |                |
|  +------------------+  +------------------+                |
|                                                            |
|  +------------------+  +------------------+                |
|  | XDP Ingress FW   |  | Control Client   |                |
|  | (on eth0, DDoS   |  | (pull-based      |                |
|  |  protection)     |  |  queries to      |                |
|  +------------------+  |  wirescale-       |                |
|                         |  control)        |                |
|  +------------------+  +------------------+                |
|  | Cross-Site WG    |                                      |
|  | (gateway nodes   |                                      |
|  |  only, on-demand |                                      |
|  |  via directory)  |                                      |
|  +------------------+                                      |
+------------------------------------------------------------+
```

### Control Plane Ownership

```
Tier 1 -- wirescale-directory (global):
  Maps cluster_id -> {gateway_endpoints, prefix_allocation, cluster_CA_cert}
  Root of trust for cross-cluster mutual authentication
  No Cilium equivalent exists

Tier 2 -- Cilium operator (per-cluster):
  IPAM (/64 allocation via Node.spec.podCIDRs)
  CiliumNode management
  Intra-cluster identity (CiliumIdentity CRDs)
  CiliumNetworkPolicy compilation

Tier 2 -- wirescale-control (per-cluster, complementary):
  Cross-cluster peer brokering (via directory lookups)
  Pull-based identity resolution for external and cross-cluster peers
  NAT64/CLAT coordination
  External peer management (non-k8s nodes)
  WirescaleAccessGrant lifecycle (time-bounded access)

Tier 3 -- agent -> control:
  wirescale-agent queries wirescale-control for cross-cluster
  identity, policy, and peer information (pull-based with local
  TTL cache, NOT CRD watches)
```

> **See also:** [EGRESS.md §14](EGRESS.md#14-interaction-with-cilium) defines the
> egress ownership split when Cilium is the CNI -- Cilium handles intra-cluster
> policy and L7, Wirescale handles internet egress via NPTv6/NAT64.

---

## 4. Intra-Cluster: Cilium's Role Is Unchanged

Cilium is an excellent intra-cluster CNI. When deployed alongside
Wirescale, Cilium's intra-cluster role MUST NOT be modified or
constrained. The sections below document what Cilium handles within a
single cluster and why no Wirescale intervention is needed.

### Address Architecture

The IPv6 address plan is identical whether Cilium or Wirescale manages
the data plane. The fabric, not the CNI, owns the address topology.

```
Site A (DC-East):        3fff:1234:0001::/48
  Rack /64s:             3fff:1234:0001:ff00::/56  (one per rack, shared L2)
    Rack 1:              3fff:1234:0001:ff01::/64
  Pod /64s:              3fff:1234:0001:0000::/52  (one per host, routed)
    worker-1:            3fff:1234:0001:0001::/64

Per host:
  eth0 (rack):           3fff:1234:0001:ff01::11/128  (from rack /64)
  Pod /64:               3fff:1234:0001:0001::/64     (dedicated, fabric-routed)
```

Cilium's IPAM in **Kubernetes host-scope mode** reads `spec.podCIDRs`
from the Node object:

```yaml
apiVersion: v1
kind: Node
metadata:
  name: worker-1
spec:
  podCIDRs:
    - "3fff:1234:0001:0001::/64"    # pod /64 from site allocation
```

Cilium reads this and allocates pod IPs from the /64. Configuration:

```yaml
# Cilium Helm values
ipam:
  mode: kubernetes           # use Node.spec.podCIDRs
ipv6NativeRoutingCIDR: "3fff:1234:0001::/48"  # site prefix, no masquerade
```

The `ipv6NativeRoutingCIDR` tells Cilium that traffic within the site
/48 SHOULD NOT be masqueraded, preserving pod source IPs end-to-end.

### Routing and Native Data Plane

Cilium operates in **native routing mode** (no VXLAN/Geneve overlay).
The fabric's BGP installs kernel routes for each remote node's pod /64:

```
# Kernel routing table on worker-1 (installed by fabric BGP, not Cilium):
3fff:1234:0001:0002::/64 via 3fff:1234:0001:ff01::12 dev eth0   # host-2, same rack
3fff:1234:0001:0003::/64 via 3fff:1234:0001:ff01::1  dev eth0    # host-3, via ToR
::/0                     via 3fff:1234:0001:ff01::1  dev eth0    # default route
```

Cilium delegates all non-local forwarding to these kernel routes.

Cilium embeds a BGP speaker (GoBGP) via `CiliumBGPClusterConfig`.
Since the fabric already handles BGP (per ROUTABLE-PREFIX.md), Cilium's
BGP Control Plane SHOULD NOT be deployed.

### Intra-Cluster WireGuard

Cilium manages `cilium_wg0` for intra-cluster encryption. This uses the
same kernel WireGuard module as Wirescale -- identical crypto, identical
GRO/GSO amortization, identical performance.

| Property | Cilium WireGuard |
|----------|-----------------|
| Interface | `cilium_wg0` |
| Listen port | 51871 |
| Key storage | CiliumNode annotation |
| Peer model | Full-mesh (all nodes) |
| AllowedIPs | Pod /64 per peer |
| Conntrack bypass | eBPF-only data path (no kernel conntrack loaded) |

### Intra-Cluster Policy

Cilium provides comprehensive L3-L7 policy enforcement:

- **L3/L4:** TC eBPF on lxc/netkit interfaces
- **L7:** HTTP path/method, gRPC services, Kafka topics, DNS queries
  via Envoy proxy
- **FQDN egress:** DNS proxy intercepts queries and dynamically allows
  connections to resolved IPs
- **Bandwidth management:** Per-pod rate limiting via EDT + BBR

These capabilities exceed what Wirescale provides standalone. With
Cilium as CNI, policy enforcement MUST use `CiliumNetworkPolicy` and
`CiliumClusterwideNetworkPolicy` CRDs.

**Time-bounded access:** Cilium has no native equivalent to Wirescale's
`WirescaleAccessGrant` CRD. For environments that need time-bounded,
approval-gated access with automatic expiry, wirescale-control MAY
continue managing AccessGrant objects that generate CiliumNetworkPolicy
resources with TTL-based cleanup.

### Observability

Hubble replaces Wirescale's custom audit:

| Capability | Wirescale Audit | Hubble |
|-----------|----------------|--------|
| L3/L4 flow events | Yes | Yes |
| L7 flow events (HTTP, DNS) | No | Yes |
| Multi-node aggregation | External log shipping | hubble-relay (built-in) |
| UI | None | hubble-ui |
| Drop reasons | Policy ID only | 30+ detailed reason codes |
| Prometheus metrics | Custom (wirescale-agent) | Built-in (`hubble_*` metrics) |

Wirescale's deny-only audit logging MAY continue alongside Hubble for
environments where Hubble's always-on tracing overhead is unacceptable.
The two use separate event pipelines and do not conflict.

> **See also:** [EGRESS.md §9.3](EGRESS.md#93-flow-export) describes
> Hubble-compatible egress flow export so that egress events appear in Hubble
> alongside Cilium's intra-cluster flows.

---

## 5. Multi-Cluster: ClusterMesh vs Global Directory

This is the critical architectural divergence. Cilium's ClusterMesh
and Wirescale's global directory represent fundamentally different
approaches to cross-cluster connectivity.

### ClusterMesh: The Push/Sync Model

Cilium ClusterMesh deploys a `clustermesh-apiserver` (backed by etcd)
in each cluster. These apiservers synchronize state between clusters:

```
Cluster A                              Cluster B
+-----------------------+              +-----------------------+
| clustermesh-apiserver |<-- sync -->  | clustermesh-apiserver |
|   etcd: identities   |  all state   |   etcd: identities   |
|   etcd: services      |              |   etcd: services      |
|   etcd: nodes         |              |   etcd: nodes         |
+-----------------------+              +-----------------------+
         |                                      |
    push to all nodes                     push to all nodes
         |                                      |
  Every node gets ALL                    Every node gets ALL
  identities from ALL                    identities from ALL
  clusters                              clusters
```

**ClusterMesh state characteristics:**
- Every `CiliumIdentity` in cluster A is replicated to cluster B, and
  vice versa
- Every node in every cluster holds a complete copy of all identities
  from all connected clusters
- Service entries are synchronized across all clusters
- State grows **O(clusters x pods)**
- Adding a new cluster requires full state synchronization with all
  existing clusters
- Background sync bandwidth grows with identity churn across all
  clusters

**ClusterMesh scaling limits:**
- 10K identities across 5 clusters: 50K identity entries per cluster
- 100K identities across 10 clusters: 1M identity entries per cluster
- 1M identities across 100 clusters: 100M identity entries per cluster
  (untenable)

### Global Directory: The Pull/On-Demand Model

Wirescale's global directory takes the opposite approach. Instead of
replicating all state everywhere, it provides an on-demand resolution
service:

```
                  wirescale-directory
                  (global, O(clusters) state)
                        |
          +-------------+-------------+
          |                           |
     Cluster A                   Cluster B
     wirescale-control           wirescale-control
          |                           |
     Node needs to                (pod identity
     talk to pod                   resolved on
     in Cluster B                  demand)
          |                           |
     1. Query local control           |
     2. Control queries directory     |
        for Cluster B gateway         |
     3. Control queries Cluster B     |
        control for pod identity      |
     4. Cache result with TTL         |
     5. Establish direct WG tunnel    |
```

**Global directory state characteristics:**
- The directory holds O(clusters) state: one entry per cluster with
  gateway endpoints, prefix allocation, and CA certificate
- Cross-cluster identity resolution is on-demand: a node queries only
  when it encounters a flow to/from a remote cluster
- Results are cached locally with TTL
- No background state synchronization between clusters
- Adding a new cluster requires only registering with the directory
- Per-node state is O(active_cross_cluster_flows), not
  O(total_remote_identities)

### State Comparison

| What | Cilium ClusterMesh | Wirescale Global Directory |
|------|-------------------|---------------------------|
| Cross-cluster identity | Full sync via etcd | On-demand pull, cached with TTL |
| Cross-cluster routing | Full sync via etcd | Aggregate routes + on-demand /64s |
| Cross-cluster services | Full sync via etcd | On-demand resolution |
| Directory state | N/A (no directory) | O(clusters) -- tens to hundreds of entries |
| State per node | O(global_pods) | O(active_flows + local_pods + clusters) |
| Adding a cluster | Full sync with all existing clusters | Register in directory |
| Removing a cluster | Drain sync from all clusters | Remove directory entry |
| First cross-cluster flow | 0 ms (identity pre-synced) | ~5-15 ms (directory + control query, cached) |
| Scales to | ~100K pods across ~10 clusters | Millions of pods across thousands of clusters |

### Why This Matters

At small scale (a few clusters, tens of thousands of pods), ClusterMesh
works well. The full-sync model means zero latency for cross-cluster
flows because identities are pre-populated.

At hyperscale, the push model breaks:

- **State explosion:** 1,000 clusters x 10,000 identities each =
  10M identity entries per cluster. Every pod churn event propagates
  to all clusters.
- **Convergence time:** After a cluster is added or experiences a mass
  restart, all identities MUST be re-synced. With millions of
  identities, convergence takes minutes.
- **etcd pressure:** Each clustermesh-apiserver's etcd instance MUST
  handle watches from all local nodes for all remote identities.
- **Blast radius:** An identity storm in one cluster (e.g., mass pod
  rescheduling) propagates to all connected clusters.

Wirescale's pull model avoids all of these issues. The cost is
~5-15ms of first-flow latency to a previously-unseen remote pod. For
most workloads this is negligible compared to connection setup and
application-level latency.

---

## 6. Signaling Gateway Model

### Signaling-Only vs Data-Path Gateways

A critical distinction between Wirescale gateways and ClusterMesh:
Wirescale gateways are **signaling-only** for the control path. After
peer resolution, data flows directly between nodes via WireGuard -- not
through the gateway.

```
Cross-cluster flow setup:

1. Node A in Cluster A wants to reach Pod B in Cluster B
2. wirescale-agent on Node A queries wirescale-control (Cluster A)
3. wirescale-control queries wirescale-directory for Cluster B info
4. wirescale-control queries Cluster B's wirescale-control for Pod B's
   node, public key, and endpoint
5. wirescale-control returns peer information to Node A
6. Node A configures WireGuard peer for Node B (direct tunnel)
7. All subsequent packets flow Node A <-> Node B directly via WireGuard

The gateway participates in step 3-4 (signaling) but NOT in step 7
(data forwarding).
```

### Comparison with ClusterMesh Data Path

ClusterMesh does not have a concept of on-demand peer resolution. Its
model is:

```
ClusterMesh:
1. All identities from all clusters are pre-synced to all nodes
2. Routing between clusters uses pre-configured tunnel or native routing
3. No per-flow setup -- everything is always ready
4. No gateway concept -- state is distributed, not brokered
```

The trade-off is clear:

| Property | Wirescale Signaling Gateway | ClusterMesh |
|----------|---------------------------|-------------|
| Gateway role | Control path only (signaling) | N/A (no gateway) |
| Data path | Direct node-to-node WireGuard | Pre-configured tunnels or native |
| Per-flow setup | ~5-15ms first flow (then cached) | 0ms (pre-synced) |
| State model | O(active_flows) per node | O(all_remote_identities) per node |
| Gateway failure impact | New flows delayed until failover | N/A |
| Steady-state overhead | Minimal (signaling only) | Continuous sync bandwidth |

### Gateway High Availability

Each cluster SHOULD deploy multiple gateway nodes. The global directory
stores multiple gateway endpoints per cluster:

```
wirescale-directory entry for cluster "us-east-prod":
  gateway_endpoints:
    - 203.0.113.1:51820  (gateway-1)
    - 203.0.113.2:51820  (gateway-2)
    - 203.0.113.3:51820  (gateway-3)
```

Gateway selection uses consistent hashing based on the destination
cluster ID, with automatic failover. Because gateways are
signaling-only, their throughput requirements are modest: they handle
control queries, not data-plane traffic.

### When Gateways Forward Data

In the standard model, gateways are signaling-only and data flows
directly between nodes. However, when direct node-to-node connectivity
is not possible (e.g., nodes behind NAT, overlapping IP spaces),
gateways MAY act as relay points:

```
Direct mode (default):
  Node A ----[WireGuard]----> Node B
  (gateway handles signaling only)

Relay mode (when direct path unavailable):
  Node A ----[WireGuard]----> Gateway ----[WireGuard]----> Node B
  (gateway relays encrypted traffic)
```

The wirescale-control peer broker determines whether direct connectivity
is possible during the signaling phase and instructs the agent
accordingly. Relay mode adds one network hop but maintains end-to-end
encryption.

### Multi-Cluster Architecture with Cilium

For multi-cluster deployments with Cilium as intra-cluster CNI:

```
Cluster A (Cilium CNI)              Cluster B (Cilium CNI)

  Cilium: native routing             Cilium: native routing
  Cilium: intra-cluster WG           Cilium: intra-cluster WG
  Cilium: L3-L7 policy               Cilium: L3-L7 policy

  wirescale-control ----[directory query]----> wirescale-directory
  wirescale-control <---[on-demand resolution]---> wirescale-control

  wirescale gateway-a               wirescale gateway-b
    wg0: on-demand cross-cluster      wg0: on-demand cross-cluster
    peers (direct node-to-node)       peers (direct node-to-node)
```

- **Cilium** handles everything within each cluster: CNI, policy,
  WireGuard, observability
- **wirescale-control** handles cross-cluster: on-demand peer
  resolution via directory, federated identity queries
- **wirescale gateways** provide the signaling endpoint for cross-cluster
  peer establishment; data flows directly between nodes after setup
- **wirescale-directory** provides the global cluster registry

This replaces ClusterMesh for cross-cluster connectivity. Cilium's
intra-cluster operation is completely unaffected.

---

## 7. Data Plane Comparison

### WireGuard: Same Kernel Module, Different Management

Both Cilium and Wirescale use the same kernel WireGuard module. The
difference is management, not mechanism:

| Property | Cilium WireGuard | Wirescale WireGuard |
|----------|-----------------|---------------------|
| Interface name | `cilium_wg0` | `wg0` |
| Listen port | 51871 | 51820 |
| Key storage | CiliumNode annotation | Provisioned by wirescale-control |
| Peer management | Watch CiliumNode CRDs (full-mesh) | Pull from wirescale-control (on-demand) |
| AllowedIPs | Pod /64 per peer | Pod /64 per peer |
| GRO/GSO | Kernel-native | Kernel-native (same) |
| Threaded NAPI | Agent enables | Agent enables |
| Conntrack bypass | eBPF-only (no netfilter) | eBPF-only (no netfilter) |
| Scope | Intra-cluster | Cross-cluster (with Cilium deployed) |

Performance is identical for the same traffic path -- same kernel
module, same crypto, same GRO/GSO amortization.

### On-Demand vs Full-Mesh Peering

This is the critical scaling difference.

**Cilium (full-mesh):** Every node peers with every other node. In a
10K-node cluster, every node maintains 9,999 WireGuard peers.

**Wirescale (on-demand):** Peers are established on first encrypted
packet and garbage-collected after idle timeout. In a 10K-node
environment, each node typically maintains ~10-50 active peers.

| Cluster Size | Cilium WG Peers/Node | Wirescale WG Peers/Node | Cilium WG Memory/Node | Wirescale WG Memory/Node |
|-------------|---------------------|------------------------|----------------------|-------------------------|
| 100 nodes | 99 | ~10-30 | ~40 KB | ~4-12 KB |
| 1,000 nodes | 999 | ~10-50 | ~400 KB | ~4-20 KB |
| 10,000 nodes | 9,999 | ~10-50 | ~4 MB | ~4-20 KB |
| 100,000 nodes | 99,999 | ~10-50 | ~40 MB | ~4-20 KB |

**First-packet latency trade-off:** Cilium's full-mesh means zero
setup latency for any intra-cluster peer. Wirescale's on-demand model
incurs ~15-30ms for the first packet to a new peer (control query +
WireGuard handshake). Subsequent packets have zero additional latency.

With Cilium handling intra-cluster WireGuard (full-mesh, acceptable at
per-site sizes) and Wirescale handling cross-cluster WireGuard
(on-demand, essential at fleet scale), each system operates in its
optimal regime.

### Profile-Based Encryption

**Wirescale** uses named deployment profiles to govern encryption scope
(see [ARCHITECTURE.md Section 3](ARCHITECTURE.md#3-deployment-profiles)):
- `encrypted-overlay` (default) -- all inter-node traffic via WireGuard
- `encrypted-routable` -- GUA pods, all inter-node traffic via WireGuard
- `trusted-site` -- intra-site plaintext, cross-site encrypted
- `development` -- no WireGuard (dev/test only)

Per-flow encryption overrides are available via `WirescalePolicy` resources
with `encryption: required` on any profile.

**Cilium** supports only:
- All inter-node traffic encrypted (WireGuard enabled)
- No encryption (WireGuard disabled)

Cilium has no concept of site boundaries or profile-based encryption. In
a multi-site deployment, this forces a choice:
- Enable WireGuard: all traffic encrypted, including same-site
  (unnecessary ~20-40% throughput reduction for intra-site)
- Disable WireGuard: no encryption anywhere, including cross-site
  (unacceptable for untrusted transit)

**Resolution:** Use the `trusted-site` deployment profile. Disable Cilium
WireGuard for intra-site traffic. Wirescale-agent's cross-site WireGuard
via signaling gateways handles inter-site encryption:

```
Intra-site:  Cilium native routing, no encryption (line rate)
Cross-site:  Wirescale on-demand WireGuard (trusted-site profile)
```

### IPv4 Compatibility: CLAT + NAT64 + DNS64

Cilium has no CLAT support. Its NAT46x64 is gateway-centric and
stateful. Wirescale provides the complete IPv4 compatibility stack
for IPv6-only clusters:

| Property | Wirescale NAT64 | Cilium NAT46x64 |
|----------|----------------|-----------------|
| Deployment | Per-node (every node translates) | Gateway (dedicated nodes) |
| Translation | Stateless SIIT (eBPF) | Stateful eBPF NAT (BPF conntrack map) |
| Latency | Local to the node (~50-100 ns) | Extra hop to gateway node |
| Bottleneck | None (distributed) | Gateway node throughput |
| Failure mode | Node-local (isolated) | Gateway failure = no IPv4 egress |

With Cilium as CNI, wirescale-agent MUST continue providing CLAT, NAT64,
and DNS64 on every node.

### eBPF Hook Coexistence

Both Cilium and Wirescale attach TC eBPF programs to the pod's
host-side veth. The `clsact` qdisc supports multiple programs in a
priority chain:

```
Pod veth host-side:
  TC egress chain:
    prio 1: Cilium policy enforcement (lxc program)
    prio 2: Wirescale CLAT IPv4->IPv6 translation

  TC ingress chain:
    prio 1: Wirescale CLAT IPv6->IPv4 translation (return path)
    prio 2: Cilium policy enforcement
```

The CLAT program only acts on IPv4 packets (from `clat0`). Cilium's
programs only act on IPv6 packets (from `eth0`). The two do not
conflict because they operate on different packet types.

**Netkit caveat:** If Cilium uses netkit (Linux 6.8+), Wirescale's CLAT
program MUST attach to the netkit device's TC hook rather than a veth.
Netkit TC hooks function identically from the eBPF program's perspective.

---

## 8. Identity Model: Push vs Pull

### Cilium Identity (Intra-Cluster, Push-Based)

Cilium's identity is a 32-bit numeric ID derived from a pod's label set.
All pods with identical labels share the same identity number. The
identity is distributed cluster-wide via `CiliumIdentity` CRDs.

```
Pod "web-abc" in ns production:
  labels: {app: web, tier: frontend, version: v3}
  -> Cilium identity: 48291 (hash of label set)

Pod "web-def" in ns production (same labels):
  -> Cilium identity: 48291 (same -- shared identity)
```

**Distribution:** The Cilium operator creates `CiliumIdentity` CRDs for
every unique label set. The Cilium agent on every node watches these
CRDs and populates its local ipcache BPF map with ALL identity-to-IP
mappings. Every node holds a complete copy of all identities.

### Wirescale Identity (Cross-Cluster, Pull-Based)

Wirescale's identity is a structured tuple:

```
(namespace, serviceAccount, labels, node, cluster)
```

This is richer than Cilium's label-only identity: two pods with the same
labels but different ServiceAccounts, nodes, or clusters have different
identities.

**Distribution:** Each node queries wirescale-control for identity
information only when it encounters a flow from/to an unknown peer.
Results are cached locally with a TTL. Each node stores only the
identities it has recently resolved.

### Cross-Cluster Identity: The Key Difference

For **intra-cluster** identity, Cilium's push model works well.
Identity counts within a single cluster are bounded, and the ipcache
fits comfortably in memory.

For **cross-cluster** identity, the models diverge dramatically:

**Cilium ClusterMesh identity sync:**
- ALL identities from ALL connected clusters are replicated to every
  node in every cluster
- Identity churn in any cluster propagates to all other clusters
- State grows O(clusters x identities)

**Wirescale cross-cluster identity resolution:**
- A node queries wirescale-control only when it encounters a flow
  to/from a remote cluster
- wirescale-control resolves the identity by querying the remote
  cluster's control plane (via the directory)
- The result is cached with a TTL
- State per node grows O(active_cross_cluster_flows)

#### Identity Scaling Comparison

| Metric | Cilium (ClusterMesh) | Wirescale (Global Directory) |
|--------|---------------------|------------------------------|
| Intra-cluster distribution | Push (CiliumIdentity CRDs) | Push (same, when Cilium is CNI) |
| Cross-cluster distribution | Push (ClusterMesh etcd sync) | Pull (on-demand via control) |
| Cross-cluster state per node | ALL remote identities | Active remote identities only |
| 5 clusters, 10K identities each | 50K entries/node | ~500-2K entries/node |
| 100 clusters, 100K identities each | 10M entries/node (untenable) | ~1-5K entries/node |
| Cross-cluster first-flow latency | 0 ms (pre-synced) | ~5-15 ms (cached thereafter) |
| Identity churn propagation | All clusters, all nodes | Only querying nodes |

### Complementary Use

With Cilium as CNI:
- **Intra-cluster:** Use Cilium's identity model. It is well-integrated
  with Cilium's policy engine and ipcache.
- **Cross-cluster:** Use Wirescale's pull-based identity resolution via
  the three-tier hierarchy. This replaces ClusterMesh's identity sync.

The two identity systems coexist without conflict. Cilium's ipcache
handles local and intra-cluster identities. Wirescale's control client
handles cross-cluster identities and populates a separate BPF map for
cross-cluster policy decisions.

---

## 9. Ingress Security for Internet-Routable Pods

### The Problem

With GUA pods (ROUTABLE-PREFIX.md), every pod is reachable from the
internet unless firewalled. Both architectures MUST solve this.

### Wirescale: XDP on eth0

Wirescale installs an XDP program on the physical NIC that drops
external-to-pod traffic at the driver level before it enters the kernel
network stack:

```
Physical NIC -> XDP program (14-26 Mpps/core)
  External src + local pod dst + no allow rule -> XDP_DROP
  (packet never reaches kernel stack)
```

### Cilium: TC-based Host Firewall

Cilium's host firewall operates at the TC hook level (after XDP, after
the kernel processes the packet):

```
Physical NIC -> kernel stack -> TC hook -> Cilium host firewall
  (packet has already been processed by NIC driver and allocated sk_buff)
```

Cilium uses XDP for Service load-balancing (DSR), not for ingress
firewalling. The host firewall is policy-driven via
`CiliumClusterwideNetworkPolicy`:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: deny-external-to-pods
spec:
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/worker: ""
  ingress:
    - fromEntities:
        - cluster
        - health
```

### Comparison

| Property | Wirescale XDP Firewall | Cilium Host Firewall |
|----------|----------------------|---------------------|
| Hook point | XDP (driver level) | TC (after kernel stack entry) |
| Packet rate | 14-26 Mpps/core | 2-5 Mpps/core |
| DDoS protection | Yes (drops before sk_buff alloc) | Limited (packet already in kernel) |
| Per-pod granularity | Yes (checks dst against pod prefix) | Yes (via endpoint identity) |
| Configuration | BPF map (policy-driven) | CiliumClusterwideNetworkPolicy |

### Recommendation

For internet-routable pods, wirescale-agent SHOULD continue to install
its XDP program on `eth0` for external-to-pod ingress filtering,
complementing Cilium's per-pod policy enforcement on veths. The two do
not conflict: XDP runs before TC. Packets dropped by XDP never reach
Cilium's hooks.

---

## 10. Performance and Scaling Analysis

### Same-Site Pod-to-Pod (Native IPv6, No Encryption)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| Interface type | veth | veth or netkit |
| eBPF programs in path | 1 (policy on veth) | 1 (policy on lxc/netkit) |
| Throughput (10G) | ~9.4 Gbps | ~9.4 Gbps (veth) / ~9.6 Gbps (netkit) |
| Latency | ~5 us | ~5 us (veth) / ~3 us (netkit) |

### Same-Site Pod-to-Pod (WireGuard Encrypted)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| WireGuard interface | wg0 | cilium_wg0 |
| Kernel module | Same | Same |
| GRO/GSO | Same | Same |
| Throughput (10G) | ~9.0 Gbps | ~9.0 Gbps |

### IPv4 via CLAT (Pod-to-Pod)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| CLAT eBPF programs | 2 (TC on each veth) | 2 (TC on each lxc/netkit) |
| Overhead vs pure IPv6 | ~5% | ~5% |
| Throughput (10G) | ~8.5 Gbps | ~8.5 Gbps |

### IPv4 via NAT64 (Pod-to-External)

| Metric | Wirescale NAT64 | Cilium NAT46x64 |
|--------|----------------|-----------------|
| Translation location | Local node | Gateway node |
| Extra network hops | 0 | 1+ (to gateway) |
| Translation type | Stateless SIIT | Stateful eBPF NAT |
| Per-packet cost | ~50-100 ns | ~100-200 ns + hop latency |
| Throughput (10G) | ~8.0 Gbps | Bottlenecked by gateway |
| Failure impact | Node-local | Cluster-wide IPv4 outage |

### Scaling Analysis: Control Plane State

The fundamental scaling difference is state distribution. This table
compares per-node resource consumption as the deployment grows:

| Metric | Cilium Only | Wirescale Only | Cilium + Wirescale |
|--------|-------------|----------------|-------------------|
| **Single cluster, 100 nodes** | | | |
| WG peers/node | 99 | ~10-30 | Cilium: 99 / WS: 0 |
| Identity entries/node | ~1K | ~100-500 | Cilium: ~1K / WS: 0 |
| Control plane overhead | Low | Low | Low |
| **Single cluster, 10K nodes** | | | |
| WG peers/node | 9,999 | ~10-50 | Cilium: 9,999 / WS: 0 |
| Identity entries/node | ~100K | ~100-1K | Cilium: ~100K / WS: 0 |
| WG memory/node | ~4 MB | ~4-20 KB | ~4 MB |
| Identity memory/node | ~10 MB | ~10-100 KB | ~10 MB |
| CRD watch bandwidth | High | None | High |
| **5 clusters, 10K nodes each** | | | |
| Cross-cluster identity/node | 50K (ClusterMesh) | ~500-2K | WS: ~500-2K |
| Cross-cluster WG peers/node | N/A (no cross-cluster WG) | ~10-50 | WS: ~10-50 |
| Background sync bandwidth | Continuous | None | None |
| **100 clusters, 100K nodes total** | | | |
| Cross-cluster identity/node | 10M+ (untenable) | ~1-5K | WS: ~1-5K |
| Directory state (global) | N/A | O(100) entries | O(100) entries |
| Adding a cluster | Full sync with 99 others | Register in directory | Register in directory |

**Key observations:**

- **Intra-cluster at moderate scale (< 1K nodes):** Cilium's push model
  works well. The overhead is acceptable and zero first-flow latency is
  a genuine advantage.
- **Intra-cluster at hyperscale (10K+ nodes):** Cilium's CRD watch
  bandwidth and per-node state become expensive. The ipcache grows to
  tens of MB per node. This is Cilium's known scaling limitation.
- **Cross-cluster at any scale:** Wirescale's pull-based model via the
  global directory is strictly more scalable than ClusterMesh's push
  model. The ~5-15ms first-flow latency is negligible for cross-cluster
  traffic (which already has higher RTT).
- **Recommended hybrid:** Cilium for intra-cluster (where full-mesh is
  acceptable at per-site sizes), Wirescale for cross-cluster (where
  on-demand resolution is essential at fleet scale).

---

## 11. Component-by-Component Diff

### Full Comparison Table

| Component | Without Cilium | With Cilium | Delta |
|-----------|---------------|-------------|-------|
| **CNI binary** | wirescale-cni | Cilium CNI | Replaced |
| **Pod interface** | veth pair | veth or netkit | Upgraded (netkit on 6.8+) |
| **IPv6 IPAM** | wirescale-control | Cilium operator (kubernetes mode) | Replaced |
| **Per-pod /128 routes** | wirescale-cni | Cilium CNI | Replaced |
| **WireGuard (intra-cluster)** | wirescale-agent `wg0` (on-demand) | Cilium agent `cilium_wg0` (full-mesh) | Replaced |
| **WireGuard (cross-cluster)** | wirescale-agent `wg0` (on-demand via control) | wirescale-agent `wg0` (on-demand via directory) | Updated (three-tier resolution) |
| **Profile-based encryption** | wirescale-agent eBPF | Not available in Cilium | Wirescale still needed |
| **L3/L4 policy** | wirescale-agent TC eBPF | Cilium TC eBPF | Replaced |
| **L7 policy** | Not available | Cilium + Envoy | Added |
| **FQDN egress** | Not available | Cilium DNS proxy | Added |
| **CLAT (per-pod IPv4)** | wirescale-agent | wirescale-agent | Unchanged |
| **NAT64** | wirescale-agent (per-node) | wirescale-agent (per-node) | Unchanged |
| **DNS64** | CoreDNS dns64 plugin | CoreDNS dns64 plugin | Unchanged |
| **XDP ingress firewall** | wirescale-agent on eth0 | wirescale-agent on eth0 | Unchanged |
| **Conntrack bypass** | eBPF-only (no netfilter) | eBPF-only (no netfilter) | eBPF-only |
| **Intra-cluster identity** | Pull-based via wirescale-control | Push-based CiliumIdentity CRDs | Replaced |
| **Cross-cluster identity** | Pull-based via wirescale-control | Pull-based via global directory | Updated (three-tier) |
| **Policy CRD** | WirescalePolicy | CiliumNetworkPolicy | Replaced |
| **Time-bounded access** | WirescaleAccessGrant | Not available | Wirescale still needed |
| **Observability** | Custom BPF ringbuf | Hubble | Replaced (richer) |
| **Bandwidth management** | Not available | Cilium EDT + BBR | Added |
| **External peers** | WirescaleExternalPeer | WirescaleExternalPeer (via control) | Unchanged |
| **Multi-cluster identity** | Federated wirescale-control | Via global directory + control | Updated (three-tier) |
| **Global cluster registry** | Not available | wirescale-directory | Added |
| **Kernel sysctl tuning** | wirescale-agent | Cilium agent + wirescale-agent | Shared |

### Summary Scorecard

```
Functions moved to Cilium:          8  (CNI, IPAM, intra-cluster WG, intra-cluster
                                        policy, intra-cluster identity, routes,
                                        observability, bandwidth)
Functions retained by Wirescale:    8  (CLAT, NAT64, DNS64, XDP firewall,
                                        cross-cluster WG, external peers,
                                        time-bounded access, profile-based encryption)
Functions added by Cilium:          3  (L7 policy, FQDN egress, bandwidth mgmt)
Functions updated for three-tier:   3  (cross-cluster identity, multi-cluster,
                                        global directory)
Functions lost:                     0  (time-bounded access adapted via controller)
```

---

## 12. Deployment Decision Matrix

### When to Use Cilium + Wirescale (Recommended for Most Deployments)

- You need **L7 policy** (HTTP path filtering, gRPC method control)
- You need **FQDN-based egress control** (allow only specific domains)
- You need **Hubble** for deep network observability
- You need **bandwidth management** (per-pod rate limiting)
- You need **IPv4 compatibility** in IPv6-only clusters (CLAT/NAT64)
- You want **netkit** performance improvements (Linux 6.8+)
- You need **cross-cluster connectivity** without ClusterMesh's state
  explosion

### When to Use Wirescale Standalone

- You need **profile-based encryption** (`trusted-site` for line rate intra-site)
- You want **simpler operations** (one agent, one CNI, one policy CRD)
- You don't need L7 policy
- You want the **lowest possible overhead** (no Envoy, no Hubble)
- You need **time-bounded access grants** natively
- Your threat model requires **XDP-level ingress filtering** as the
  primary defense for internet-routable pods

### When to Use Cilium + Wirescale at Hyperscale

- **Multi-cluster with cross-cluster traffic** where ClusterMesh's
  O(clusters x identities) sync is prohibitive
- **Thousands of clusters** where the global directory's O(clusters)
  state is essential
- Need **on-demand cross-cluster WireGuard** (signaling gateways
  instead of full state sync)
- Need **federated identity** via pull-based resolution, not global
  replication
- Want Cilium's **L7 + Hubble + bandwidth** within each cluster
- Want Wirescale's **three-tier hierarchy** for cross-cluster

### When Cilium Alone Breaks Down

- **Cross-cluster at scale:** ClusterMesh syncs all identities between
  clusters, producing O(clusters x identities) state. At 100 clusters
  with 100K identities each, this is 10M entries per node -- untenable.
- **WireGuard at scale:** 10K+ WireGuard peers per node consumes ~4+ MB
  of memory and significant CPU for keepalive processing.
- **No profile-based encryption:** Cilium cannot encrypt cross-site traffic
  while leaving intra-site traffic at line rate (requires Wirescale's
  `trusted-site` deployment profile).
- **No IPv4 compatibility:** No CLAT, no per-node NAT64, no DNS64.
- **No external peers:** ClusterMesh is k8s-to-k8s only.

### When to Use Cilium Alone (No Wirescale)

- Your cluster is **dual-stack** (IPv4 + IPv6) -- no need for CLAT/NAT64
- All applications are IPv6-native -- no IPv4 compatibility needed
- Single-site, single-cluster deployment -- no cross-site encryption needed
- No external non-k8s peers
- Cilium's all-or-nothing WireGuard encryption is acceptable (no need for
  Wirescale deployment profiles)
- Cluster size is below ~1K nodes
- Cross-cluster needs are met by ClusterMesh at your scale

### Feature Matrix

| Requirement | Wirescale Only | Cilium Only | Cilium + Wirescale |
|-------------|:-:|:-:|:-:|
| IPv6 native routing | Yes | Yes | Yes |
| /64-per-host IPAM | Yes | Yes | Yes |
| Fabric-managed BGP | Yes | Yes | Yes |
| WireGuard encryption | Yes | Yes | Yes |
| On-demand WireGuard peering | Yes | No (full-mesh) | Yes (cross-cluster) |
| Profile-based encryption (e.g., `trusted-site`) | Yes | No | Yes |
| CLAT (per-pod IPv4) | Yes | No | Yes |
| Per-node NAT64 | Yes | Gateway only | Yes |
| DNS64 | Yes | External only | Yes |
| L3/L4 policy | Yes | Yes | Yes (Cilium) |
| L7 policy | No | Yes | Yes (Cilium) |
| FQDN egress | No | Yes | Yes (Cilium) |
| Time-bounded access | Yes | No | Yes (Wirescale) |
| XDP ingress firewall | Yes | No (TC-based) | Yes (Wirescale) |
| Hubble observability | No | Yes | Yes (Cilium) |
| Bandwidth management | No | Yes | Yes (Cilium) |
| External non-k8s peers | Yes | No | Yes (Wirescale) |
| Cross-cluster identity (on-demand) | Yes | No (full sync) | Yes (Wirescale) |
| Global cluster directory | Yes | No | Yes (Wirescale) |
| Signaling gateways | Yes | No | Yes (Wirescale) |
| O(active_flows) per-node scaling | Yes | No (O(N) per node) | Yes (cross-cluster) |
| netkit (Linux 6.8+) | No | Yes | Yes (Cilium) |
| Scales to 1000s of clusters | Yes | No | Yes |
