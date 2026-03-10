# Wirescale: Kubernetes Network Operator Architecture

> A WireGuard-based network operator for Kubernetes that provides seamless
> IPv4 and IPv6 connectivity in IPv6-only clusters, with a hyperscale-ready
> three-tier control plane supporting central authentication, decentralized
> forwarding, on-demand peering, and federated cross-cluster connectivity.
>
> Status: design document. Unless explicitly linked to implementation artifacts,
> behavior described here should be treated as target architecture.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

**See also:**
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
  (GRO/GSO, eBPF fast paths, kernel tuning, hardware acceleration)
- [SECURITY.md](SECURITY.md) -- Network security and dynamic access control
  (identity model, policy enforcement, BPF maps, audit)
- [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) -- Globally routable /64-per-host
  design (BGP routing, selective encryption, native IPv6 performance)
- [CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md) -- Architecture comparison
  with Cilium as CNI (what changes, what Wirescale still provides)

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Design Principles](#2-design-principles)
3. [Three-Tier Control Hierarchy](#3-three-tier-control-hierarchy)
4. [Component Deep Dives](#4-component-deep-dives)
5. [Address Architecture and Hierarchical Prefix Aggregation](#5-address-architecture-and-hierarchical-prefix-aggregation)
6. [Data Plane: On-Demand WireGuard Peering](#6-data-plane-on-demand-wireguard-peering)
7. [Cross-Cluster Connectivity](#7-cross-cluster-connectivity)
8. [IPv4 in an IPv6-Only World](#8-ipv4-in-an-ipv6-only-world)
9. [DNS Architecture](#9-dns-architecture)
10. [Cross-Cluster Service Discovery and Load Balancing](#10-cross-cluster-service-discovery-and-load-balancing)
11. [Host-Network Pods](#11-host-network-pods)
12. [Security Model](#12-security-model)
13. [Custom Resource Definitions](#13-custom-resource-definitions)
14. [Packet Flow Walkthrough](#14-packet-flow-walkthrough)
15. [Comparison with Existing Solutions](#15-comparison-with-existing-solutions)
16. [Implementation Phases](#16-implementation-phases)

---

## 1. Problem Statement

### The IPv4 Sunset Reality

Public IPv4 addresses are exhausted and increasingly expensive. Cloud providers
charge per-address (AWS: ~$43/year per public IPv4). The path forward is
IPv6-only infrastructure. However:

- Many external services remain IPv4-only
- Legacy applications hardcode IPv4 addresses or use IPv4-only socket APIs
- Kubernetes networking assumes dual-stack or IPv4-primary in most tooling
- Pod-to-pod communication across nodes needs encryption (zero-trust)

### The Full-Mesh Scaling Wall

Traditional WireGuard mesh architectures require every node to know about
every other node in the fleet:

- Every agent watches ALL peer CRDs -- O(N) watches per node
- Identity propagation pushes ALL pod identities to ALL nodes -- O(N^2) state
- Policy compilation generates per-node rules for ALL nodes -- O(N^2) work
- WireGuard mesh: every node peers with every other node -- N-1 peers per node

This model works for a single cluster under ~10K nodes but **completely breaks
cross-cluster** where you would have hundreds of thousands of hosts. At that
scale, O(total_hosts) routing state and O(total_pods) identity state on every
node becomes unmanageable.

### The Cross-Cluster Gap

Existing approaches to cross-cluster connectivity fall into two traps:

1. **Full state sync** -- replicate all pod/node/identity state across clusters.
   This creates O(total_pods_all_clusters) state on every node and does not
   scale past a handful of small clusters.
2. **Gateway bottleneck** -- funnel all cross-cluster traffic through a small
   number of gateway nodes. This creates throughput bottlenecks, single points
   of failure, and adds latency to every cross-cluster packet.

### What We Want

A conformant Wirescale deployment SHOULD satisfy the following goals for pods
in an IPv6-only Kubernetes cluster:

1. **Native IPv6 connectivity** -- the data plane MUST support first-class IPv6
   pod connectivity without translation in native paths.
2. **Transparent IPv4 connectivity** -- the platform MUST provide an IPv4
   compatibility path so pods can use IPv4 socket semantics over an IPv6
   underlay.
3. **Encrypted pod-to-pod mesh** -- inter-node traffic MUST be encrypted with
   WireGuard via on-demand peering; peers MUST be established only when
   traffic demands it and garbage-collected when idle.
4. **Central authentication, decentralized forwarding** -- a central control
   plane MUST handle authentication, authorization, and peer brokering. The
   data plane MUST remain fully decentralized. Nodes MUST make forwarding
   decisions locally with cached state.
5. **Minimal state distribution** -- nodes MUST only learn about hosts and
   identities they actively communicate with. Per-node state MUST be
   O(active_peers), not O(total_nodes). Pod-level state MUST NOT be
   distributed globally.
6. **Hyperscale readiness** -- the system MUST scale to 10K+ nodes per cluster
   and support federations of hundreds of clusters (hundreds of thousands of
   total hosts) without requiring any node to hold global state.
7. **Cross-cluster without full sync** -- cross-cluster connectivity MUST use
   on-demand resolution and hierarchical prefix aggregation. Remote clusters
   MUST be representable as a single aggregate route, not per-host entries.
8. **External mesh capability** -- deployments MAY extend the mesh to external
   services (other clusters, bare-metal, cloud VMs) via federated control
   planes.

---

## 2. Design Principles

| Principle | Rationale |
|-----------|-----------|
| **IPv6-native, IPv4-compatible** | The underlay is IPv6-only. IPv4 is provided as a service via translation, not as infrastructure. |
| **Three-tier control hierarchy** | A global directory tracks clusters (O(clusters) state). Per-cluster controllers track nodes and pods within their cluster. Per-node agents hold only active flow state. No component holds global state for the entire federation. |
| **Central authentication, decentralized forwarding** | The control plane (wirescale-control and wirescale-directory) handles authentication, authorization, peer brokering, and identity resolution. The data plane (WireGuard on each node) handles encryption and forwarding with no central mediation. Control plane failure does not break existing connections. |
| **On-demand peering, not full mesh** | Nodes establish WireGuard peers only when traffic requires it. Idle peers are garbage-collected. A node with 50 active communication partners holds 50 peers, not 10,000. |
| **Hierarchical prefix aggregation** | Each cluster is allocated a contiguous prefix. Intra-cluster routing uses per-host /64 routes. Cross-cluster routing uses one aggregate route per remote cluster. Total per-node route state: O(local_hosts + clusters). |
| **Signaling gateways, not data-path gateways** | Cross-cluster gateways handle signaling (initial peer resolution) only. Data flows directly between source and destination nodes. Gateways are never in the data path for established flows. |
| **Pull-based identity and policy** | Nodes request identity and policy information on demand, cache it with TTLs, and expire it. No push-based global state distribution. |
| **O(active_peers) per node, not O(total_nodes)** | Every per-node resource -- WireGuard peers, identity cache entries, policy rules, route table entries -- scales with the number of active communication partners, not with the total size of the fleet. |
| **Key-per-node, not key-per-pod** | Matches the WireGuard model and avoids quadratic key distribution. Pods on the same node share a tunnel. Same-node traffic is unencrypted (already isolated by kernel namespaces). |
| **CNI-complementary, not CNI-replacing** | Wirescale can operate as a standalone CNI or as an overlay on top of an existing CNI (like Flannel or kubenet) for the intra-node path. |
| **Cluster autonomy** | Each cluster operates independently. The global directory is a thin registry. A cluster MUST continue operating normally if the global directory is temporarily unavailable -- only new cross-cluster peer establishment is affected. |
| **Graceful degradation** | If wirescale-control is unavailable, existing WireGuard peers and cached identities MUST persist. New peer establishment MAY wait until control recovers. The data plane never depends on real-time control plane availability. |

---

## 3. Three-Tier Control Hierarchy

The control plane is organized into three tiers, each holding only the state
appropriate to its scope. This is the fundamental architectural change from
flat mesh designs.

```
+=========================================================================+
|                     TIER 1: GLOBAL DIRECTORY                            |
|                     (wirescale-directory)                                |
|                                                                         |
|  Globally replicated service (Raft consensus or similar)                |
|  State: O(clusters) -- tens to hundreds of entries                      |
|                                                                         |
|  Maps: cluster_id -> {                                                  |
|    gateway_endpoints,                                                   |
|    prefix_allocation,   (e.g., 3fff:1234:0001::/48)                     |
|    cluster_CA_cert,                                                     |
|    controller_endpoint,                                                 |
|    metadata                                                             |
|  }                                                                      |
|                                                                         |
|  Root of trust for cross-cluster authentication.                        |
|  Does NOT know about individual pods or nodes.                          |
+=========================================================================+
          |                    |                    |
     cluster registration     |              cluster lookup
          |                    |                    |
+=========================+  +=========================+  +=================+
| TIER 2: CLUSTER         |  | TIER 2: CLUSTER         |  | TIER 2: ...     |
| CONTROLLER              |  | CONTROLLER              |  |                 |
| (wirescale-control)     |  | (wirescale-control)     |  |                 |
| Cluster 1               |  | Cluster 2               |  |                 |
|                         |  |                         |  |                 |
| State: O(nodes * pods)  |  | State: O(nodes * pods)  |  |                 |
| - within this cluster   |  | - within this cluster   |  |                 |
|                         |  |                         |  |                 |
| - AuthN/AuthZ           |  | - AuthN/AuthZ           |  |                 |
| - Peer Broker           |  | - Peer Broker           |  |                 |
| - Identity Service      |  | - Identity Service      |  |                 |
| - Policy Service        |  | - Policy Service        |  |                 |
| - IPAM                  |  | - IPAM                  |  |                 |
| - Cross-cluster proxy   |  | - Cross-cluster proxy   |  |                 |
+=========================+  +=========================+  +=================+
     |          |                 |          |
  gRPC(mTLS)  CRD watch       gRPC(mTLS)  CRD watch
  (per-node)  (own node)      (per-node)  (own node)
     |          |                 |          |
+=========================+  +=========================+
| TIER 3: NODE AGENT      |  | TIER 3: NODE AGENT      |
| (wirescale-agent)       |  | (wirescale-agent)       |
| Per node                |  | Per node                |
|                         |  |                         |
| State: O(active_peers)  |  | State: O(active_peers)  |
| - WireGuard peers       |  | - WireGuard peers       |
| - Identity cache        |  | - Identity cache        |
| - Route table           |  | - Route table           |
| - Policy for local pods |  | - Policy for local pods |
+=========================+  +=========================+
     |                            |
     |    On-demand WireGuard     |
     |    tunnels (direct,        |
     |    including cross-cluster)|
     +----------------------------+
```

### Tier 1: Global Directory (`wirescale-directory`)

A lightweight, globally replicated service that serves as the root of trust
for cross-cluster operations.

**Responsibilities:**
- Cluster registry: maps cluster IDs to gateway endpoints, prefix allocations,
  cluster CA certificates, and controller endpoints
- Root of trust: issues or validates cross-cluster authentication credentials
- Prefix allocation: assigns contiguous prefixes to clusters from the
  federation's address space

**What it does NOT do:**
- It does NOT know about individual pods or nodes
- It does NOT participate in data-plane forwarding
- It does NOT store identity or policy state
- It does NOT need to be in the hot path for any per-packet operation

**State size:** O(clusters) -- typically tens to hundreds of entries. A
federation of 500 clusters requires ~500 registry entries. This state is small
enough to be fully replicated across all directory replicas with negligible
overhead.

**Availability:** The directory MUST be replicated (3+ nodes, Raft or similar)
for HA. However, the directory is only needed for:
- New cluster registration
- Cross-cluster peer establishment (cache miss on the cluster controller)
- Certificate renewal

Existing cross-cluster peers, cached cluster info on controllers, and all
intra-cluster operations continue without the directory.

### Tier 2: Cluster Controller (`wirescale-control`)

A per-cluster service that knows all nodes and pods within its cluster. This
is the primary control plane component that agents interact with.

**Responsibilities:**
- Authentication and authorization for agents within its cluster
- Peer brokering: on-demand peer discovery for intra-cluster peers
- Identity service: pod-to-identity resolution for pods in this cluster
- Policy service: per-node policy compilation and push
- IPAM: node /64 and /24 allocation within the cluster's prefix
- Cross-cluster proxy: for cross-cluster peer requests, queries the global
  directory for remote cluster info, then queries the remote cluster's
  controller directly
- Cluster registration: registers with the global directory at startup

**State size:** O(nodes_in_cluster x pods_per_node). For a 10K-node cluster
with 100 pods per node, this is ~1M entries -- manageable for an in-memory
service with persistent backing.

**Horizontal scaling:** The controller is stateless for read operations (reads
from Kubernetes API / in-memory cache) and SHOULD be deployed as 3+ replicas
behind a Service for HA. Write operations (IPAM, CRD updates) use leader
election.

### Tier 3: Node Agent (`wirescale-agent`)

A per-node daemon with minimal state, responsible for data-plane operations.

**Responsibilities:**
- WireGuard interface management (key generation, peer setup, peer GC)
- On-demand peering via cluster controller
- Identity caching (pull-based, TTL-expiring)
- Policy enforcement (eBPF/nftables for local pods only)
- NAT64/CLAT translation
- Route programming

**State size:** O(active_peers) for WireGuard peers and identity cache. The
agent MUST NOT watch all pods or nodes across the cluster -- only its own
node's CRDs.

**Routing table:** O(hosts_in_local_cluster) + O(remote_clusters) aggregate
routes. Intra-cluster: one /64 route per local peer (programmed on demand).
Cross-cluster: one aggregate route per remote cluster, pointing to the local
signaling gateway.

### State Distribution Summary

| What | Flat Mesh (Broken at Scale) | Three-Tier (Hyperscale) |
|------|---------------------------|------------------------|
| Routes per node | O(all_hosts_in_fleet) | O(local_hosts + clusters) |
| Identity state per node | O(all_pods_in_fleet) | O(active_flows) -- pull-based cache |
| Policy per node | Grows with fleet | Local pods only |
| CRD watches per node | O(N) events/sec | O(1) -- own node only |
| Cross-cluster state | Full sync | On-demand resolution, cached |
| Route updates on pod churn | O(pod_churn) globally | O(0) -- pods do not affect routes |
| Route updates on host churn | O(host_churn) globally | O(host_churn) within cluster only |
| Global directory state | N/A | O(clusters) -- tiny |

---

## 4. Component Deep Dives

### 4.1 wirescale-directory (Tier 1)

The global directory runs as a replicated service (3+ nodes) outside any
single Kubernetes cluster. It MAY run on dedicated infrastructure, as a
multi-cluster service, or within a designated management cluster.

**Cluster Registry:**
- Each cluster controller registers at startup:
  `{cluster_id, gateway_endpoints, prefix_allocation, controller_endpoint, cluster_CA_cert}`
- Registration MUST be authenticated (the directory issues bootstrap tokens
  or uses a shared root CA)
- The directory MUST validate that prefix allocations do not overlap
- Registry entries include a heartbeat TTL; controllers MUST refresh
  periodically (default 60s)
- The directory MUST expose a gRPC API for cluster lookup by prefix or ID

**Cross-Cluster Trust Root:**
- The directory maintains the root CA (or a set of cross-signed CAs) for
  federation-wide mTLS
- Cluster controllers present their cluster CA certificate during registration
- The directory validates and stores the CA certificate, making it available
  to other cluster controllers that need to establish cross-cluster mTLS

**Prefix Allocation:**
- The directory allocates contiguous prefixes from the federation address
  space (see [Section 5](#5-address-architecture-and-hierarchical-prefix-aggregation))
- Allocation is idempotent: re-registering with the same cluster ID returns
  the existing allocation
- Deallocated prefixes are quarantined (default 7 days) before reuse

### 4.2 wirescale-control (Tier 2)

The per-cluster control plane service runs as a Kubernetes Deployment with 3+
replicas behind a Service for high availability. It is the single component
within a cluster that maintains cluster-wide state. Agents connect to it via
gRPC over mTLS.

**Authentication & Authorization:**
- Nodes MUST authenticate to control via mTLS using kubelet client
  certificates or projected ServiceAccount tokens.
- Control MUST validate node identity against the Kubernetes API before
  responding to any request.
- Control MUST issue short-lived WireGuard peer authorization tokens that
  bind a specific node pair for a bounded TTL.
- Unauthorized or revoked nodes MUST be rejected immediately.

**Peer Broker** -- on-demand peer discovery:
- When node-A needs encrypted traffic to node-B, it queries control:
  "I need the peer info for the node owning prefix `3fff:1234:0001:002a::/64`"
- Control authenticates the request, checks authorization, and returns:
  `{publicKey, endpoint, allowedIPs, token, TTL}`
- Node-A configures a WireGuard peer with the returned parameters.
- Control does NOT mediate data-plane traffic -- only peer discovery.
- Peer info responses SHOULD include a TTL (default 300s). The agent
  MUST re-validate before TTL expiry or on next cache miss.

**Identity Service** -- pod identity resolution:
- Agents query control to resolve: "Who owns IP `3fff:1234:0001:0003::7`?"
- Control returns: `{namespace, serviceAccount, labels, nodeName}`
- Agents cache identity responses locally (default TTL 60s).
- Control is the only component that subscribes to global Pod events
  within its cluster. It maintains a complete pod-to-identity index internally.
- On identity cache miss, the agent queries control synchronously.
  The expected latency budget for this path is ~5-10ms.

**Policy Service** -- per-node policy push:
- Each agent subscribes to control via a gRPC stream for policy updates
  relevant to its own local pods only.
- Control compiles policy rules on demand (or caches compiled results)
  by intersecting WirescalePolicy/NetworkPolicy objects with the set of
  pods running on each node.
- Policy updates MUST be pushed to subscribed agents within 1s of a
  policy or pod change that affects them.
- Each node receives only the policy rules for its own pods -- not the
  global policy set.

**Node IPAM Reconciler** -- watches `Node` objects:
- When a node joins, allocates a `/64` IPv6 pod CIDR from the cluster's
  IPv6 pod range and a `/24` IPv4 pod CIDR from an internal CGNAT-like range.
- Writes allocations to the corresponding `WirescaleNode` CRD.
- Handles node removal and CIDR reclamation.

**Cross-Cluster Proxy:**
- When an agent requests a peer in a prefix not belonging to this cluster,
  control resolves the target cluster via the global directory (or its local
  cache of directory state).
- Control then contacts the remote cluster's controller directly via mTLS
  (using the CA certificate from the directory) to resolve the specific node.
- The response is relayed back to the requesting agent.
- Cluster controller MUST cache directory responses (cluster -> controller
  mapping) with a TTL (default 300s) to avoid hot-path queries to the
  directory.

**External Peer Reconciler** -- watches `WirescaleExternalPeer` CRDs:
- Manages peers outside the cluster (bare metal, other clusters, VMs).
- Issues peer authorization for external nodes through the same broker
  interface used by in-cluster agents.

### 4.3 wirescale-agent (Tier 3)

The agent is the workhorse. It runs as a privileged DaemonSet with
`hostNetwork: true` and capabilities `NET_ADMIN`, `NET_RAW`, `SYS_MODULE`.

On startup:
1. Generate WireGuard keypair (private key stored in-memory only, never
   persisted to disk or CRD)
2. Create `WirescaleNode` CRD for this node (or update existing) with:
   - WireGuard public key
   - Node endpoint (IPv6 address + UDP port)
   - Allocated pod CIDRs (from IPAM)
3. Create the `wg0` WireGuard interface bound to the node's IPv6 address
4. Establish gRPC connection to wirescale-control (mTLS)
5. Subscribe to policy stream for local pods from control
6. Program kernel routes:
   - Intra-cluster: /64 routes for active local peers (on demand)
   - Cross-cluster: aggregate routes for each known remote cluster,
     pointing to local signaling gateway
7. Create `nat64` interface for NAT64 translation
8. Start CLAT engine for per-pod IPv4 address provision

The agent MUST NOT watch all `WirescaleNode` CRDs. It watches only its own
`WirescaleNode` CRD for IPAM updates and configuration changes.

**On-demand peer establishment:**
```
Packet destined for remote pod arrives at egress path:
  1. eBPF checks encrypt_map -> encryption required for destination /64
  2. If WireGuard peer exists for destination /64:
       forward through wg0 (warm path, zero additional latency)
  3. If no WireGuard peer for destination /64:
       a. Queue packet in userspace buffer (bounded, default 64 packets)
       b. Request peer info from wirescale-control via gRPC
       c. Control authenticates, authorizes, returns peer parameters
          (for cross-cluster: control proxies through directory + remote control)
       d. Agent configures WireGuard peer:
            wg set wg0 peer <pubkey> allowed-ips <cidrs> endpoint <ipv6:port>
       e. Program kernel routes for remote pod CIDRs -> wg0
       f. Drain queued packets through the new peer
  4. Peer idle GC (continuous):
       - Track last handshake time per peer
       - If no traffic for peer_idle_timeout (default 300s): remove peer
       - Next packet to that destination re-triggers step 3 (cache-miss path)
```

**Cross-cluster aggregate route handling:**
When a packet matches an aggregate route for a remote cluster (no specific
/64 peer route exists yet):
1. The packet is intercepted by the agent (or forwarded to the signaling
   gateway first, which hands it to the agent)
2. The agent queries wirescale-control for the specific remote node
3. A direct WireGuard tunnel is established to the remote node
4. A specific /64 route is installed, overriding the aggregate route
5. All subsequent traffic flows directly -- the gateway is bypassed

**Identity cache:**
The agent maintains a local TTL-based cache of pod identities. On cache miss,
it queries wirescale-control synchronously. Cache entries expire after a
configurable TTL (default 60s) and are re-fetched on next access.

**Drift correction:**
The agent periodically verifies actual WireGuard state matches desired state
and removes stale peers that should have been garbage-collected.

### 4.4 wirescale-cni

A stateless binary invoked by the container runtime per-pod. The binary is
short-lived -- it sets up the pod's network namespace and exits. All ongoing
mesh management is handled by the agent.

**CNI ADD flow:**

```
1. Create veth pair: eth0 (pod side) <-> vethXXXX (host side)
2. Move eth0 into pod network namespace
3. Assign IPv6 address from node's /64 pod CIDR
4. Assign IPv4 address from node's /24 pod CIDR (via CLAT tun or direct)
5. Set MTU = host_MTU - 80 (WireGuard overhead)
6. Add routes inside pod:
   - default via IPv6 gateway -> eth0
   - 64:ff9b::/96 via IPv6 gateway -> eth0  (NAT64 prefix)
   - IPv4 default via CLAT tun (if CLAT mode)
7. Add host-side route: pod IPv6 /128 -> vethXXXX
8. Add host-side route: pod IPv4 /32 -> vethXXXX
9. Return CNI result with both IPs
```

### Component Summary

| Component | Type | Runs On | State Size | Purpose |
|-----------|------|---------|------------|---------|
| `wirescale-directory` | Replicated service (3+ nodes, Raft) | Dedicated / management cluster | O(clusters) | Cluster registry, cross-cluster trust root, prefix allocation |
| `wirescale-control` | Deployment (HA, 3+ replicas) | Per cluster, control plane nodes | O(nodes x pods) within cluster | AuthN/AuthZ, peer brokering, identity service, policy service, IPAM, cross-cluster proxy |
| `wirescale-agent` | DaemonSet | Every node | O(active_peers) | On-demand WireGuard peering, NAT64/CLAT, route programming, policy enforcement, identity caching |
| `wirescale-cni` | CNI binary | Every node (invoked by CRI) | Stateless | Pod network namespace setup |
| CoreDNS `dns64` plugin | ConfigMap patch | CoreDNS pods | N/A | Synthesize AAAA records for IPv4-only destinations |

---

## 5. Address Architecture and Hierarchical Prefix Aggregation

### Hierarchical Prefix Model

The addressing scheme is hierarchical: a federation-wide prefix is subdivided
into per-cluster prefixes, which are further subdivided into per-host prefixes.
This enables route aggregation at cluster boundaries.

```
Org prefix:          3fff:1234::/32            (configurable, from RFC 9637 space)
                     |
  +------------------+------------------+
  |                                     |
Cluster 1:           3fff:1234:0001::/48  Cluster 2:         3fff:1234:0002::/48
  |                                       |
  +------+------+                         +------+------+
  |      |      |                         |      |      |
Host 1  Host 2  Host N                  Host 1  Host 2  Host N
:0001:: :0002:: :000N::                 :0001:: :0002:: :000N::
 /64     /64     /64                     /64     /64     /64
```

**Organization level:**
- The global directory allocates a `/48` per cluster from the organization's
  address space.
- Example: org uses `3fff:1234::/32`, Cluster 1 gets `3fff:1234:0001::/48`,
  Cluster 2 gets `3fff:1234:0002::/48`.
- This allows up to 65,536 clusters per `/32` (16 bits of cluster space in a /48).

**Cluster level:**
- Each cluster's `/48` provides 16 bits of host space (65,536 possible /64
  allocations) -- sufficient for any single cluster.
- Each host is allocated a `/64` from its cluster's prefix.
- Example: Cluster 1, Host 42 = `3fff:1234:0001:002a::/64`
- Pods on Host 42 receive /128 addresses from that /64.

**Routing implications:**
- Intra-cluster: O(hosts_in_cluster) /64 routes -- one per host, programmed
  on demand as peers are established.
- Cross-cluster: O(clusters) aggregate routes -- one per remote cluster,
  pointing to the local signaling gateway (or directly to known peers).
- A node in a 10K-node cluster with 200 remote clusters has at most ~10,200
  route entries (most programmed on demand), compared to hundreds of thousands
  in a flat model.

### IPv6 Addressing (Primary)

```
Org prefix:           3fff:1234::/32              (from RFC 9637 space, configurable)
Cluster allocation:   3fff:1234:CCCC::/48         (C = cluster index)
Per-node allocation:  3fff:1234:CCCC:HHHH::/64    (H = host index within cluster)
Pod address:          3fff:1234:CCCC:HHHH::P/128  (P = pod index within node)
Service CIDR:         3fff:1234:CCCC:ffff::/108    (per-cluster)
```

All pod-to-pod, pod-to-service, and pod-to-external communication uses IPv6
natively. The WireGuard mesh endpoints are IPv6 addresses on the physical
network.

In routable-prefix mode (see [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md)), pods
receive globally routable /128 addresses from a site /48 allocation. Fabric
BGP routes /64 prefixes to hosts without any WireGuard involvement in the
forwarding path.

### IPv4 Addressing (Translated)

Every pod also gets an IPv4 address for application compatibility:

```
Internal pod CIDR:    100.64.0.0/10       (CGNAT range, like Tailscale)
Per-node allocation:  100.64.N.0/24       (N = node index)
Pod address:          100.64.N.P/32       (P = pod index)
```

These IPv4 addresses exist only within the WireGuard mesh. They are never
exposed on the physical network. The mapping is:

```
Pod IPv4: 100.64.N.P  <-->  Pod IPv6: 3fff:1234:CCCC:N::P
```

This deterministic mapping enables stateless translation between the two
address families within the mesh.

### NAT64 Prefix

```
64:ff9b::/96          (well-known NAT64 prefix, RFC 6052)
```

Used for reaching external IPv4-only destinations. The IPv4 address is
embedded in the last 32 bits: `64:ff9b::1.2.3.4`.

### Address Summary

```
+------------------+-----------------------------+---------------------------+
| Purpose          | IPv6                        | IPv4                      |
+------------------+-----------------------------+---------------------------+
| Org prefix       | 3fff:1234::/32              | (none)                    |
| Cluster alloc    | 3fff:1234:CCCC::/48         | (none)                    |
| Pod addressing   | 3fff:1234:CCCC:N::P/128     | 100.64.N.P/32             |
| Service VIPs     | 3fff:1234:CCCC:ffff::/108   | 100.64.255.0/24 (opt.)    |
| WireGuard endpt  | <node phys IPv6>:51820      | (none - IPv6 underlay)    |
| External v4 dst  | 64:ff9b::<ipv4>/128         | (translated at egress)    |
| DNS resolver     | 3fff:1234:CCCC::64/128      | 100.100.100.100 (compat)  |
+------------------+-----------------------------+---------------------------+
```

### Aggregate Route Table (Per-Node Example)

A node in Cluster 1 (3fff:1234:0001::/48) with 3 active intra-cluster peers
and 2 known remote clusters:

```
# Intra-cluster: specific /64 routes (on-demand, only for active peers)
3fff:1234:0001:0005::/64  dev wg0 peer=worker-5    # active peer
3fff:1234:0001:002a::/64  dev wg0 peer=worker-42   # active peer
3fff:1234:0001:006b::/64  dev wg0 peer=worker-107  # active peer

# Cross-cluster: aggregate routes (one per remote cluster)
3fff:1234:0002::/48       via gateway0              # Cluster 2 aggregate
3fff:1234:0003::/48       via gateway0              # Cluster 3 aggregate

# Local
3fff:1234:0001:0001::/64  dev cni0                  # this node's pods

# Default
::/0                    via <physical-gw>         # underlay default
```

When a packet for `3fff:1234:0002:0017::5` arrives, it matches the Cluster 2
aggregate route and is sent toward the gateway. The agent (or gateway)
resolves the specific remote node, establishes a direct WireGuard tunnel,
and installs a /64 route that overrides the aggregate for subsequent traffic.

---

## 6. Data Plane: On-Demand WireGuard Peering

### On-Demand Peer Lifecycle

Wirescale does NOT maintain a full mesh of WireGuard peers. Instead, peers
are established on demand when traffic requires encryption, and
garbage-collected when idle. This reduces per-node WireGuard state from
O(total_nodes) to O(active_peers).

```
         Node A                   wirescale-control              Node B
           |                             |                          |
           |  Packet for Node B's /64    |                          |
           |  (no WireGuard peer exists) |                          |
           |                             |                          |
           |--- gRPC: PeerRequest ------>|                          |
           |    (dst prefix, my pubkey)  |                          |
           |                             |--- validate authz ------>|
           |                             |    (is A allowed to      |
           |                             |     peer with B?)        |
           |                             |                          |
           |<-- PeerResponse ------------|                          |
           |    {pubkey, endpoint,       |                          |
           |     allowedIPs, TTL}        |                          |
           |                             |                          |
           |  wg set wg0 peer ...        |                          |
           |  (configure peer)           |                          |
           |                             |                          |
           |========= WireGuard Tunnel ============================|
           |  (encrypted traffic flows)  |                          |
           |                             |                          |
           | ...idle timeout (300s)...   |                          |
           |                             |                          |
           |  wg set wg0 peer remove     |                          |
           |  (GC idle peer)             |                          |
           |                             |                          |
```

**Peer states:**

| State | Description | Transition |
|-------|-------------|------------|
| **absent** | No peer configured for this /64 | First packet triggers PeerRequest |
| **establishing** | PeerRequest in flight, packets queued | PeerResponse received -> active |
| **active** | Peer configured, traffic flowing | Idle timeout -> idle |
| **idle** | No traffic for peer_idle_timeout | GC removes peer -> absent |

**Cold path latency budget (intra-cluster):**

| Operation | Expected Latency |
|-----------|-----------------|
| Identity cache miss (gRPC to control) | ~5-10ms |
| Peer setup (gRPC + WireGuard handshake) | ~10-20ms |
| Total first-packet latency (cold path) | ~15-30ms |
| Subsequent packets (warm path) | 0ms additional overhead |

**Cold path latency budget (cross-cluster):**

| Operation | Expected Latency |
|-----------|-----------------|
| Agent -> local control | ~5ms |
| Local control -> directory (cache miss) | ~10-20ms |
| Local control -> remote control | ~10-30ms (depends on inter-cluster RTT) |
| WireGuard handshake | ~5-10ms |
| Total first-packet latency (cold, cross-cluster) | ~30-65ms |
| Subsequent packets (warm path) | 0ms additional overhead |

The cold path latency of ~15-65ms is acceptable for TCP SYN (which already
tolerates RTT-scale delays). After peer establishment, the warm path is
identical in performance to a pre-configured full mesh.

### State Comparison: Full Mesh vs. On-Demand

| Per-Node State | Full Mesh (Old) | On-Demand (Hyperscale) |
|----------------|----------------|------------------------|
| WireGuard peers | N-1 (all nodes) | Active peers only (~10-50 typical) |
| Identity cache | All pods in cluster | Recently-seen pods (TTL-based) |
| Policy rules | All rules compiled for all nodes | Only rules for local pods |
| Route table | N-1 routes (one per node) | Active peer routes + aggregate routes |
| CRD watches | All WirescaleNode CRDs | Own WirescaleNode CRD only |

At 10,000 nodes, a node communicating with 50 peers holds 50 WireGuard
peer entries instead of 9,999.

### Key Distribution

```
Node boot:
  1. Generate Curve25519 (X25519) keypair (WireGuard)
  2. Private key: memory-only (never written to disk/CRD)
  3. Public key: written to WirescaleNode CRD
  4. Public key: registered with wirescale-control

Key rotation:
  1. Agent generates new keypair
  2. Updates WirescaleNode CRD and notifies control
  3. Control invalidates cached peer info for this node
  4. Active peers of the rotating node receive key-update
     notification via control's push channel
  5. Brief handshake interruption (~1-2 RTT), then traffic resumes
  6. New peers automatically receive the current key from control
```

No pre-shared keys by default (simplicity). PSK support is available as an
option for post-quantum defense-in-depth.

### WireGuard Configuration per Node

At any given moment, a node's WireGuard configuration contains only its
active peers -- not all nodes in the cluster:

```
[Interface]
ListenPort = 51820
PrivateKey = <generated-at-boot>

# Active Peer: worker-42 (established 2m ago, last handshake 15s ago)
[Peer]
PublicKey = <from wirescale-control PeerResponse>
Endpoint = [3fff:1234:0001:ff01::2a]:51820
AllowedIPs = 3fff:1234:0001:002a::/64, 100.64.42.0/24

# Active Peer: worker-107 (established 30s ago, last handshake 5s ago)
[Peer]
PublicKey = <from wirescale-control PeerResponse>
Endpoint = [3fff:1234:0001:ff01::6b]:51820
AllowedIPs = 3fff:1234:0001:006b::/64, 100.64.107.0/24

# Cross-cluster Peer: cluster-2-node-23 (established 5m ago)
[Peer]
PublicKey = <from remote cluster's control via proxy>
Endpoint = [3fff:1234:0002:ff01::17]:51820
AllowedIPs = 3fff:1234:0002:0017::/64

# (only 3 active peers out of 10,000+ nodes across clusters)
```

The `AllowedIPs` for each peer covers both the IPv6 and IPv4 pod CIDRs of
that node. WireGuard's cryptokey routing handles both address families
through the same tunnel.

### Routing Modes

**ULA overlay mode (default):**
- All inter-node pod traffic goes through WireGuard (encryption + routing)
- On-demand peering: first packet to a new /64 triggers peer setup via control
- Routes for active peers are programmed dynamically as peers are established
- Cross-cluster aggregate routes point to local signaling gateway

**Routable-prefix mode (see [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md)):**
- Fabric BGP routes /64 prefixes to hosts -- packets reach the right host
  without WireGuard involvement in the forwarding path
- WireGuard is used for encryption only, not routing
- On-demand peering still applies: WireGuard peers are established only when
  encryption policy requires it for a given destination
- Unencrypted intra-zone traffic MAY bypass WireGuard entirely (by policy)

### MTU Handling

```
Physical interface MTU:  1500 (typical)
WireGuard overhead:      60 bytes (20 IPv4 + 8 UDP + 32 WG data header/tag)
                         80 bytes with IPv6 outer header (40 IPv6 + 8 UDP + 32 WG)
Pod interface MTU:       1420 (1500 - 80)
TCP MSS clamping:        1380 (1420 - 40 for IPv6 TCP header)
```

The agent programs MSS clamping via nftables on the `wg0` interface to
prevent fragmentation.

### Multicast and Neighbor Discovery Through WireGuard

#### Background

IPv6 NDP (RFC 4861) relies on link-local multicast -- solicited-node
multicast `ff02::1:ffXX:XXXX` -- to resolve addresses to link-layer
addresses.  WireGuard is Layer 3 point-to-point: it carries routed
unicast and does not forward link-local multicast.

#### When NDP Works Natively

**Routable-prefix mode with unencrypted forwarding** (ROUTABLE-PREFIX.md
Section 7, encryption policy = `default` or `cross-cluster-only`):

- Intra-cluster traffic traverses the physical L2 segment.
- NDP operates on `eth0` against the rack /64 as usual.
- Cross-node traffic within the same L2 domain resolves the next-hop
  (ToR gateway) via standard NDP on `eth0`.

No Wirescale-specific handling is required in this mode.

#### When NDP Needs Help

**ULA overlay mode** (ARCHITECTURE.md Section 6) and **routable-prefix
with `always` encryption** (ROUTABLE-PREFIX.md Section 8):

All inter-node pod traffic goes through `wg0`, which has no link-layer
address resolution.  NDP solicitations sent into `wg0` have no
meaningful recipient.

| Scenario | Interface | NDP Status |
|----------|-----------|------------|
| Same node | `cni0` bridge / veth | Works (local L2) |
| Cross-node, overlay/always-encrypt | `wg0` | Broken (L3 P2P) |
| Pod-to-external, overlay | `wg0` -> physical | Broken on `wg0` leg |
| Host NDP on physical NIC | `eth0` | Works (native L2) |

#### Solution: NDP Suppression on Overlay Paths

The wirescale-agent MUST suppress NDP on WireGuard paths and rely on
explicit routing entries from the control plane:

1. **Explicit /64 routes.**  When the agent installs a WireGuard peer,
   it programs the remote node's entire /64 via the `wg0` nexthop.
   Individual pod /128s within that /64 are resolved by the remote node
   after decryption -- no local neighbor resolution is needed.

2. **Static neighbor entries for local pods.**  The agent MUST install
   static or proxy neighbor entries on `cni0` for each local pod's
   link-local and global addresses, ensuring intra-node NDP succeeds
   without multicast.

3. **eBPF NDP interception.**  The agent SHOULD attach a TC/XDP program
   on `wg0` that drops NDP Neighbor Solicitation packets, preventing
   unresolvable solicitations from wasting tunnel bandwidth.

```
Pod A (node-1) -> Pod B (node-2), overlay mode:

  Pod A sends to 3fff:1234:0001:0002::b
    -> host routing: 3fff:1234:0001:0002::/64 via wg0 peer=node-2
    -> NO NDP: route is explicit, nexthop is the WireGuard peer
    -> wg0 encrypts, sends to node-2
    -> node-2 decrypts, routes to Pod B via local veth (local bridge)
```

#### Multicast Applications (mDNS, MLD)

General IPv6 multicast (`ff02::/16`, `ff05::/16`) does not traverse
WireGuard.  Implications:

- **mDNS / DNS-SD** (`ff02::fb`): MUST NOT be relied upon for
  cross-node discovery.  Use Wirescale DNS (ARCHITECTURE.md Section 9).
- **MLD:** Unaffected in routable-prefix native mode.  In overlay mode,
  MLD is confined to the local node's bridge.
- **Application multicast:** Workloads needing cross-node multicast
  MUST be adapted to unicast or use an external multicast overlay.

The agent SHOULD log a warning when multicast traffic is destined for
`wg0`.

#### NDP and Multicast Summary

| Traffic Type | Native/Routable Mode | Overlay / Always-Encrypt Mode |
|-------------|---------------------|-------------------------------|
| NDP (same node) | Works | Works (local bridge) |
| NDP (cross-node) | Works (physical L2) | Suppressed; explicit routes |
| Solicited-node multicast | Works | Dropped on `wg0` |
| mDNS / DNS-SD | Works on L2 segment | Use Wirescale DNS |
| Application multicast | Works on L2 segment | Not available cross-node |

---

## 7. Cross-Cluster Connectivity

### Signaling Gateway Model

Each cluster designates gateway nodes (typically 2-3 for HA). Gateways handle
**signaling only** -- initial cross-cluster peer resolution. They are NOT in
the data path for established flows.

```
Cluster 1 (3fff:1234:0001::/48)      Cluster 2 (3fff:1234:0002::/48)

+---------+                           +---------+
| Node A  |                           | Node B  |
| (agent) |                           | (agent) |
+----+----+                           +----+----+
     |                                     |
     | 1. Packet for 3fff:1234:0002::/48   |
     |    hits aggregate route             |
     |    -> signaling gateway             |
     |                                     |
+----+----+                           +----+----+
| Gateway |                           | Gateway |
| (signal |                           | (signal |
|  only)  |                           |  only)  |
+----+----+                           +----+----+
     |                                     |
     | 2. Agent resolves via               |
     |    control -> directory -> remote   |
     |    control -> specific node B info  |
     |                                     |
     +=====================================+
     | 3. Direct WireGuard tunnel          |
     |    Node A <-> Node B                |
     |    (gateway bypassed for data)      |
     +=====================================+
```

**Why signaling-only gateways?**
- Gateways are NOT a throughput bottleneck -- data flows directly between nodes
- Gateways CAN be data relays for nodes without direct reachability (NAT
  traversal), but this is the exception, not the rule
- Gateway failure does not disrupt established cross-cluster tunnels
- No single point of failure for cross-cluster data traffic

### Cross-Cluster Peer Establishment Flow

```
Node A (cluster 1) wants to reach Pod on Node B (cluster 2):

  1. Packet matches aggregate route 3fff:1234:0002::/48 -> gateway
  2. Agent intercepts (or gateway forwards to agent): cache miss
  3. Agent -> local wirescale-control: "resolve 3fff:1234:0002:002a::/64"
  4. Local control checks cache for cluster 2 info
     a. Cache miss: local control -> global directory: "where is cluster 2?"
     b. Global directory -> local control:
        {cluster_2_controller_endpoint, cluster_2_CA}
     c. Local control caches this (TTL 300s)
  5. Local control -> cluster 2 controller:
     "resolve host 002a, here's my cluster 1 cert"
  6. Cluster 2 controller authenticates cluster 1, checks policy, returns:
     {node_B_endpoint, node_B_pubkey, allowed_IPs}
  7. Local control -> agent: peer info for node B
  8. Agent establishes direct WireGuard tunnel to node B
  9. Agent installs /64 route for node B pointing to wg peer
     (overrides aggregate route)
  10. All traffic flows directly, gateway bypassed
```

**Subsequent packets to the same node:** Warm path, zero additional overhead
(the specific /64 route already exists).

**Subsequent packets to a different node in the same remote cluster:** Steps
3-10 repeat for the new node, but step 4 is a cache hit (cluster info is
already cached). Total latency is reduced by ~10-20ms.

### Cross-Cluster Trust Model

- The global directory is the root of trust for cross-cluster authentication
- Each cluster controller holds a cluster-scoped CA certificate
- During cross-cluster peer resolution, controllers authenticate via mTLS
  using their cluster CA certificates (validated against the directory's
  trusted CA list)
- No per-pod or per-node state is exchanged between clusters at rest --
  only at the time of connection establishment
- Cross-cluster peer authorization tokens are scoped to the specific
  cluster pair and node pair, with bounded TTL

### Cross-Cluster Addressing

- Hierarchical prefix aggregation (see [Section 5](#5-address-architecture-and-hierarchical-prefix-aggregation))
  makes cross-cluster routing efficient: one aggregate route per remote cluster.
- In routable-prefix mode (see [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md)),
  each cluster's prefix is routable via BGP, so packets reach the correct
  cluster without Wirescale involvement in the forwarding path.
- WireGuard provides encryption for cross-cluster traffic using the same
  on-demand peering model as intra-cluster traffic.

### Any-Node Peering

Unlike gateway-only models, any node in Cluster A MAY establish a direct
WireGuard peer with any node in Cluster B. There is no requirement to
funnel cross-cluster traffic through designated gateway nodes once the
initial peer resolution is complete. This eliminates single-point-of-failure
and bandwidth bottleneck concerns inherent in gateway-based designs.

### External Peers (Non-Kubernetes Nodes)

Wirescale supports connecting external machines (bare metal servers, VMs,
developer laptops) to the mesh via the `WirescaleExternalPeer` CRD:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleExternalPeer
metadata:
  name: office-server
spec:
  publicKey: "YWJjZGVm..."
  endpoint: "[3fff:1234:00ff:ff01::1]:51820"
  allowedIPs:
    - "3fff:1234:00ff:0001::/64"      # External peer's subnet
    - "100.64.200.0/24"        # External peer's IPv4 range
  # Optional: advertise routes FROM the external peer into the mesh
  advertisedRoutes:
    - "192.168.1.0/24"         # Office LAN (subnet router mode)
```

External peers authenticate to wirescale-control using a pre-shared
registration token. After initial registration and admin approval, the
external peer uses the same on-demand peering model as in-cluster nodes:
it queries control for peer info when it needs to reach a cluster pod,
and cluster nodes query control when they need to reach the external peer.

### Subnet Router Mode

Any node (or external peer) can advertise additional routes into the mesh,
like Tailscale's subnet router:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleNode
metadata:
  name: node-with-legacy-lan
spec:
  # ... normal fields ...
  advertisedRoutes:
    - "10.0.0.0/8"     # Legacy corporate network
    - "172.16.0.0/12"  # Another internal range
```

Nodes that need to reach advertised subnets establish on-demand WireGuard
peers with the advertising node through wirescale-control.

### Exit Node Mode

A node can be designated as an exit node for internet-bound traffic:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleNode
metadata:
  name: egress-node
spec:
  exitNode: true   # Advertise 0.0.0.0/0 and ::/0
```

Pods can be configured (via annotation or policy) to route all non-mesh
traffic through the exit node. This is useful for:
- Centralizing egress through a node with both IPv4 and IPv6 connectivity
- Egress filtering/auditing at a single point
- Providing IPv4 internet access when most nodes are IPv6-only

### NAT Traversal

When direct node-to-node reachability is not available (nodes behind NAT),
the signaling gateway MAY act as a data relay:

- The gateway maintains a WireGuard peer with both nodes
- Traffic is relayed through the gateway's WireGuard interface
- This adds one extra hop but preserves end-to-end encryption
- The agent SHOULD periodically attempt to re-establish a direct tunnel
  (NAT hole-punching via coordinated endpoint exchange through control)
- A DERP-like relay protocol MAY be implemented for better NAT traversal

---

## 8. IPv4 in an IPv6-Only World

This is the core innovation: making IPv4 "just work" for pods on an
IPv6-only underlay. Three mechanisms work together:

### 8.1 CLAT (Customer-side Translator) -- Pod-Local IPv4

Each pod gets a `clat0` TUN interface that provides a real IPv4 address.
Applications can bind to IPv4, connect to IPv4 addresses, and use IPv4
socket APIs.

```
Pod network namespace:
  eth0:   3fff:1234:0001:0001::5/128    (primary, IPv6)
  clat0:  100.64.1.5/32              (CLAT, IPv4)

  IPv4 default route -> clat0
  IPv6 default route -> eth0
```

**How CLAT works:**

```
App sends IPv4 packet to 93.184.216.34 (example.com)
         |
         v
   clat0 TUN interface (in pod netns)
         |
   Stateless SIIT translation (RFC 7915):
     src: 100.64.1.5        -> 3fff:1234:0001:0001::5
     dst: 93.184.216.34     -> 64:ff9b::93.184.216.34
         |
         v
   eth0 (IPv6 packet exits pod)
         |
   host routing:
     - In-mesh IPv4 compatibility traffic -> deterministic pod mapping over wg0
     - External IPv4 destinations -> 64:ff9b::/96 via nat64 interface
```

The CLAT translation is stateless and deterministic. The reverse mapping
works because of the 1:1 correspondence between IPv4 pod addresses and
IPv6 pod addresses.

### 8.2 NAT64 -- Reaching External IPv4 Destinations

For traffic destined to IPv4-only hosts on the internet, a per-node NAT64
engine translates at the cluster edge.

```
wirescale-agent on each node:
  nat64 interface: 64:ff9b::/96

  Inbound (from pod):
    IPv6 dst = 64:ff9b::93.184.216.34
    -> Extract embedded IPv4: 93.184.216.34
    -> Translate to IPv4 packet
    -> MASQUERADE with node's IPv4 address (if node has one)
       or forward to a designated NAT64 gateway node

  Return path:
    IPv4 src = 93.184.216.34, dst = node's IPv4
    -> Reverse translate to IPv6
    -> Route back to originating pod
```

**Implementation:** eBPF programs attached to the `nat64` dummy interface
perform stateless address translation. Connection tracking is handled by
Linux conntrack for the MASQUERADE step.

### 8.3 DNS64 -- Making It Transparent

CoreDNS is configured with the `dns64` plugin:

```
.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    dns64 {
        prefix 64:ff9b::/96
        # translate_all is optional and disabled by default
        # translate_all
    }
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
```

When a pod queries `example.com` and only an A record exists:
1. CoreDNS queries upstream, gets `A 93.184.216.34`
2. `dns64` plugin synthesizes `AAAA 64:ff9b::5db8:d822`
3. Pod connects to `64:ff9b::5db8:d822` over IPv6
4. NAT64 engine translates to IPv4 at the node boundary

When an AAAA record exists, it is returned directly unless `translate_all` is
explicitly enabled.

### 8.4 Complete IPv4 Flow (Pod to External IPv4 Host)

```
Pod (100.64.1.5 / 3fff:1234:0001:0001::5)
  |
  | App: connect("93.184.216.34", 80)
  v
clat0 (CLAT: IPv4 -> IPv6)
  | src: 3fff:1234:0001:0001::5
  | dst: 64:ff9b::5db8:d822
  v
eth0 -> veth -> host routing
  |
  | route: 64:ff9b::/96 -> nat64
  v
nat64 interface (eBPF xlat: IPv6 -> IPv4)
  | src: <node-ipv4>  (MASQUERADE)
  | dst: 93.184.216.34
  v
Physical NIC -> Internet -> 93.184.216.34

Return path reverses each step.
```

### 8.5 IPv4 Within the Mesh

Pod-to-pod IPv4 traffic stays within the WireGuard mesh and never hits
NAT64. The routing is:

```
Pod A on node-1: app connects to 100.64.2.7 (Pod B's IPv4)
  |
  | clat0: translate to IPv6
  | src: 3fff:1234:0001:0001::5, dst: 3fff:1234:0001:0002::7
  v
  eth0 -> host routing
  |
  | route: 3fff:1234:0001:0002::/64 -> wg0
  | (if no WireGuard peer for node-2: on-demand peer setup via control)
  v
  wg0: encrypt and send to node-2
  |
  v
  Node 2: wg0 decrypt -> route to pod B's veth -> Pod B
  |
  | Pod B's clat0: translate back to IPv4
  v
  App on Pod B sees: src=100.64.1.5 dst=100.64.2.7
```

### 8.6 Cross-Cluster IPv4 Address Collisions

#### The Problem

The CLAT mapping `100.64.N.P <--> 3fff:1234:CCCC:N::P` embeds the node
index `N` and pod index `P` but not the cluster index `CCCC`.  Two pods
on identically-indexed nodes in different clusters receive the same IPv4
address:

```
Cluster 1, Node 3, Pod 7:  100.64.3.7  <-->  3fff:1234:0001:0003::7
Cluster 2, Node 3, Pod 7:  100.64.3.7  <-->  3fff:1234:0002:0003::7
```

Both pods believe they own `100.64.3.7`.  Within a single cluster this
is unambiguous because CLAT resolves the IPv4 address against the local
cluster's IPv6 prefix.  Across clusters, the same IPv4 address maps to
two distinct IPv6 endpoints and the reverse translation is ambiguous.

#### Design Decision: IPv4 Is Intra-Cluster Only

Cross-cluster pod-to-pod traffic MUST use IPv6 addresses.  The CGNAT
`100.64.0.0/10` address space is scoped to the originating cluster and
MUST NOT be routed across cluster boundaries.

Rationale:

1. **Ambiguous reverse mapping.**  A destination of `100.64.3.7` cannot
   be translated to a unique IPv6 address without knowing the target
   cluster -- information that is absent from the IPv4 packet.
2. **Address space exhaustion.**  `100.64.0.0/10` provides ~4 million
   addresses.  Partitioning it across clusters (e.g., `/16` per cluster)
   severely limits per-cluster pod capacity and introduces fragile
   coordination between the global directory and CLAT configuration.
3. **IPv6 is the primary address family.**  Wirescale is an IPv6-native
   architecture.  Cross-cluster connectivity (Section 7) operates on
   hierarchical IPv6 prefixes with route aggregation; IPv4 is a
   compatibility layer for legacy applications, not a routable fabric.

#### Enforcement

The wirescale-agent MUST NOT install CLAT reverse-translation routes
for remote clusters.  Specifically:

- The `100.64.0.0/10` route on each node MUST point only to the local
  CLAT translation path, never to a WireGuard peer in another cluster.
- Cross-cluster aggregate routes (`3fff:1234:CCCC::/48` for remote
  clusters) MUST NOT have corresponding IPv4 CGNAT routes.
- If a pod attempts to reach an IPv4 address that maps to a remote
  cluster's IPv6 prefix, the packet MUST be dropped and the agent
  SHOULD log a diagnostic message.

#### Operator Guidance

Applications that require cross-cluster communication MUST use IPv6
addresses or DNS names that resolve to IPv6 (AAAA records).  The
cross-cluster DNS system (Section 9) returns AAAA records for remote
pods; operators SHOULD NOT configure A record synthesis for cross-cluster
names.

For legacy applications that cannot use IPv6 socket APIs, operators MAY
deploy an application-layer proxy (e.g., Envoy, HAProxy) within the
local cluster that accepts IPv4 connections and forwards to the remote
pod's IPv6 address.

```
Legacy IPv4 app -> 100.64.N.P (local proxy pod)
  -> proxy opens IPv6 connection to 3fff:1234:CCCC:H::Q (remote pod)
  -> cross-cluster WireGuard tunnel (IPv6)
  -> remote pod receives IPv6 connection
```

This preserves the deterministic CLAT model within each cluster while
providing a clear upgrade path for cross-cluster IPv4 consumers.

---

## 9. DNS Architecture

### In-Mesh DNS (MagicDNS-inspired)

Every pod in the mesh is resolvable by name, like Tailscale's MagicDNS:

```
<pod-name>.<namespace>.ws.cluster.internal          -> 3fff:1234:CCCC:N::P (AAAA)
<pod-name>.<namespace>.ws.cluster.internal          -> 100.64.N.P        (A)
<service-name>.<namespace>.svc.ws.cluster.internal  -> service VIP
```

The wirescale-agent runs a lightweight DNS sidecar that:
1. Receives pod IP-to-name mappings from wirescale-control (pushed for local
   pods, queried on demand for remote pods)
2. Maintains an in-memory name-to-IP map
3. Serves DNS queries for `*.ws.cluster.internal` domain
4. Forwards all other queries to CoreDNS (which handles `dns64`)

### Cross-Cluster DNS

For cross-cluster name resolution, the DNS sidecar queries wirescale-control,
which proxies the request to the remote cluster's controller (the same path
used for cross-cluster peer resolution). This enables:

```
<pod-name>.<namespace>.ws.<cluster-name>.internal   -> 3fff:1234:CCCC:N::P (AAAA)
```

Cross-cluster DNS queries are resolved on demand and cached with TTLs. The
agent does NOT pre-fetch DNS records for remote clusters.

### DNS Query Flow

```
Pod makes DNS query for "api.backend.ws.cluster.internal"
  |
  v
CoreDNS (cluster DNS)
  |
  | matches ws.cluster.internal -> forward to wirescale DNS
  v
wirescale-agent DNS
  |
  | lookup in-memory map
  | if miss: query wirescale-control for name resolution
  | returns AAAA: 3fff:1234:0001:0003::12 and A: 100.64.3.12
  v
Pod receives answer, connects directly via mesh
```

For external names:
```
Pod makes DNS query for "example.com"
  |
  v
CoreDNS
  |
  | forward to upstream
  | if only A record: dns64 synthesizes AAAA
  v
Pod receives AAAA (native or synthesized)
```

### 9.1 StatefulSet Stable Network Identities

#### The Challenge

Kubernetes StatefulSets provide stable DNS names via headless Services:
`web-0.web.<ns>.svc.cluster.local` survives rescheduling.  The IP
address behind that name does not.

In Wirescale, pod IPs derive from the hosting node's /64 prefix
(`3fff:1234:CCCC:HHHH::P`).  When a StatefulSet pod moves to a different
node, `HHHH` changes:

```
web-0 on node-3:  3fff:1234:0001:0003::1 / 100.64.3.1
web-0 on node-7:  3fff:1234:0001:0007::1 / 100.64.7.1  (after reschedule)
```

This is consistent with standard Kubernetes -- pod IPs are always
ephemeral -- but certain patterns are sensitive to it:

- **IP caching:** Connection pools or gRPC channels that resolve once
  and hold the IP for the lifetime of the connection.
- **Ordinal discovery:** Patterns like "connect to `web-{0..N-1}`" that
  resolve all peers at startup and cache the results.
- **Storage affinity:** PVs with node affinity constrain rescheduling,
  reducing IP changes in practice but not eliminating them.

#### Interaction with Wirescale DNS

Both Kubernetes DNS and Wirescale DNS (`*.ws.cluster.internal`) MUST
return the current pod IP after rescheduling:

```
web-0.web.default.svc.cluster.local   -> AAAA 3fff:1234:0001:0007::1
web-0.web.default.ws.cluster.internal -> AAAA 3fff:1234:0001:0007::1
```

The wirescale-agent MUST update its in-memory name-to-IP map within 5
seconds of receiving a pod relocation event from wirescale-control.
CoreDNS cache TTL (default 30s, per Section 8.3) bounds how quickly
downstream clients observe the change.

#### Stable IPs Are a Non-Goal

Wirescale does NOT provide node-independent stable IPs for StatefulSet
pods.  A reserved /128 pool would require:

- Addresses outside the /64-per-host model, breaking hierarchical
  prefix aggregation (Section 5).
- Per-pod /128 routes on every node, regressing routing state from
  O(hosts) to O(statefulset_pods).
- Scheduler-to-allocator coordination to ensure the /128 is routable
  regardless of placement.

This contradicts the design principles in Section 2 (hierarchical
aggregation, minimal per-node state).

#### Operator Guidance

1. **Use DNS names, not IPs.**  All StatefulSet peer communication
   MUST go through DNS.  Applications SHOULD re-resolve on reconnect
   rather than caching addresses indefinitely.

2. **Lower DNS TTLs for latency-sensitive workloads.**  Operators MAY
   reduce the CoreDNS cache TTL for faster convergence:
   ```
   cache 5   # 5-second TTL
   ```

3. **Retry with re-resolution.**  Applications SHOULD trigger a fresh
   DNS lookup on connection failure rather than retrying a cached IP.

4. **Topology constraints.**  Use `topologySpreadConstraints` or node
   affinity to reduce cross-node rescheduling frequency where stable
   placement is operationally important.

5. **ClusterIP for stable VIPs.**  When a fixed address is needed
   (e.g., a database primary), use a ClusterIP Service instead of a
   headless Service.  The VIP is allocated from the Service CIDR
   (`3fff:1234:CCCC:ffff::/108`) and is placement-independent.

---

## 10. Cross-Cluster Service Discovery and Load Balancing

Sections 7 and 9 describe how individual pods in one cluster can reach
individual pods in another via on-demand WireGuard peering and cross-cluster
DNS. However, Kubernetes workloads overwhelmingly communicate via **Services**,
not raw pod IPs. Cilium's ClusterMesh provides multi-cluster services through
full state synchronization -- an approach that does not scale past a handful of
clusters (see [Section 5 of CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md#5-multi-cluster-clustermesh-vs-global-directory)).
This section designs the Wirescale replacement: on-demand, hierarchical
cross-cluster service discovery and load balancing that maintains O(active_services)
state per node, not O(all_services_all_clusters).

### 10.1 Cross-Cluster Service Model

A pod in cluster-1 discovers and reaches a Service in cluster-2 through the
following conceptual flow:

1. **Export:** The service owner in cluster-2 creates a `WirescaleServiceExport`
   declaring that a local Service is available to remote clusters.
2. **Register:** The cluster-2 controller registers the exported service with
   the global directory as a lightweight metadata entry.
3. **Import:** A consuming cluster (cluster-1) creates a `WirescaleServiceImport`
   that references the remote service by name and origin cluster.
4. **Resolve:** When a pod in cluster-1 first attempts to reach the imported
   service (via DNS or VIP), the local controller resolves endpoints on demand
   through the hierarchy: local controller -> directory -> remote controller.
5. **Connect:** The resolved backend endpoints are programmed into the local
   cluster's load-balancing datapath. WireGuard peers to the remote backend
   nodes are established on demand (the existing cross-cluster peering flow
   from Section 7).

A node in cluster-1 MUST NOT learn about services in cluster-2 unless a
`WirescaleServiceImport` in cluster-1 explicitly references them. There is no
background synchronization of service catalogs.

### 10.2 WirescaleServiceExport / WirescaleServiceImport CRDs

The CRD design follows the KEP-1645 Multi-Cluster Services API pattern but
adapts it for the three-tier hierarchy.

**WirescaleServiceExport** (namespace-scoped, in the exporting cluster):

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleServiceExport
metadata:
  name: api-server
  namespace: backend
spec:
  serviceRef:
    name: api-server
    ports:                              # optional: export a subset of ports
      - { name: grpc, port: 9090, protocol: TCP }
  allowedClusters: ["cluster-1", "cluster-3"]   # empty = all federated clusters
  topology:
    mode: proximity                     # "proximity" | "global" | "weighted" | "failover"
  globalName: "api-server.backend"      # optional: override global service name
status:
  exported: true
  registeredInDirectory: true
  importingClusters:
    - { clusterID: "cluster-1", lastSync: "2026-03-10T08:00:00Z" }
```

**WirescaleServiceImport** (namespace-scoped, in the importing cluster):

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleServiceImport
metadata:
  name: remote-api-server
  namespace: backend
spec:
  sourceCluster: "cluster-2"
  serviceRef: { name: api-server, namespace: backend }
  localServiceName: api-server-cluster2   # local k8s Service created with this name
  ports:
    - { name: grpc, port: 9090, protocol: TCP }
  vip:
    mode: allocate                        # "allocate" | "global" (see Section 10.4)
  healthCheck:
    intervalSeconds: 10
    timeoutSeconds: 3
status:
  imported: true
  vip: "3fff:1234:0001:ffff::a02"
  vipv4: "100.64.255.42"
  endpoints:
    - { clusterID: "cluster-2", ready: 3, notReady: 0, lastResolved: "2026-03-10T08:00:15Z" }
```

### 10.3 Resolution via the Control Hierarchy

Service resolution follows the same three-tier, on-demand pattern as
cross-cluster peer resolution. The directory gains a lightweight service
registry; controllers handle endpoint resolution.

```
Pod in cluster-1 resolves "api-server-cluster2.backend.svc.cluster.local"
  |
  v
CoreDNS -> kube-proxy/Cilium service VIP (allocated locally)
  |
  v
First packet hits VIP with no backends programmed (cold path):
  1. wirescale-agent intercepts (no backend in eBPF/IPVS map)
  2. Agent -> wirescale-control (cluster-1):
       "resolve WirescaleServiceImport backend/remote-api-server"
  3. Control (cluster-1) checks local endpoint cache
     a. Cache miss: control -> global directory:
        "service api-server.backend exported by cluster-2?"
     b. Directory -> control:
        {cluster_2_controller, endpoint_count: 3, ports: [9090/TCP]}
     c. Control caches directory response (TTL 300s)
  4. Control (cluster-1) -> control (cluster-2) via mTLS:
       "give me endpoints for Service backend/api-server"
  5. Control (cluster-2) returns:
       {endpoints: [
         {ip: "3fff:1234:0002:000a::5", node: "3fff:1234:0002:000a::/64",
          port: 9090, zone: "us-east-2a"},
         {ip: "3fff:1234:0002:0014::3", node: "3fff:1234:0002:0014::/64",
          port: 9090, zone: "us-east-2b"},
         {ip: "3fff:1234:0002:001e::9", node: "3fff:1234:0002:001e::/64",
          port: 9090, zone: "us-east-2c"}
       ], TTL: 30}
  6. Control (cluster-1) -> agent:
       endpoint list for the imported service
  7. Agent programs endpoints into local LB datapath
       (eBPF map or IPVS, depending on datapath mode)
  8. Agent triggers on-demand WireGuard peer setup for the
       selected backend node (standard Section 7 flow)
  9. Queued packets drain to the selected backend
```

**Subsequent requests:** The agent holds a cached endpoint list (TTL-based).
Backend selection and WireGuard peering are warm-path operations. The
controller refreshes endpoints from the remote cluster before TTL expiry.

**Endpoint TTL:** Remote endpoint lists MUST have a short TTL (default 30s)
because the importing cluster does not watch remote pod events. The remote
controller MUST return the current healthy endpoint set at each refresh. If
the remote controller is unreachable, the agent MUST continue using the
last-known endpoint list until `staleEndpointTimeout` (default 120s),
then mark the service as degraded.

### 10.4 Cross-Cluster Service VIPs

Three VIP strategies are supported, selectable per `WirescaleServiceImport`:

| Strategy | VIP Source | Pros | Cons |
|----------|-----------|------|------|
| **Local allocation** (default) | Local cluster service CIDR (`3fff:1234:CCCC:ffff::/108`) | No cross-cluster VIP coordination; works with any CNI; kube-proxy/Cilium handles VIP natively | Same service has different VIPs in each importing cluster |
| **Global VIP** | Federation service CIDR (`3fff:1234:0000:ffff::/108`, reserved) | Same VIP everywhere; enables service migration | Requires directory-level VIP allocation; nodes must recognize the global service CIDR |
| **Anycast VIP** | Shared prefix announced via BGP from multiple clusters | Clients routed to nearest cluster by network topology | Requires BGP integration; connection pinning challenges |

**Local allocation (default):** `wirescale-control` allocates a VIP from the
local `serviceCIDRv6` (e.g., `3fff:1234:0001:ffff::/108`) and a corresponding
IPv4 VIP from `serviceCIDRv4`. A Kubernetes Service is created with
EndpointSlice entries managed by wirescale-control. kube-proxy or Cilium
handles the VIP natively -- no changes required.

**Global VIP:** The global directory allocates VIPs from the reserved
federation service prefix `3fff:1234:0000:ffff::/108`. Every importing cluster
programs the same VIP. The global CIDR MUST be routed on every node. Useful
when VIPs are embedded in configuration or when services migrate between
clusters.

**Example VIP allocation (local mode):**

```
Cluster-1 imports "api-server" from cluster-2:
  Local VIP:     3fff:1234:0001:ffff::a02 / 100.64.255.42
  Backends:      3fff:1234:0002:000a::5:9090
                 3fff:1234:0002:0014::3:9090
                 3fff:1234:0002:001e::9:9090

Cluster-3 imports the same service:
  Local VIP:     3fff:1234:0003:ffff::701 / 100.64.255.33
  Backends:      (same remote endpoints, different local VIP)
```

### 10.5 Load Balancing

Traffic distribution across backends in multiple clusters uses a two-level
scheme: **inter-cluster** (which cluster receives traffic) and
**intra-cluster** (which endpoint within the chosen cluster).

**Topology-aware inter-cluster selection:**

When a service is available in both the local cluster and remote clusters
(a service exported from multiple clusters, or a local service augmented
by remote backends), the load balancer MUST support topology preferences:

| Mode | Behavior |
|------|----------|
| `proximity` (default) | Prefer local-cluster backends. Spill to remote clusters only when local backends are insufficient (< `minLocalEndpoints`) or unhealthy. |
| `global` | Treat all backends across all clusters as a single pool. Weight by endpoint count per cluster. |
| `weighted` | Explicit per-cluster weights (e.g., cluster-1: 70%, cluster-2: 30%). |
| `failover` | Use remote backends only when all local backends are unhealthy. |

**Intra-cluster backend selection:** Within a chosen cluster, standard
load-balancing applies: Maglev consistent hashing (for eBPF/Cilium datapath)
or round-robin (for IPVS). The agent programs remote backends into the same
LB map used for local services.

**Session affinity:** When `sessionAffinity: ClientIP` is configured on the
`WirescaleServiceImport`, the LB MUST pin a given source IP to a consistent
backend across clusters for the affinity timeout. Maglev hashing naturally
provides this property.

**Endpoint weighting:** Remote endpoints MAY carry weights reported by the
exporting cluster's controller. Controllers SHOULD set lower weights for
endpoints in zones with high latency relative to the importing cluster.

### 10.6 DNS Integration

Cross-cluster services appear in DNS through two complementary mechanisms.

**Mechanism 1: Standard Kubernetes DNS (via local Service, RECOMMENDED)**

Each `WirescaleServiceImport` creates a local Kubernetes Service, so standard
DNS works without modification:

```
api-server-cluster2.backend.svc.cluster.local  ->  3fff:1234:0001:ffff::a02
```

**Mechanism 2: Wirescale mesh DNS (global names)**

For federation-wide names consistent across clusters, the wirescale-agent DNS
sidecar (from Section 9) resolves names under a dedicated zone:

```
<service>.<namespace>.svc.ws.<cluster-name>.internal   -> remote service VIP
<service>.<namespace>.svc.ws.global.internal           -> global VIP (if allocated)
```

Examples:
```
api-server.backend.svc.ws.cluster-2.internal     -> 3fff:1234:0001:ffff::a02
                                                    (local VIP for cluster-2's export)
api-server.backend.svc.ws.global.internal        -> 3fff:1234:0000:ffff::42
                                                    (federation global VIP)
```

Both zones are resolved by the wirescale-agent DNS sidecar via on-demand
queries to wirescale-control.

**DNS query flow for cross-cluster service:**

```
Pod queries "api-server.backend.svc.ws.cluster-2.internal"
  |
  v
CoreDNS: matches ws.*.internal -> forward to wirescale-agent DNS
  |
  v
wirescale-agent DNS:
  lookup in-memory cache for service VIP
  if miss: query wirescale-control for imported service resolution
  return: AAAA 3fff:1234:0001:ffff::a02 / A 100.64.255.42
  |
  v
Pod connects to VIP -> LB selects backend -> WireGuard tunnel to remote node
```

### 10.7 Health Checking

Backend health is tracked across clusters without requiring direct probe
connectivity from every importing node to every remote backend.

**Responsibility model:**

| Component | Health-Check Scope |
|-----------|-------------------|
| Remote wirescale-control | Tracks readiness of local endpoints via Kubernetes readinessProbe / EndpointSlice status |
| Remote wirescale-control | Runs optional L4 probe (TCP connect) or L7 probe (HTTP GET) to backends |
| Local wirescale-control | Receives healthy endpoint list from remote control at each refresh (TTL-based) |
| Local wirescale-agent | Removes unhealthy backends from LB map when refresh indicates endpoint removal |

**Cross-cluster health propagation:**

```
cluster-2 (exporting):
  Pod becomes unready (kubelet readinessProbe fails)
    -> EndpointSlice updated (endpoint removed)
    -> wirescale-control updates in-memory service endpoint set

cluster-1 (importing):
  wirescale-control refreshes endpoints (every TTL interval, default 30s)
    -> remote control returns updated endpoint list (unhealthy pod excluded)
    -> local control pushes updated list to subscribed agents
    -> agents reprogram LB map
    -> total propagation delay: <= 1 TTL interval (30s default)
```

**Fast-path health detection:** The local agent MAY detect unresponsive
remote backends via transport-layer signals (TCP RST, ICMP unreachable,
WireGuard handshake timeout). On such detection, the agent SHOULD
immediately remove the backend from its local LB map and notify
wirescale-control to trigger an out-of-band endpoint refresh.

**Circuit breaking:** When all backends for an imported service are
unhealthy, the agent MUST return ICMP destination unreachable for new
connections (rather than black-holing traffic). If `failover` topology mode
is configured, the agent MUST attempt resolution from the next-priority
cluster before declaring the service down.

### 10.8 Interaction with Cilium

When Cilium is the intra-cluster CNI, cross-cluster services integrate
with Cilium's service handling via standard Kubernetes primitives.

**Service and EndpointSlice injection:**

`wirescale-control` creates and manages standard Kubernetes Service and
EndpointSlice objects for each `WirescaleServiceImport`. Cilium observes
these through its normal Kubernetes API watches and programs them into
its eBPF `lb4_services_v2` / `lb6_services_v2` maps. From Cilium's
perspective, cross-cluster service backends are indistinguishable from
local backends.

```
wirescale-control creates:
  Service:        backend/api-server-cluster2  (ClusterIP: 3fff:1234:0001:ffff::a02)
  EndpointSlice:  backend/api-server-cluster2-ws-xxxx
    endpoints:
      - addresses: ["3fff:1234:0002:000a::5"]
        conditions: {ready: true}
        targetRef: null     # no local pod -- external endpoint
        zone: "us-east-2a"
      - addresses: ["3fff:1234:0002:0014::3"]
        conditions: {ready: true}

Cilium sees the Service + EndpointSlice:
  -> programs eBPF LB maps
  -> applies CiliumNetworkPolicy if any match the service
  -> Hubble observes flows to the service normally
```

**Encryption boundary:** Cilium handles intra-cluster WireGuard. When a
backend IP falls outside the local cluster's prefix (e.g.,
`3fff:1234:0002::/48` is not in cluster-1's `3fff:1234:0001::/48`), the packet
matches a Wirescale aggregate route and exits via the Wirescale cross-cluster
WireGuard interface (`wg0`). Cilium's `cilium_wg0` does not handle
cross-cluster peers. The boundary is clean: Cilium encrypts intra-cluster,
Wirescale encrypts cross-cluster.

**Policy enforcement:** `CiliumNetworkPolicy` rules that reference the
imported service's VIP or label selectors work normally. For identity-aware
cross-cluster policy, the Wirescale controller annotates the EndpointSlice
with a `wirescale.io/source-cluster` label, enabling policies such as:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-from-remote-api
  namespace: frontend
spec:
  endpointSelector:
    matchLabels:
      app: web
  egress:
    - toServices:
        - k8sService:
            serviceName: api-server-cluster2
            namespace: backend
      toPorts:
        - ports:
            - port: "9090"
              protocol: TCP
```

**Standalone Wirescale (no Cilium):** When Wirescale is the only CNI, the
agent programs cross-cluster service backends directly into eBPF LB maps
or IPVS. The same `WirescaleServiceImport` CRD drives both modes; only
the datapath backend differs.

### 10.9 Comparison with Alternatives

| Property | Wirescale Cross-Cluster Services | Cilium ClusterMesh Services | KEP-1645 MCS API |
|----------|----------------------------------|---------------------------|-------------------|
| State model | On-demand, O(active_imports) per node | Full sync, O(all_services_all_clusters) | Implementation-dependent |
| Service discovery | Pull-based via control hierarchy | Push-based via etcd sync | API-defined, impl varies |
| VIP allocation | Local, global, or anycast | Shared global (annotation) | Not specified |
| Load balancing | Topology-aware, weighted, failover | Round-robin across merged backends | Not specified |
| Health checking | Delegated to exporting cluster, TTL refresh | Merged EndpointSlice sync | Not specified |
| First-flow latency | ~30-65ms (endpoint resolve + WG peer) | 0ms (pre-synced) | Implementation-dependent |
| Scale limit | O(clusters) directory + O(active_imports) per node | O(clusters x services) full sync | Implementation-dependent |
| Cilium compatibility | Native (Service + EndpointSlice) | Native | Requires MCS controller |
| DNS | Standard k8s DNS + optional ws.* zone | clusterset.local zone | svcname.ns.svc.clusterset.local |

---

## 11. Host-Network Pods

Pods running with `hostNetwork: true` bypass the CNI entirely -- no veth
pair, no per-pod eBPF attachment point, no CLAT translation layer. This
section specifies how Wirescale handles them.

### Identity Model

A host-network pod shares the node's IP addresses, so its network
identity is indistinguishable from the node's identity at L3/L4:

- A host-network pod MUST inherit the node's Wirescale identity (the
  WireGuard public key and node certificate). It MUST NOT receive a
  separate pod-level identity.
- When wirescale-control resolves the source identity for traffic from
  a host-network pod, it MUST return the node identity. The agent MUST
  tag such traffic with node-level labels (e.g., `node=worker-07`,
  `role=infra`) rather than pod-level labels.
- If multiple host-network pods bind distinct ports, policy rules MAY
  use L4 port matching to distinguish them. Operators SHOULD NOT rely
  on port-based identity for security-critical decisions.

### WireGuard Data Path

Traffic from host-network pods originates in the host network namespace,
where `wg0` already resides. The data path is simpler than for regular
pods:

```
Host-network pod sends to fd00:1234:0002:0001::7 (remote pod):
  |  Packet originates in host netns (no veth traversal)
  v
Host routing table: fd00:1234:0002:0001::/64 dev wg0 -> WireGuard encrypt
  v
Physical NIC (eth0): encrypted UDP to remote node
```

- Outbound traffic MUST traverse `wg0` for remote destinations,
  following the same routing rules as host-originated traffic. No
  special forwarding configuration is required.
- Inbound traffic arrives through `wg0` (from remote mesh peers) and
  is delivered to the host stack directly.

### CLAT: Not Applicable

Host-network pods use the host's full network stack, including any IPv4
addresses on the node's physical interfaces. CLAT translation (mapping
per-pod `100.64.x.x` to ULA `fd00:1234:CCCC:N::P`) does not apply:

- The agent MUST NOT install CLAT rules for host-network pods.
- Host-network pods needing IPv4-only external services MUST use the
  node's NAT64 path (`64:ff9b::/96`) or native IPv4 connectivity.

### Policy Enforcement

Regular pods have eBPF programs attached to their veth interfaces.
Host-network pods have no veth, so enforcement MUST use a different
attachment point.

**Standalone Wirescale (no Cilium):**

- The agent MUST enforce policy using nftables rules in the
  `inet wirescale_host` table, matching on the node's IP and L4 ports.
- Rules MUST be programmed at pod admission time and removed at
  teardown. Nftables is preferred over eBPF on `eth0` because the
  physical interface may carry TC programs from other subsystems.

**With Cilium CNI:**

- Cilium's host firewall attaches TC eBPF to `eth0` and enforces
  `CiliumClusterwideNetworkPolicy` for host-level traffic. Wirescale
  SHOULD defer host-network pod L3/L4 policy to Cilium's host firewall
  when detected. The agent MUST NOT install conflicting nftables rules.
- Wirescale MUST still enforce WireGuard encryption: inter-node traffic
  from host-network pods MUST traverse `wg0` regardless of whether
  Cilium handles L3/L4 filtering.

### Operator Guidance

| Concern | Regular Pod | Host-Network Pod |
|---------|-------------|------------------|
| Identity | Pod IP + SA + labels | Node IP + node labels |
| eBPF attachment | veth (TC hook) | N/A (no veth) |
| L3/L4 policy | Per-pod eBPF maps | nftables or Cilium host firewall |
| CLAT | Per-pod `100.64.x.x` | Not applicable |
| WireGuard path | veth -> host route -> wg0 | host route -> wg0 (direct) |
| Encryption | Always (inter-node) | Always (inter-node) |

Operators SHOULD minimize the use of `hostNetwork: true` pods. Each
host-network pod widens the node's attack surface because it shares the
node's identity and network namespace. Where possible, use regular pods
with explicit `hostPort` mappings instead.

---

## 12. Security Model

### Encryption

- **Inter-node pod traffic:** WireGuard (ChaCha20-Poly1305, Curve25519, BLAKE2s)
- **Intra-node pod traffic:** Unencrypted (kernel namespace isolation is sufficient)
- **Agent-to-control:** gRPC over mTLS (kubelet certs or projected SA tokens)
- **Control-to-control (cross-cluster):** Mutual TLS with CA certificates
  validated by the global directory
- **Control-to-directory:** gRPC over mTLS (cluster CA certificates)
- **Key material:** Private keys MUST never leave node memory. Public keys are
  registered with control and written to the node's own CRD.

### Identity and Authentication

**Intra-cluster:** Nodes authenticate to the mesh via wirescale-control:
1. Agent presents kubelet client certificate or projected ServiceAccount token
2. Control validates identity against the Kubernetes API
3. Control issues short-lived peer authorization tokens
4. Peer authorization tokens bind a specific node pair and expire after TTL

**Cross-cluster:** Cluster controllers authenticate to each other via:
1. Controller presents its cluster CA certificate to the remote controller
2. Remote controller validates the CA against the global directory's trusted
   CA list
3. Cross-cluster peer authorization tokens bind a specific cluster pair and
   node pair, with bounded TTL

**External peers:** Authentication is bootstrapped via:
1. Pre-shared auth token (one-time registration)
2. Admin approves the `WirescaleExternalPeer` CRD
3. External peer connects to wirescale-control with the approved credentials
4. Subsequent peer discovery uses the same control-mediated flow

### Network Policy

Wirescale enforces policies at two levels:

**Level 1: WireGuard AllowedIPs (L3)**
Each peer's WireGuard config only permits traffic from/to the peer's
allocated pod CIDRs. Traffic from unknown sources is silently dropped by
WireGuard.

**Level 2: eBPF/nftables per-pod policy (L3/L4)**
The agent programs per-pod firewall rules based on policies pushed from
wirescale-control. Policy rules are scoped to local pods only -- each
node receives the minimal set of rules needed for enforcement. See
[SECURITY.md](SECURITY.md) for the full policy language and enforcement
architecture.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: allow-frontend-to-api
spec:
  # Source: pods with label app=frontend
  from:
    - podSelector:
        matchLabels:
          app: frontend
  # Destination: pods with label app=api
  to:
    - podSelector:
        matchLabels:
          app: api
      ports:
        - protocol: TCP
          port: 8080
  # Also allow traffic from external peer "office-server"
  fromExternal:
    - peerName: office-server
  # Cross-cluster policy: allow from pods in remote cluster
  fromClusters:
    - clusterName: "cluster-2"
      podSelector:
        matchLabels:
          app: frontend
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping on inter-node traffic | WireGuard encryption (always on for inter-node traffic) |
| Unauthorized node joining mesh | Must authenticate to wirescale-control via mTLS; control validates against Kubernetes API |
| Compromised node | Revoke by deleting WirescaleNode CRD; control rejects all peer requests for the revoked node; active peers on other nodes are torn down |
| Control plane compromise | Attacker can disrupt peer discovery but cannot decrypt data plane traffic (no private keys in control). Existing peers persist. |
| Key compromise on a single node | Rotate: agent generates new key, updates CRD and control. Control pushes key-update to active peers. Old key immediately invalid. |
| Cross-cluster impersonation | Controllers use mutual TLS with CA certificates validated by the global directory; peer authorization tokens are cluster-scoped and node-scoped |
| DoS on wirescale-control | Existing peers and cached identities persist. New peer establishment degrades gracefully. Control is HA (3+ replicas). |
| DoS on wirescale-directory | Existing cross-cluster peers persist. Cached cluster info on controllers persists (TTL-based). Only new cross-cluster peer establishment to previously-unknown clusters is affected. |
| Global directory compromise | Attacker can inject false cluster registrations. Mitigation: directory entries require mutual authentication; controllers SHOULD pin known cluster CA certificates. |

---

## 13. Custom Resource Definitions

### WirescaleMesh (cluster-scoped, singleton)

Cluster-wide mesh configuration.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
metadata:
  name: default
spec:
  # Cluster identity
  clusterID: "cluster-1"
  # Cluster's allocated prefix (from global directory or manual config)
  clusterPrefix: "3fff:1234:0001::/48"
  # IPv4 pod CIDR (CGNAT range, translated via CLAT)
  podCIDRv4: "100.64.0.0/10"
  # Service CIDRs
  serviceCIDRv6: "3fff:1234:0001:ffff::/108"
  serviceCIDRv4: "100.64.255.0/24"  # optional
  # NAT64 prefix
  nat64Prefix: "64:ff9b::/96"
  # WireGuard listen port
  listenPort: 51820
  # DNS domain for mesh names
  dnsDomain: "ws.cluster.internal"
  # MTU override (0 = auto-detect)
  mtu: 0
  # Control plane configuration
  controlPlane:
    # Address of wirescale-control gRPC service
    endpoint: "wirescale-control.wirescale-system.svc:9443"
    # TLS mode for agent-to-control connections
    tlsMode: mtls          # "mtls" | "token"
    # Control plane replicas (informational)
    replicas: 3
  # Global directory configuration
  directory:
    # Address of wirescale-directory gRPC service
    endpoint: "directory.wirescale-global.example.com:9445"
    # CA certificate for directory TLS
    caCertRef:
      name: directory-ca
      key: ca.crt
  # Signaling gateway nodes
  gateways:
    # Nodes designated as signaling gateways (label selector)
    nodeSelector:
      matchLabels:
        wirescale.io/gateway: "true"
    # Number of desired gateway nodes
    replicas: 3
  # Peer lifecycle policy
  peerPolicy:
    # Seconds of idle time before a WireGuard peer is garbage-collected
    idleTimeout: 300
    # Maximum queued packets during peer establishment
    establishQueueSize: 64
    # Peer authorization token TTL (seconds)
    peerTokenTTL: 300
  # Identity cache settings
  identityCache:
    # TTL for cached identity entries on each agent (seconds)
    ttl: 60
    # Maximum number of cached identity entries per agent
    maxEntries: 10000
status:
  nodeCount: 12
  healthyNodes: 12
  controlPlaneReady: true
  directoryConnected: true
  allocatedv6Blocks: 12
  allocatedv4Blocks: 12
  registeredClusters: 5      # known remote clusters
  gatewayNodes: 3
```

### WirescaleNode (cluster-scoped, one per node)

Per-node mesh state. Created by the agent, enriched by wirescale-control.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleNode
metadata:
  name: worker-3
  ownerReferences:
    - apiVersion: v1
      kind: Node
      name: worker-3
spec:
  # Set by agent at boot
  publicKey: "YWJjZGVm..."
  endpoint: "[3fff:1234:0001:ff01::3]:51820"
  # Set by control (IPAM)
  podCIDRv6: "3fff:1234:0001:0003::/64"
  podCIDRv4: "100.64.3.0/24"
  # Optional: subnet router / exit node
  advertisedRoutes: []
  exitNode: false
  # Optional: designate as signaling gateway
  gateway: false
status:
  # Updated by agent
  ready: true
  controlPlaneConnected: true
  activePeers: 23
  crossClusterPeers: 2       # active peers to remote clusters
  lastHandshake: "2026-03-02T10:00:00Z"
  wireguardInterface: "wg0"
  natType: "full-cone"        # Detected NAT type
  bytesTransferred:
    tx: 1073741824
    rx: 2147483648
```

### WirescaleExternalPeer (cluster-scoped)

For non-Kubernetes nodes joining the mesh.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleExternalPeer
metadata:
  name: dev-laptop
spec:
  publicKey: "eHl6MTIz..."
  endpoint: "[3fff:1234:00ff:ff01::1]:51820"
  allowedIPs:
    - "3fff:1234:00ff:0001::1/128"
    - "100.64.200.1/32"
  advertisedRoutes: []
  # Pre-auth key for initial registration (one-time)
  authKeyRef:
    name: external-peer-keys
    key: dev-laptop
status:
  approved: true
  lastSeen: "2026-03-02T09:55:00Z"
```

### WirescalePolicy (namespace-scoped)

Extended network policy with mesh-aware identity.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: backend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - externalPeer:
            name: office-server
        - clusterPeer:
            clusterName: "cluster-2"
            podSelector:
              matchLabels:
                app: frontend
      ports:
        - protocol: TCP
          port: 443
  egress:
    - to:
        - ipBlock:
            cidr: "0.0.0.0/0"    # Allow all external IPv4
        - ipBlock:
            cidr: "::/0"         # Allow all external IPv6
      ports:
        - protocol: TCP
          port: 443
```

### WirescaleCluster (directory-scoped)

Stored in the global directory, represents a registered cluster.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleCluster
metadata:
  name: cluster-1
spec:
  clusterID: "cluster-1"
  prefix: "3fff:1234:0001::/48"
  controllerEndpoint: "control.cluster-1.example.com:9443"
  gateways:
    - endpoint: "[3fff:1234:0001:ff01::1]:51820"
    - endpoint: "[3fff:1234:0001:ff01::2]:51820"
    - endpoint: "[3fff:1234:0001:ff01::3]:51820"
  caCert: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  metadata:
    region: "us-west-2"
    provider: "aws"
status:
  registered: "2026-01-15T00:00:00Z"
  lastHeartbeat: "2026-03-02T10:00:00Z"
  healthy: true
  nodeCount: 5000
```

---

## 14. Packet Flow Walkthrough

### Case 1: Pod-to-Pod, Same Node

```
Pod A (3fff:1234:0001:0001::5) -> Pod B (3fff:1234:0001:0001::7)
  eth0 -> veth -> host bridge/routing -> veth -> eth0
  (no WireGuard, no translation, direct kernel path)
```

### Case 2: Pod-to-Pod, Different Nodes, Same Cluster (IPv6, Warm Path)

When the WireGuard peer is already established (the common case after first
contact):

```
Pod A on node-1 (3fff:1234:0001:0001::5) -> Pod B on node-2 (3fff:1234:0001:0002::7)

Pod A: eth0 -> veth -> host
Host node-1: route 3fff:1234:0001:0002::/64 dev wg0
  -> wg0: encrypt with node-2's public key
  -> UDP to [3fff:1234:0001:ff01::2]:51820

Network: IPv6 UDP packet transit

Host node-2: UDP :51820 -> wg0 decrypt
  -> verify src 3fff:1234:0001:0001::5 in AllowedIPs for node-1 peer
  -> route 3fff:1234:0001:0002::7 -> veth -> Pod B eth0
```

### Case 3: Pod-to-Pod, Different Nodes, Same Cluster (IPv6, Cold Path)

When no WireGuard peer exists for the destination node (first contact or
after idle GC):

```
Pod A on node-1 (3fff:1234:0001:0001::5) -> Pod B on node-2 (3fff:1234:0001:0002::7)

Pod A: eth0 -> veth -> host
Host node-1: route 3fff:1234:0001:0002::/64 -> no WireGuard peer!
  1. eBPF queues packet (up to 64 packets buffered)
  2. Agent sends PeerRequest to wirescale-control:
       "I need peer info for the node owning 3fff:1234:0001:0002::/64"
  3. Control authenticates node-1, checks authorization
  4. Control returns: {pubkey, endpoint=[3fff:1234:0001:ff01::2]:51820, allowedIPs, TTL=300s}
  5. Agent configures WireGuard peer:
       wg set wg0 peer <pubkey> \
         allowed-ips 3fff:1234:0001:0002::/64,100.64.2.0/24 \
         endpoint [3fff:1234:0001:ff01::2]:51820
  6. Agent programs route: 3fff:1234:0001:0002::/64 dev wg0
  7. Queued packets drain through new peer
  8. Total cold-path delay: ~15-30ms (acceptable for TCP SYN)

Subsequent packets: warm path (Case 2), zero additional overhead.

After 300s idle: agent removes peer. Next packet re-triggers this flow.
```

### Case 4: Pod-to-Pod, Different Nodes (IPv4 via CLAT)

```
Pod A on node-1: app connects to 100.64.2.7 (Pod B's IPv4)

Pod A: IPv4 packet -> clat0 TUN
  -> CLAT xlat: src 3fff:1234:0001:0001::5, dst 3fff:1234:0001:0002::7
  -> eth0 -> veth -> host
Host node-1: route 3fff:1234:0001:0002::/64 dev wg0
  -> (on-demand peer setup if needed, see Case 3)
  -> wg0: encrypt, send to node-2

Host node-2: wg0 decrypt -> route to Pod B veth
Pod B: eth0 receives IPv6 -> clat0 TUN xlat -> app sees IPv4
```

### Case 5: Pod to External IPv4 (via DNS64 + NAT64)

```
Pod A: getaddrinfo("ipv4only.example.com")
  -> CoreDNS -> upstream returns A 93.184.216.34
  -> dns64 synthesizes AAAA 64:ff9b::5db8:d822
  -> Pod connects to 64:ff9b::5db8:d822

Pod A: eth0 -> veth -> host
Host node-1: route 64:ff9b::/96 -> nat64 interface
  -> eBPF xlat: IPv6 -> IPv4
  -> src: MASQUERADE with node's IPv4
  -> dst: 93.184.216.34
  -> physical NIC -> internet

Return: IPv4 -> nat64 eBPF xlat -> IPv6 -> route to Pod A
```

### Case 6: Cross-Cluster Pod-to-Pod (Cold Path)

```
Pod A in cluster-1 (3fff:1234:0001:0001::5) ->
  Pod B in cluster-2 (3fff:1234:0002:0002::7)

Pod A: eth0 -> veth -> host
Host node-A-1: no specific peer for 3fff:1234:0002:0002::/64
  route 3fff:1234:0002::/48 (aggregate) -> signaling gateway

  1. Agent intercepts aggregate-route packet (cache miss)
  2. Agent -> wirescale-control (cluster-1):
       "resolve 3fff:1234:0002:0002::/64"
  3. Control (cluster-1) -> directory (cache miss):
       "where is cluster 2?"
  4. Directory -> control:
       {cluster_2_controller: "control.c2.example.com:9443",
        cluster_2_CA: "..."}
  5. Control (cluster-1) -> control (cluster-2) via mTLS:
       "resolve host 0002, cluster-1 cert attached"
  6. Control (cluster-2) authenticates, returns:
       {node_B_endpoint: [3fff:1234:0002:ff01::2]:51820, pubkey: "...", allowedIPs: ...}
  7. Control (cluster-1) -> agent: peer info for node-B-2
  8. Agent establishes direct WireGuard tunnel to node-B-2
  9. Agent installs specific route:
       3fff:1234:0002:0002::/64 dev wg0 peer=node-B-2
       (overrides aggregate 3fff:1234:0002::/48 for this /64)
  10. Queued packets drain through direct tunnel
  11. Total cold-path delay: ~30-65ms

Subsequent packets: direct WireGuard tunnel (warm path).
Gateway is NOT in the data path.
```

### Case 7: Cross-Cluster Pod-to-Pod (Warm Path)

```
Pod A in cluster-1 -> Pod B in cluster-2
  (direct WireGuard tunnel already established from Case 6)

Pod A: eth0 -> veth -> host
Host node-A-1: route 3fff:1234:0002:0002::/64 dev wg0 peer=node-B-2
  -> wg0: encrypt with node-B-2's public key
  -> UDP to [3fff:1234:0002:ff01::2]:51820

Network: IPv6 UDP packet transit (inter-cluster)

Host node-B-2: wg0 decrypt -> route to Pod B

(identical to intra-cluster warm path, zero gateway overhead)
```

### Case 8: External Peer to Pod

```
Dev laptop (3fff:1234:00ff:0001::1) -> Pod B (3fff:1234:0001:0002::7)

Laptop: wirescale-join agent
  -> queries wirescale-control for peer info to reach 3fff:1234:0001:0002::/64
  -> control authenticates laptop (approved WirescaleExternalPeer)
  -> returns peer info for node-2
  -> wg0: encrypt with node-2's public key
  -> UDP to [3fff:1234:0001:ff01::2]:51820

Node-2: wg0 decrypt -> verify AllowedIPs -> route to Pod B
```

---

## 15. Comparison with Existing Solutions

| Feature | Wirescale | Tailscale K8s Operator | Cilium WireGuard | Calico WireGuard | Kilo |
|---------|-----------|----------------------|------------------|------------------|------|
| Primary goal | Full CNI + IPv6-only + hyperscale | Expose/connect services to tailnet | Transparent encryption for existing CNI | Transparent encryption for Calico | Multi-site WG overlay |
| CNI plugin | Yes (standalone) | No (uses existing) | No (is Cilium) | No (is Calico) | Optional |
| IPv6-only cluster support | First-class target | N/A | Version/mode dependent | Version/mode dependent | Topology dependent |
| NAT64/DNS64 | Built-in | No | No | No | No |
| CLAT per-pod | Yes | No | No | No | No |
| Mesh topology | On-demand peering | Service-level proxies | Full mesh (node-to-node) | Full mesh (node-to-node) | Zone-based leaders |
| Scale model | O(active_peers) per node | N/A | O(N) peers per node | O(N) peers per node | O(zones) |
| Cross-cluster | Three-tier hierarchy, on-demand | Tailscale mesh | ClusterMesh (full sync) | Federation | Manual peering |
| Cross-cluster state | O(clusters) aggregate routes | N/A | O(all_nodes) across clusters | Full sync | Manual config |
| External peers | Yes (control-mediated) | Yes (tailnet) | No | No | Yes (Peer CRD) |
| Control plane | Three-tier (directory + control + agent) | Tailscale SaaS | Cilium agent | Calico Felix | Kubernetes API |
| Identity model | Control-issued tokens + WG keys | Tailscale identity | CiliumNode annotation | Node annotation | Node annotation |
| Data-path gateways | No (signaling-only) | N/A | Yes (ClusterMesh) | Yes | Yes (zone leaders) |

### Why Not Just Use Tailscale K8s Operator?

Tailscale's operator is designed to connect Kubernetes services to a
Tailscale tailnet. It is not a CNI -- it creates proxy pods that bridge
between the cluster network and the tailnet. It does not encrypt pod-to-pod
traffic within the cluster, does not handle IPv6-only clusters, and requires
a Tailscale account (or headscale) for the coordination server.

Wirescale is a ground-up CNI that uses the same principles (WireGuard mesh,
key coordination, identity-aware routing) but applies them at the cluster
network fabric level, with IPv6-only as the primary design target and
hyperscale as a first-class architectural constraint.

### Why Not ClusterMesh (Cilium)?

Cilium's ClusterMesh replicates etcd state across clusters, creating
O(all_nodes) state on every node in every cluster. This works for small
federations (2-5 clusters, hundreds of nodes each) but does not scale to
hundreds of clusters with tens of thousands of nodes each. Wirescale's
three-tier hierarchy keeps cross-cluster state at O(clusters) per node and
resolves individual nodes on demand.

---

## 16. Implementation Phases

### Phase 1: Control Plane and Core Mesh

- [ ] CRD definitions (WirescaleMesh, WirescaleNode, WirescalePolicy)
- [ ] wirescale-control: gRPC service with mTLS authentication
- [ ] wirescale-control: peer broker (on-demand peer info responses)
- [ ] wirescale-control: IPAM allocation (node /64 and /24 assignment)
- [ ] CNI plugin binary (veth pair, IPv6 address assignment)
- [ ] Agent DaemonSet (WireGuard interface, key generation)
- [ ] Agent: on-demand peer establishment via control
- [ ] Agent: peer idle GC (configurable timeout)
- [ ] Basic health checking and status reporting

**Result:** Encrypted IPv6 pod-to-pod mesh with on-demand peering and central
control. No full-mesh scaling limitation.

### Phase 2: Identity and IPv4 Compatibility

- [ ] wirescale-control: identity service (pod IP -> identity resolution)
- [ ] Agent: identity cache (TTL-based, query on miss)
- [ ] CLAT engine in agent (per-pod IPv4 via TUN)
- [ ] NAT64 engine in agent (eBPF-based translation)
- [ ] CoreDNS dns64 plugin configuration
- [ ] CNI plugin: dual-address assignment (IPv6 + IPv4)
- [ ] IPv4 service VIP support

**Result:** Pods can use IPv4 transparently on an IPv6-only underlay.
Identity resolution enables policy enforcement by workload identity.

### Phase 3: Policy and Security

- [ ] wirescale-control: policy service (per-node policy compilation and push)
- [ ] Agent: gRPC policy stream subscription
- [ ] Kubernetes NetworkPolicy enforcement (eBPF or nftables)
- [ ] WirescalePolicy CRD and controller
- [ ] Key rotation support (control-mediated push to active peers)
- [ ] Audit logging (see [SECURITY.md](SECURITY.md))

**Result:** Zero-trust network with granular policy control. Each node
enforces only the policies relevant to its local pods.

### Phase 4: External Connectivity

- [ ] WirescaleExternalPeer CRD and control integration
- [ ] `wirescale-join` CLI for external peers (authenticates to control)
- [ ] Subnet router mode (advertised routes via control)
- [ ] Exit node mode
- [ ] MagicDNS for mesh name resolution
- [ ] Cross-cluster DNS resolution

**Result:** Full Tailscale-like mesh spanning cluster and external nodes,
with all peers mediated through wirescale-control.

### Phase 5: Three-Tier Hierarchy and Hyperscale

- [ ] wirescale-directory: cluster registry with Raft consensus
- [ ] wirescale-directory: cross-cluster CA management
- [ ] wirescale-directory: prefix allocation and validation
- [ ] wirescale-control: directory registration and heartbeat
- [ ] wirescale-control: cross-cluster proxy (local control -> directory ->
      remote control -> response)
- [ ] Agent: aggregate route programming for remote clusters
- [ ] Agent: cross-cluster peer establishment via signaling gateway
- [ ] Signaling gateway nodes (signal-only, not data path)
- [ ] WirescaleCluster CRD (directory-scoped)
- [ ] Cross-cluster WirescalePolicy support (clusterPeer selectors)

**Result:** Federated multi-cluster mesh with O(clusters) state per node.
Hundreds of clusters, hundreds of thousands of total hosts.

### Phase 6: Performance and Hardening

- [ ] NAT traversal / DERP-like relay for nodes behind NAT
- [ ] Performance optimization (eBPF fast path, batch processing,
      see [PERFORMANCE.md](PERFORMANCE.md))
- [ ] Metrics and observability (Prometheus, WireGuard handshake stats,
      control plane latency histograms, directory health)
- [ ] Load testing: 10K+ nodes per cluster, 100+ clusters
- [ ] Chaos testing: directory failure, control failure, gateway failure,
      network partition between clusters

**Result:** Production-grade network operator for hyperscale deployments
with federated cross-cluster connectivity and proven resilience.

---

## Appendix A: Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go |
| Operator framework | kubebuilder / controller-runtime |
| WireGuard | wireguard-go (userspace) or kernel module |
| CNI | containernetworking/cni Go library |
| eBPF | cilium/ebpf Go library |
| NAT64/CLAT | eBPF TC programs + TUN devices |
| DNS | CoreDNS dns64 plugin + custom in-mesh resolver |
| Networking | netlink (vishvananda/netlink), nftables |
| Control plane RPC | gRPC with mTLS (grpc-go) |
| Control plane HA | Leader election (controller-runtime) + active-active for reads |
| Global directory | Raft consensus (etcd, hashicorp/raft, or similar) |
| Cross-cluster auth | x509 certificates, mutual TLS |

## Appendix B: Port and Protocol Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 51820 | UDP | Node-to-node | WireGuard mesh traffic (intra- and cross-cluster) |
| 9443 | TCP | Agent-to-control | gRPC (peer broker, identity, policy) |
| 9444 | TCP | Control-to-control | gRPC cross-cluster proxy (peer resolution) |
| 9445 | TCP | Control-to-directory | gRPC (cluster registration, lookup) |
| 53 | UDP/TCP | Pod-to-CoreDNS | DNS resolution |
| 443 / 6443 | TCP | Control-to-API | Kubernetes API (CRD operations) |

## Appendix C: Kernel Requirements

For the target data plane in this document:

- Nodes MUST run Linux >= 5.6 (native WireGuard module) or provide a validated
  fallback path.
- Nodes MUST have IPv6 enabled (`net.ipv6.conf.all.disable_ipv6 = 0`).
- Nodes MUST have IP forwarding enabled (`net.ipv6.conf.all.forwarding = 1`).
- Nodes SHOULD provide eBPF support (for NAT64 and policy enforcement).
- Nodes MUST provide TUN/TAP support (for CLAT).

## Appendix D: Scaling Characteristics

| Metric | Single Cluster (10K nodes) | Federation (100 clusters x 10K nodes) |
|--------|---------------------------|---------------------------------------|
| Routes per node | ~50 active /64 + default | ~50 active /64 + ~100 aggregate /48 |
| WireGuard peers per node | ~50 active | ~50 active (including cross-cluster) |
| Identity cache per node | ~500 entries (TTL 60s) | ~500 entries (TTL 60s) |
| Directory state (total) | N/A (single cluster) | ~100 cluster entries |
| Controller state (per cluster) | ~10K nodes, ~1M pods | ~10K nodes, ~1M pods |
| Cross-cluster resolution latency | N/A | ~30-65ms (cold), 0ms (warm) |
| Pod churn impact on routes | Zero (pods do not affect routes) | Zero |
| Host churn impact on routes | O(1) within cluster | O(1) within cluster |
