# Wirescale: Kubernetes Network Operator Architecture

> A WireGuard-based network operator for Kubernetes that provides seamless
> IPv4 and IPv6 connectivity in IPv6-only clusters, inspired by Tailscale's
> control/data plane separation and mesh networking model.
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
3. [High-Level Architecture](#3-high-level-architecture)
4. [Component Deep Dives](#4-component-deep-dives)
5. [Address Architecture](#5-address-architecture)
6. [Data Plane: WireGuard Mesh](#6-data-plane-wireguard-mesh)
7. [IPv4 in an IPv6-Only World](#7-ipv4-in-an-ipv6-only-world)
8. [DNS Architecture](#8-dns-architecture)
9. [Cross-Cluster and External Connectivity](#9-cross-cluster-and-external-connectivity)
10. [Security Model](#10-security-model)
11. [Custom Resource Definitions](#11-custom-resource-definitions)
12. [Packet Flow Walkthrough](#12-packet-flow-walkthrough)
13. [Comparison with Existing Solutions](#13-comparison-with-existing-solutions)
14. [Implementation Phases](#14-implementation-phases)

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

### What We Want

A conformant Wirescale deployment SHOULD satisfy the following goals for pods
in an IPv6-only Kubernetes cluster:

1. **Native IPv6 connectivity** -- the data plane MUST support first-class IPv6
   pod connectivity without translation in native paths.
2. **Transparent IPv4 connectivity** -- the platform MUST provide an IPv4
   compatibility path so pods can use IPv4 socket semantics over an IPv6
   underlay.
3. **Encrypted pod-to-pod mesh** -- in full-mesh mode, inter-node traffic MUST
   be encrypted with WireGuard; location-aware mode MAY use native intra-zone
   routing by policy.
4. **Control/data simplicity** -- the architecture SHOULD keep control-plane
   distribution (keys/routes/policy) separate from data-plane forwarding.
5. **External mesh capability** -- deployments MAY extend the mesh to external
   services (other clusters, bare-metal, cloud VMs).

---

## 2. Design Principles

| Principle | Rationale |
|-----------|-----------|
| **IPv6-native, IPv4-compatible** | The underlay is IPv6-only. IPv4 is provided as a service via translation, not as infrastructure. |
| **Control/data plane separation** | Inspired by Tailscale: the control plane distributes keys and policy; the data plane (WireGuard) handles encryption and routing. Control plane failure does not break existing connections. |
| **Key-per-node, not key-per-pod** | Matches the WireGuard model and avoids O(n^2) key distribution. Pods on the same node share a tunnel. Same-node traffic is unencrypted (already isolated by kernel namespaces). |
| **CRD-driven configuration** | All mesh state (peers, routes, policies) is expressed as Kubernetes Custom Resources. The cluster API server IS the coordination database. |
| **CNI-complementary, not CNI-replacing** | Wirescale can operate as a standalone CNI or as an overlay on top of an existing CNI (like Flannel or kubenet) for the intra-node path. |
| **No additional external dependencies** | No extra coordination system beyond the Kubernetes control plane. The Kubernetes API is the source of truth for Wirescale state. |
| **Graceful degradation** | If the controller is down, existing mesh connections SHOULD persist (cached WireGuard config). New nodes MAY wait until the controller recovers. |

---

## 3. High-Level Architecture

```
+------------------------------------------------------------------+
|                        CONTROL PLANE                              |
|                                                                   |
|  +---------------------------+  +-----------------------------+   |
|  | wirescale-controller      |  | Kubernetes API Server       |   |
|  | (Deployment, 1-3 replicas)|  |                             |   |
|  |                           |  |  WirescaleNode CRD          |   |
|  | - IPAM allocation         |  |  WirescaleMesh CRD          |   |
|  | - Mesh topology mgmt      |  |  WirescalePolicy CRD        |   |
|  | - Key distribution via CRD|  |  WirescaleExternalPeer CRD   |   |
|  | - Policy compilation      |  |                             |   |
|  | - Health monitoring        |  |                             |   |
|  +---------------------------+  +-----------------------------+   |
+------------------------------------------------------------------+
                              |
              CRD watch/update via kube API
                              |
+------------------------------------------------------------------+
|                         DATA PLANE (per node)                     |
|                                                                   |
|  +------------------------------------------------------------+  |
|  | wirescale-agent (DaemonSet)                                 |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+  +-----------+  |  |
|  |  | WireGuard Manager|  | Route Manager    |  | Policy    |  |  |
|  |  | - wg0 interface  |  | - kernel routes  |  | Enforcer  |  |  |
|  |  | - peer config    |  | - ip rules       |  | (eBPF/    |  |  |
|  |  | - key generation |  | - IPAM state     |  |  nftables)|  |  |
|  |  +------------------+  +------------------+  +-----------+  |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | NAT64 Engine     |  | CLAT Engine      |                 |  |
|  |  | (eBPF xlat on    |  | (per-pod IPv4    |                 |  |
|  |  |  nat64 iface)    |  |  address via tun) |                 |  |
|  |  +------------------+  +------------------+                 |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  +------------------------------------------------------------+  |
|  | wirescale-cni (CNI binary, /opt/cni/bin/wirescale)          |  |
|  | - veth pair creation                                        |  |
|  | - IPv6 address assignment (primary)                         |  |
|  | - IPv4 address assignment (CLAT tun)                        |  |
|  | - route injection into pod netns                            |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Component Summary

| Component | Type | Runs On | Purpose |
|-----------|------|---------|---------|
| `wirescale-controller` | Deployment (HA) | Control plane nodes | IPAM, mesh topology, key coordination, policy compilation |
| `wirescale-agent` | DaemonSet | Every node | WireGuard mesh, NAT64/CLAT, route programming, policy enforcement |
| `wirescale-cni` | CNI binary | Every node (invoked by CRI) | Pod network namespace setup |
| CoreDNS `dns64` plugin | ConfigMap patch | CoreDNS pods | Synthesize AAAA records for IPv4-only destinations |

---

## 4. Component Deep Dives

### 4.1 wirescale-controller

The controller runs as a standard Kubernetes Deployment with leader election.
It uses controller-runtime (kubebuilder) and manages several reconciliation
loops:

**Node IPAM Reconciler** -- watches `Node` objects:
- When a node joins, allocates a `/64` IPv6 pod CIDR from the cluster's
  IPv6 pod range and a `/24` IPv4 pod CIDR from an internal CGNAT-like range
- Writes allocations to the corresponding `WirescaleNode` CRD
- Handles node removal and CIDR reclamation

**Mesh Topology Reconciler** -- watches `WirescaleMesh` and `WirescaleNode` CRDs:
- Computes the full mesh topology: which nodes are peers
- Supports location-aware topology (like Kilo): nodes in the same zone use
  direct routing; cross-zone traffic goes through WireGuard
- Writes computed peer lists to each `WirescaleNode` status

**Policy Reconciler** -- watches `WirescalePolicy` and `NetworkPolicy` objects:
- Compiles policy rules into per-node filter sets
- Writes compiled rules to `ConfigMap` objects consumed by the agents
- Supports both Kubernetes-native `NetworkPolicy` and extended
  `WirescalePolicy` (identity-based, like Tailscale ACLs)

**External Peer Reconciler** -- watches `WirescaleExternalPeer` CRDs:
- Manages peers outside the cluster (bare metal, other clusters, VMs)
- Distributes external peer keys and routes to relevant nodes

### 4.2 wirescale-agent

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
4. Watch all `WirescaleNode` CRDs -- add/remove WireGuard peers as nodes
   join/leave
5. Program kernel routes: remote pod CIDRs -> `wg0`
6. Create `nat64` interface for NAT64 translation
7. Start CLAT engine for per-pod IPv4 address provision

**Reconciliation loop** (continuous):
```
for each WirescaleNode CRD (excluding self):
    if peer not in wg0 config:
        wg set wg0 peer <pubkey> allowed-ips <cidrs> endpoint <ipv6:port>
        ip -6 route add <remote-pod-cidr-v6> dev wg0
        ip route add <remote-pod-cidr-v4> dev wg0

    if peer in wg0 but CRD deleted:
        wg set wg0 peer <pubkey> remove
        delete associated routes

    if peer config changed (key rotation, endpoint change):
        update peer config
```

The agent also periodically verifies actual WireGuard state matches desired
state (drift correction).

### 4.3 wirescale-cni

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

---

## 5. Address Architecture

### IPv6 Addressing (Primary)

```
Cluster pod CIDR:     fd12:3456:7800::/48        (ULA, configurable)
Per-node allocation:  fd12:3456:7800:N::/64      (N = node index)
Pod address:          fd12:3456:7800:N::P/128    (P = pod index within node)
Service CIDR:         fd12:3456:78ff::/108
```

All pod-to-pod, pod-to-service, and pod-to-external communication uses IPv6
natively. The WireGuard mesh endpoints are IPv6 addresses on the physical
network.

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
Pod IPv4: 100.64.N.P  <-->  Pod IPv6: fd12:3456:7800:N::P
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
+------------------+------------------------+---------------------------+
| Purpose          | IPv6                   | IPv4                      |
+------------------+------------------------+---------------------------+
| Pod addressing   | fd00:ws:N::P/128       | 100.64.N.P/32             |
| Service VIPs     | fd00:ws:svc::/108      | 100.64.255.0/24 (opt.)    |
| WireGuard endpt  | <node phys IPv6>:51820 | (none - IPv6 underlay)    |
| External v4 dst  | 64:ff9b::<ipv4>/128    | (translated at egress)    |
| DNS resolver     | fd00:ws::64/128        | 100.100.100.100 (compat)  |
+------------------+------------------------+---------------------------+
```

---

## 6. Data Plane: WireGuard Mesh

### Mesh Topology

**Full mesh (default for small clusters, <100 nodes):**
Every node has a WireGuard peer entry for every other node. N nodes = N-1
peers per node. Key distribution is O(N) via CRDs.

**Location-aware mesh (large clusters or multi-zone):**
Inspired by Kilo's topology model:

```
Zone A (3 nodes)              Zone B (4 nodes)
+-------+-------+-------+    +-------+-------+-------+-------+
| nodeA1| nodeA2| nodeA3|    | nodeB1| nodeB2| nodeB3| nodeB4|
| (ldr) |       |       |    | (ldr) |       |       |       |
+---+---+-------+-------+    +---+---+-------+-------+-------+
    |                             |
    +---- WireGuard tunnel -------+
    (only leaders peer with each other)
```

- Intra-zone: direct routing via existing network fabric (no WireGuard)
- Inter-zone: traffic flows through zone leader's WireGuard tunnel
- Zone leaders are elected per `topology.kubernetes.io/zone` label
- If a leader fails, another node in the zone is promoted

### Key Distribution

```
Node boot:
  1. Generate Curve25519 (X25519) keypair (WireGuard)
  2. Private key: memory-only (never written to disk/CRD)
  3. Public key: written to WirescaleNode CRD

Key rotation:
  1. Agent generates new keypair
  2. Updates WirescaleNode CRD with new public key
  3. All peer agents detect CRD change via watch
  4. Peers update their wg0 config with new key
  5. Brief handshake interruption (~1-2 RTT), then traffic resumes
```

No pre-shared keys by default (simplicity). PSK support available as an
option for post-quantum defense-in-depth.

### WireGuard Configuration per Node

```
[Interface]
ListenPort = 51820
PrivateKey = <generated-at-boot>

# Peer: node-worker-2
[Peer]
PublicKey = <from WirescaleNode CRD>
Endpoint = [3fff::2]:51820
AllowedIPs = fd12:3456:7800:2::/64, 100.64.2.0/24

# Peer: node-worker-3
[Peer]
PublicKey = <from WirescaleNode CRD>
Endpoint = [3fff::3]:51820
AllowedIPs = fd12:3456:7800:3::/64, 100.64.3.0/24
```

The `AllowedIPs` for each peer covers both the IPv6 and IPv4 pod CIDRs of
that node. This means WireGuard's cryptokey routing handles both address
families through the same tunnel.

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

---

## 7. IPv4 in an IPv6-Only World

This is the core innovation: making IPv4 "just work" for pods on an
IPv6-only underlay. Three mechanisms work together:

### 7.1 CLAT (Customer-side Translator) -- Pod-Local IPv4

Each pod gets a `clat0` TUN interface that provides a real IPv4 address.
Applications can bind to IPv4, connect to IPv4 addresses, and use IPv4
socket APIs.

```
Pod network namespace:
  eth0:   fd12:3456:7800:1::5/128    (primary, IPv6)
  clat0:  100.64.1.5/32       (CLAT, IPv4)

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
     src: 100.64.1.5        -> fd12:3456:7800:1::5
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

### 7.2 NAT64 -- Reaching External IPv4 Destinations

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

### 7.3 DNS64 -- Making It Transparent

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

### 7.4 Complete IPv4 Flow (Pod to External IPv4 Host)

```
Pod (100.64.1.5 / fd00:ws:1::5)
  |
  | App: connect("93.184.216.34", 80)
  v
clat0 (CLAT: IPv4 -> IPv6)
  | src: fd00:ws:1::5
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

### 7.5 IPv4 Within the Mesh

Pod-to-pod IPv4 traffic stays within the WireGuard mesh and never hits
NAT64. The routing is:

```
Pod A (100.64.1.5) -> connect to Pod B (100.64.2.7)
  |
  | clat0: translate to IPv6
  | src: fd00:ws:1::5, dst: fd00:ws:2::7
  v
  eth0 -> host routing
  |
  | route: fd00:ws:2::/64 -> wg0
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

---

## 8. DNS Architecture

### In-Mesh DNS (MagicDNS-inspired)

Every pod in the mesh is resolvable by name, like Tailscale's MagicDNS:

```
<pod-name>.<namespace>.ws.cluster.internal          -> fd12:3456:7800:N::P (AAAA)
<pod-name>.<namespace>.ws.cluster.internal          -> 100.64.N.P          (A)
<service-name>.<namespace>.svc.ws.cluster.internal  -> service VIP
```

The wirescale-agent runs a lightweight DNS sidecar that:
1. Watches Pod objects for IP assignments
2. Maintains an in-memory name-to-IP map
3. Serves DNS queries for `*.ws.cluster.internal` domain
4. Forwards all other queries to CoreDNS (which handles `dns64`)

This is push-based, like Tailscale, which reduces stale records. DNS clients
still honor TTL semantics for cached responses.

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
  | returns AAAA: fd00:ws:3::12 and A: 100.64.3.12
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

---

## 9. Cross-Cluster and External Connectivity

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
  endpoint: "[3fff:office::1]:51820"
  allowedIPs:
    - "fd00:ws:ext:1::/64"     # External peer's subnet
    - "100.64.200.0/24"        # External peer's IPv4 range
  # Optional: advertise routes FROM the external peer into the mesh
  advertisedRoutes:
    - "192.168.1.0/24"         # Office LAN (subnet router mode)
```

The controller distributes external peer configs to all relevant nodes.
External peers run a lightweight `wirescale-join` agent that handles
key exchange and route setup without requiring Kubernetes.

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

All mesh nodes learn these routes and can reach the advertised subnets
through the advertising node's WireGuard tunnel.

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

### Multi-Cluster Mesh

Two Wirescale clusters can be linked by exchanging `WirescaleExternalPeer`
CRDs pointing at each other's gateway nodes:

```
Cluster A                          Cluster B
fd00:ws:a::/48                     fd00:ws:b::/48
  |                                  |
  +-- gateway-a (WirescaleNode)      +-- gateway-b (WirescaleNode)
  |     exitNode: false              |     exitNode: false
  |     advertisedRoutes:            |     advertisedRoutes:
  |       - fd00:ws:a::/48           |       - fd00:ws:b::/48
  |       - 100.64.0.0/16           |       - 100.64.128.0/16
  |                                  |
  +------ WireGuard tunnel ----------+
```

Pod in Cluster A can reach pods in Cluster B by their IPv6 or IPv4 mesh
addresses. DNS integration makes cross-cluster resolution seamless:
`api.backend.cluster-b.ws.cluster.internal`.

---

## 10. Security Model

### Encryption

- **Inter-node pod traffic:** WireGuard (ChaCha20-Poly1305, Curve25519, BLAKE2s)
- **Intra-node pod traffic:** Unencrypted (kernel namespace isolation is sufficient)
- **Control plane (CRD operations):** Kubernetes API TLS + RBAC
- **Key material:** Private keys never leave node memory. Public keys in CRDs.

### Identity and Authentication

Nodes authenticate to the mesh by proving ownership of their WireGuard
private key. The CRD serves as the key registry (analogous to Tailscale's
coordination server). Only nodes with valid kubeconfig can register CRDs.

For external peers, authentication is bootstrapped via:
1. Pre-shared auth token (one-time registration)
2. Admin approves the `WirescaleExternalPeer` CRD
3. Key exchange completes through the CRD

### Network Policy

Wirescale enforces policies at two levels:

**Level 1: WireGuard AllowedIPs (L3)**
Each node's WireGuard config only permits traffic from/to known pod CIDRs.
Traffic from unknown sources is silently dropped by WireGuard.

**Level 2: eBPF/nftables per-pod policy (L3/L4)**
The agent programs per-pod firewall rules based on:
- Kubernetes `NetworkPolicy` objects (standard API)
- `WirescalePolicy` CRDs (extended, identity-aware policies)

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
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping on inter-node traffic | WireGuard encryption (always on) |
| Unauthorized node joining mesh | Must create CRD via authenticated kube API |
| Compromised node | Revoke by deleting WirescaleNode CRD; all peers drop the peer immediately |
| Control plane compromise | Attacker can disrupt topology but cannot decrypt data plane traffic (no private keys in CRDs) |
| Key compromise on a single node | Rotate: agent generates new key, updates CRD. Old key immediately invalid for all peers. |

---

## 11. Custom Resource Definitions

### WirescaleMesh (cluster-scoped, singleton)

Cluster-wide mesh configuration.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
metadata:
  name: default
spec:
  # IPv6 pod CIDR (ULA range for the mesh)
  podCIDRv6: "fd00:ws::/48"
  # IPv4 pod CIDR (CGNAT range, translated via CLAT)
  podCIDRv4: "100.64.0.0/10"
  # Service CIDRs
  serviceCIDRv6: "fd00:ws:svc::/108"
  serviceCIDRv4: "100.64.255.0/24"  # optional
  # NAT64 prefix
  nat64Prefix: "64:ff9b::/96"
  # Mesh topology mode
  topology: full          # "full" | "location-aware"
  # WireGuard listen port
  listenPort: 51820
  # DNS domain for mesh names
  dnsDomain: "ws.local"
  # MTU override (0 = auto-detect)
  mtu: 0
status:
  nodeCount: 12
  healthyNodes: 12
  allocatedv6Blocks: 12
  allocatedv4Blocks: 12
```

### WirescaleNode (cluster-scoped, one per node)

Per-node mesh state. Created by the agent, enriched by the controller.

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
  endpoint: "[3fff::3]:51820"
  # Set by controller (IPAM)
  podCIDRv6: "fd00:ws:3::/64"
  podCIDRv4: "100.64.3.0/24"
  # Optional: subnet router / exit node
  advertisedRoutes: []
  exitNode: false
status:
  # Updated by agent
  ready: true
  peerCount: 11
  lastHandshake: "2026-03-02T10:00:00Z"
  wireguardInterface: "wg0"
  natType: "full-cone"     # Detected NAT type
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
  endpoint: "[3fff:home::1]:51820"
  allowedIPs:
    - "fd00:ws:ext:1::1/128"
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

---

## 12. Packet Flow Walkthrough

### Case 1: Pod-to-Pod, Same Node

```
Pod A (fd00:ws:1::5) -> Pod B (fd00:ws:1::7)
  eth0 -> veth -> host bridge/routing -> veth -> eth0
  (no WireGuard, no translation, direct kernel path)
```

### Case 2: Pod-to-Pod, Different Nodes (IPv6)

```
Pod A on node-1 (fd00:ws:1::5) -> Pod B on node-2 (fd00:ws:2::7)

Pod A: eth0 -> veth -> host
Host node-1: route fd00:ws:2::/64 dev wg0
  -> wg0: encrypt with node-2's public key
  -> UDP to [3fff::2]:51820

Network: IPv6 UDP packet transit

Host node-2: UDP :51820 -> wg0 decrypt
  -> verify src fd00:ws:1::5 in AllowedIPs for node-1 peer
  -> route fd00:ws:2::7 -> veth -> Pod B eth0
```

### Case 3: Pod-to-Pod, Different Nodes (IPv4 via CLAT)

```
Pod A on node-1: app connects to 100.64.2.7 (Pod B's IPv4)

Pod A: IPv4 packet -> clat0 TUN
  -> CLAT xlat: src fd00:ws:1::5, dst fd00:ws:2::7
  -> eth0 -> veth -> host
Host node-1: route fd00:ws:2::/64 dev wg0
  -> wg0: encrypt, send to node-2

Host node-2: wg0 decrypt -> route to Pod B veth
Pod B: eth0 receives IPv6 -> clat0 TUN xlat -> app sees IPv4
```

### Case 4: Pod to External IPv4 (via DNS64 + NAT64)

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

### Case 5: External Peer to Pod

```
Dev laptop (fd00:ws:ext:1::1) -> Pod B (fd00:ws:2::7)

Laptop: wirescale-join agent
  -> wg0: encrypt with node-2's public key
  -> UDP to [3fff::2]:51820

Node-2: wg0 decrypt -> verify AllowedIPs -> route to Pod B
```

---

## 13. Comparison with Existing Solutions

| Feature | Wirescale | Tailscale K8s Operator | Cilium WireGuard | Calico WireGuard | Kilo |
|---------|-----------|----------------------|------------------|------------------|------|
| Primary goal | Full CNI + IPv6-only support | Expose/connect services to tailnet | Transparent encryption for existing CNI | Transparent encryption for Calico | Multi-site WG overlay |
| CNI plugin | Yes (standalone) | No (uses existing) | No (is Cilium) | No (is Calico) | Optional |
| IPv6-only cluster support | First-class target | N/A | Version/mode dependent | Version/mode dependent | Topology dependent |
| NAT64/DNS64 | Built-in | No | No | No | No |
| CLAT per-pod | Yes | No | No | No | No |
| Mesh scope | Full cluster + external | Service-level proxies | Node-to-node | Node-to-node | Cross-site |
| External peers | Yes (CRD-based) | Yes (tailnet) | No | No | Yes (Peer CRD) |
| Control plane | In-cluster (CRDs) | Tailscale SaaS | Cilium agent | Calico Felix | Kubernetes API |
| Identity model | WG keys via CRD | Tailscale identity | CiliumNode annotation | Node annotation | Node annotation |

### Why Not Just Use Tailscale K8s Operator?

Tailscale's operator is designed to connect Kubernetes services to a
Tailscale tailnet. It is not a CNI -- it creates proxy pods that bridge
between the cluster network and the tailnet. It does not encrypt pod-to-pod
traffic within the cluster, does not handle IPv6-only clusters, and requires
a Tailscale account (or headscale) for the coordination server.

Wirescale is a ground-up CNI that uses the same principles (WireGuard mesh,
key coordination, identity-aware routing) but applies them at the cluster
network fabric level, with IPv6-only as the primary design target.

---

## 14. Implementation Phases

### Phase 1: Core Mesh (MVP)

- [ ] CRD definitions (WirescaleMesh, WirescaleNode)
- [ ] CNI plugin binary (veth pair, IPv6 address assignment)
- [ ] Agent DaemonSet (WireGuard interface, peer management, key exchange)
- [ ] Controller Deployment (IPAM allocation, mesh topology)
- [ ] Basic health checking and status reporting

**Result:** Encrypted IPv6 pod-to-pod mesh across nodes.

### Phase 2: IPv4 Compatibility

- [ ] CLAT engine in agent (per-pod IPv4 via TUN)
- [ ] NAT64 engine in agent (eBPF-based translation)
- [ ] CoreDNS dns64 plugin configuration
- [ ] CNI plugin: dual-address assignment (IPv6 + IPv4)
- [ ] IPv4 service VIP support

**Result:** Pods can use IPv4 transparently on an IPv6-only underlay.

### Phase 3: Policy and Security

- [ ] Kubernetes NetworkPolicy enforcement (eBPF or nftables)
- [ ] WirescalePolicy CRD and controller
- [ ] Key rotation support
- [ ] Audit logging

**Result:** Zero-trust network with granular policy control.

### Phase 4: External Connectivity

- [ ] WirescaleExternalPeer CRD and controller
- [ ] `wirescale-join` CLI for external peers
- [ ] Subnet router mode
- [ ] Exit node mode
- [ ] MagicDNS for mesh name resolution

**Result:** Full Tailscale-like mesh spanning cluster and external nodes.

### Phase 5: Multi-Cluster and Scale

- [ ] Multi-cluster mesh (gateway peering)
- [ ] Location-aware topology (zone-based leader election)
- [ ] NAT traversal / DERP-like relay for nodes behind NAT
- [ ] Performance optimization (eBPF fast path, batch processing)
- [ ] Metrics and observability (Prometheus, WireGuard handshake stats)

**Result:** Production-grade network operator for large-scale deployments.

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

## Appendix B: Port and Protocol Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 51820 | UDP | Node-to-node | WireGuard mesh traffic |
| 53 | UDP/TCP | Pod-to-CoreDNS | DNS resolution |
| 443 (svc) / 6443 (common control-plane endpoint) | TCP | Agent-to-API | Kubernetes API (CRD operations) |

## Appendix C: Kernel Requirements

For the target data plane in this document:

- Nodes MUST run Linux >= 5.6 (native WireGuard module) or provide a validated
  fallback path.
- Nodes MUST have IPv6 enabled (`net.ipv6.conf.all.disable_ipv6 = 0`).
- Nodes MUST have IP forwarding enabled (`net.ipv6.conf.all.forwarding = 1`).
- Nodes SHOULD provide eBPF support (for NAT64 and policy enforcement).
- Nodes MUST provide TUN/TAP support (for CLAT).
