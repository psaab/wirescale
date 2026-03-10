# Wirescale: Hierarchical /64-per-Host Design with Prefix Aggregation

> Every host in the fleet owns a dedicated /64 prefix. Within a cluster,
> the fabric routes /64 per host. Across clusters, a single aggregate
> prefix per cluster collapses routing state from O(global_hosts) to
> O(local_hosts + clusters). Direct WireGuard tunnels are established
> after signaling-plane resolution -- the gateway is a control waypoint,
> not a data-plane bottleneck.
>
> Status: design document for hierarchical routable-prefix mode. Treat
> statements as target architecture unless explicitly tied to implementation
> artifacts.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

**See also:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Core architecture (ULA overlay model,
  on-demand peering, control/data plane separation)
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
  (GRO/GSO, eBPF fast paths, kernel tuning)
- [SECURITY.md](SECURITY.md) -- Network security and dynamic access control
  (identity model, policy enforcement, trust boundaries)
- [CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md) -- Architecture comparison
  with Cilium as CNI
- [EGRESS.md](EGRESS.md) -- Internet egress architecture (NPTv6, NAT64,
  FQDN policy, egress observability)

---

## Table of Contents

1. [The /64-per-Host Model](#1-the-64-per-host-model)
2. [Hierarchical Prefix Allocation](#2-hierarchical-prefix-allocation)
3. [Two-Level Routing Architecture](#3-two-level-routing-architecture)
4. [BGP Aggregation Across Sites](#4-bgp-aggregation-across-sites)
5. [Route Override: Direct Tunnels](#5-route-override-direct-tunnels)
6. [Three-Tier Control Hierarchy](#6-three-tier-control-hierarchy)
7. [WireGuard as Encryption-Only Layer](#7-wireguard-as-encryption-only-layer)
8. [Selective Encryption for Cross-Cluster Traffic](#8-selective-encryption-for-cross-cluster-traffic)
9. [IPv4 Compatibility](#9-ipv4-compatibility)
10. [Cross-Cluster Connectivity and Signaling Gateway](#10-cross-cluster-connectivity-and-signaling-gateway)
11. [Scaling Analysis](#11-scaling-analysis)
12. [Packet Flow Walkthroughs](#12-packet-flow-walkthroughs)
13. [Security: Internet-Routable Pods](#13-security-internet-routable-pods)
14. [Deployment Topologies](#14-deployment-topologies)
15. [Comparison: ULA Overlay vs Hierarchical GUA](#15-comparison-ula-overlay-vs-hierarchical-gua)

---

## 1. The /64-per-Host Model

### Concept

Every host in the fleet receives a dedicated **/64 prefix** from globally
routable IPv6 address space (GUA -- Global Unicast Addresses, `2000::/3`)
or from ULA space (`fd00::/8`). Every pod on that host gets an address from
the host's /64. These addresses are internet-routable in GUA mode when
route advertisement and perimeter policy allow it, without NAT, tunnels, or
overlays in the same-site native path.

```
Cluster 1 allocation:   3fff:1234:0001::/48        (65,536 /64s available)
  Host worker-1:        3fff:1234:0001:0001::/64
    Pod A:              3fff:1234:0001:0001::a/128
    Pod B:              3fff:1234:0001:0001::b/128
  Host worker-2:        3fff:1234:0001:0002::/64
    Pod C:              3fff:1234:0001:0002::1/128
  Host worker-3:        3fff:1234:0001:0003::/64
    ...
```

The /64 is the natural operational unit for IPv6 subnets: SLAAC on standard
Ethernet links expects a 64-bit IID, and many production designs optimize
around /64 boundaries. A /64 provides 2^64 addresses per host -- more than
enough for any conceivable pod density.

### Why This Matters

With routable pod addresses:
- **No overlay network needed for reachability** -- pods reach each other
  and the internet via native IP routing within the cluster
- **No SNAT for outbound traffic** -- the pod's real address is preserved
  end-to-end (GUA mode)
- **Direct inbound connectivity** -- external clients can reach pods
  directly (when policy allows, GUA mode)
- **WireGuard is optional for reachability** -- it becomes a pure
  encryption layer, activated only when confidentiality is required
- **Maximum performance** -- no encapsulation overhead for unencrypted
  same-cluster traffic

### Hyperscale Implications

The /64-per-host model is the fundamental architectural decision that makes
hyperscale deployments possible. The /64 prefix is the **routing unit
within a cluster**: the data center fabric routes /64 prefixes, not
individual pod addresses.

**Within a cluster, routing state is O(hosts), not O(pods).** Each host
contributes exactly one /64 route to the fabric. At 10,000 hosts, the
fabric carries 10,000 routes. The number of pods per host is irrelevant
to routing state -- a host running 1 pod and a host running 500 pods
both contribute the same single /64 prefix.

**Across clusters, routing state is O(clusters), not O(global_hosts).**
Each remote cluster contributes exactly one aggregate route. A node does
not need to know about every host in every remote cluster -- it needs
only the aggregate prefix that covers the entire cluster. This is the
hierarchical aggregation that makes 100K+ host deployments tractable.

The combined per-node routing state is:

```
Per-node state = O(local_hosts) + O(clusters) + O(active_direct_peers)
               = O(local_hosts + clusters)

Where:
  local_hosts    = hosts in the node's own cluster (typically 1K-10K)
  clusters       = total remote clusters (typically tens to hundreds)
  active_peers   = direct tunnels to remote hosts (transient, bounded)
```

This decoupling of routing state from global host count is what allows
hyperscale deployments. See [SECURITY.md](SECURITY.md) for policy
implications and [PERFORMANCE.md](PERFORMANCE.md) for the data plane
fast path.

---

## 2. Hierarchical Prefix Allocation

### The Problem with Flat /64 Distribution

If every host's /64 is distributed globally across all clusters, a 100K-host
fleet produces 100K route entries on every node in every cluster. This
approach has O(global_hosts) routing state per node and fails to scale:

| Global Scale | Flat /64 Routes per Node | Hierarchical Routes per Node |
|-------------|--------------------------|------------------------------|
| 10K hosts, 1 cluster | 10,000 | 10,000 (no benefit) |
| 50K hosts, 5 clusters | 50,000 | 10,000 + 4 aggregates |
| 100K hosts, 10 clusters | 100,000 | 10,000 + 9 aggregates |
| 500K hosts, 50 clusters | 500,000 | 10,000 + 49 aggregates |

Hierarchical prefix aggregation reduces cross-cluster routing from
O(global_hosts) to O(clusters).

### Cluster-Level Prefix Allocation

Each cluster receives a contiguous prefix from which all host /64s within
that cluster are allocated. The choice of prefix depends on the addressing
mode:

**ULA mode:** each cluster gets a `/48` from `fd00:1234::/32`:

```
Organization prefix:   fd00:1234::/32   (reserved for Wirescale ULA)

  Cluster 1:           fd00:1234:0001::/48
    Host 1:            fd00:1234:0001:0001::/64
    Host 2:            fd00:1234:0001:0002::/64
    ...                (up to 65,536 hosts per cluster)

  Cluster 2:           fd00:1234:0002::/48
    Host 1:            fd00:1234:0002:0001::/64
    Host 2:            fd00:1234:0002:0002::/64
    ...

  Cluster N:           fd00:1234:CCCC::/48
    (up to 65,536 clusters addressable)
```

**GUA mode:** each cluster gets a `/48` from globally routable space:

```
Organization prefix:   3fff:1234::/32   (documentation prefix, replace in production)

  Cluster 1:           3fff:1234:0001::/48
    Host 1:            3fff:1234:0001:0001::/64
    Host 2:            3fff:1234:0001:0002::/64
    ...                (up to 65,536 hosts per cluster)

  Cluster 2:           3fff:1234:0002::/48
    Host 1:            3fff:1234:0002:0001::/64
    Host 2:            3fff:1234:0002:0002::/64
    ...

  Cluster N:           3fff:1234:N::/48
    (up to 65,536 clusters addressable)
```

`3fff::/20` is designated for documentation/example usage (RFC 9637).
Replace the examples above with provider-assigned production GUA ranges.

### Allocation Rules

1. **The global directory** MUST assign non-overlapping cluster prefixes.
   Each cluster gets exactly one /32 (ULA) or /48 (GUA).

2. **The cluster controller** MUST assign non-overlapping /64 prefixes
   within the cluster's prefix to each host. Each host gets exactly one /64.

3. **The CNI** MUST assign non-overlapping /128 addresses within the
   host's /64 to each pod.

4. Cluster prefixes MUST be contiguous and aggregatable. The global
   directory MUST NOT assign prefixes that fragment the aggregation
   hierarchy.

### Dual-Address Model: Rack /64 + Pod /64

Within a cluster, every host has **two IPv6 addresses from two different
/64 prefixes**:

1. **Rack address (/128 from the rack's /64):** The host's identity on the
   data center fabric. All hosts in the same rack share one /64 on the L2
   segment connecting them to the ToR switch. Each host gets a single /128
   from this prefix. Used for: management, WireGuard endpoints,
   node-to-node communication, and as the BGP next-hop for the pod /64
   (configured by the fabric, not Wirescale).

2. **Pod prefix (dedicated /64):** A separate /64 from the cluster's
   prefix, routed to this host for pod addressing. Every pod on the host
   gets a /128 from this prefix. The fabric routes this prefix to the
   host (via BGP or static config).

```
Cluster 1: 3fff:1234:0001::/48

  Rack 1 (ToR-1):
    Rack /64:    3fff:1234:0001:ff01::/64  (shared L2 segment)
    ToR switch:  3fff:1234:0001:ff01::1/128

    Host worker-1:
      eth0 (rack):   3fff:1234:0001:ff01::11/128  (from rack /64)
      Pod /64:       3fff:1234:0001:0001::/64      (dedicated, routed to host)
        gateway:     3fff:1234:0001:0001::1
        Pod A:       3fff:1234:0001:0001::a
        Pod B:       3fff:1234:0001:0001::b

    Host worker-2:
      eth0 (rack):   3fff:1234:0001:ff01::12/128  (from rack /64)
      Pod /64:       3fff:1234:0001:0002::/64      (dedicated, routed to host)
        gateway:     3fff:1234:0001:0002::1
        Pod C:       3fff:1234:0001:0002::1a

  Rack 2 (ToR-2):
    Rack /64:    3fff:1234:0001:ff02::/64
    ToR switch:  3fff:1234:0001:ff02::1/128

    Host worker-3:
      eth0 (rack):   3fff:1234:0001:ff02::11/128
      Pod /64:       3fff:1234:0001:0003::/64
        ...
```

### Why Two Prefixes

The separation is deliberate:

- **The rack /64 is infrastructure.** It's the L2 segment. The ToR switch
  has a directly-connected route for it. NDP works naturally -- all hosts
  on the rack can discover each other via standard Neighbor Solicitation
  on this shared /64. No proxy NDP, no hacks.

- **The pod /64 is routed, not bridged.** The ToR learns about each host's
  pod /64 via BGP (next-hop = host's rack address). Pods are not on the
  rack L2 segment -- they're behind the host, which acts as a router.
  This is cleaner, scales better, and prevents pod NDP traffic from
  flooding the rack segment.

- **Clear failure domain.** If a host goes down, only its pod /64 is
  affected. The rack /64 remains operational for all other hosts. The
  fabric automatically withdraws the dead host's pod /64 route.

### WireGuard Endpoint

The WireGuard endpoint uses the host's rack address (stable,
infrastructure-level):

```
Host worker-1:
  WireGuard endpoint:  [3fff:1234:0001:ff01::11]:51820  (rack address)
  wg0 has no IP assigned -- it's an encryption-only device
```

This means WireGuard peers use the rack address to reach each other,
while pod traffic is routed via the pod /64. The two address spaces serve
completely different purposes and never overlap.

### Pod Address Assignment

The CNI assigns addresses directly (no SLAAC, no DHCPv6):

```
IPAM strategy: sequential from pool, skip gateway and reserved

Pool:     3fff:1234:0001:0001::a  through  3fff:1234:0001:0001:ffff:ffff:ffff:ffff
Reserved: 3fff:1234:0001:0001::0  (subnet-router anycast, RFC 4291)
          3fff:1234:0001:0001::1  (host gateway)
          3fff:1234:0001:0001::2  through ::9 (infrastructure, future use)
Available: ~18.4 quintillion addresses (2^64 - 10)
```

DAD (Duplicate Address Detection) is disabled on pod interfaces because the
IPAM is authoritative and no other device shares the link:

```bash
sysctl -w net.ipv6.conf.eth0.accept_dad=0    # inside pod netns
```

---

## 3. Two-Level Routing Architecture

### The Core Insight

Routing operates at two distinct levels, each with different granularity
and distribution scope:

1. **Within a cluster:** /64-per-host routes distributed to all nodes in
   the cluster. O(hosts_in_cluster) entries per node.

2. **Across clusters:** ONE aggregate route per remote cluster. O(clusters)
   entries per node.

The combined routing table on any node contains:

```
WITHIN-CLUSTER ROUTES (from fabric BGP or cluster controller):
  3fff:1234:0001:0001::/64 via 3fff:1234:0001:ff01::11   # host-1
  3fff:1234:0001:0002::/64 via 3fff:1234:0001:ff01::12   # host-2
  3fff:1234:0001:0003::/64 via 3fff:1234:0001:ff02::11   # host-3
  ...                                                      # (one per local host)

CROSS-CLUSTER AGGREGATES (from global directory -> controller -> agent):
  3fff:1234:0002::/48 via gateway-cluster2                 # Cluster 2
  3fff:1234:0003::/48 via gateway-cluster3                 # Cluster 3
  3fff:1234:0004::/48 via gateway-cluster4                 # Cluster 4
  ...                                                      # (one per remote cluster)

DIRECT PEER OVERRIDES (transient, from on-demand resolution):
  3fff:1234:0002:0042::/64 dev wg0                         # direct tunnel to host-42 in Cluster 2
  3fff:1234:0003:0017::/64 dev wg0                         # direct tunnel to host-17 in Cluster 3
  ...                                                      # (only active peers, GC'd when idle)
```

### Why This Works

The key property is **longest-prefix match**. When a node has both an
aggregate route (`3fff:1234:0002::/48 via gateway`) and a specific route
(`3fff:1234:0002:0042::/64 dev wg0`), the /64 is more specific than the
/48, so traffic to host-42 goes through the direct WireGuard tunnel. Traffic
to any other host in Cluster 2 falls through to the aggregate and goes via
the gateway for signaling-plane resolution.

This gives three forwarding states per remote destination:

| State | Route Matched | Path | Latency |
|-------|--------------|------|---------|
| No communication yet | Aggregate /48 (or /32 ULA) | Via gateway (triggers resolution) | Cold path: +10-50 ms |
| Direct tunnel active | Specific /64 | Via WireGuard peer | Warm path: native |
| Tunnel GC'd | Aggregate /48 (or /32 ULA) | Via gateway (re-triggers resolution) | Cold path on next use |

### Within-Cluster Route Distribution

Within a cluster, /64 routes are distributed by the **cluster fabric BGP
or cluster controller**. This is the standard datacenter model:

- **Fabric BGP (bare metal):** Each host peers with its ToR switch via
  eBGP. The host announces its pod /64 with its rack address as next-hop.
  The ToR aggregates and re-advertises to the spines. All hosts in the
  cluster learn all /64 routes via the fabric.

- **Controller-managed (cloud or overlay):** The cluster controller
  pushes /64 routes to each node via the agent. This is functionally
  equivalent to fabric BGP but uses the Wirescale control plane instead
  of the network fabric.

In either case, Wirescale does **not** embed a BGP speaker. The routing
infrastructure is managed by the network operations team using their
existing tools (BIRD, FRR, SONiC, Arista EOS, etc.) or by the Wirescale
controller for environments without fabric BGP.

| Responsibility | Owner |
|---------------|-------|
| Cluster prefix allocation (/48 or /32) | Global directory |
| Host /64 allocation within cluster | Cluster controller (IPAM) |
| Route advertisement (pod /64 -> host) within cluster | Fabric BGP (network team) or cluster controller |
| Pod address assignment within /64 | Wirescale CNI |
| Per-pod /128 host routes | Wirescale CNI (local only, not in BGP) |
| Cross-cluster aggregate routes | Global directory -> controller -> agent |
| Encryption policy | Wirescale agent |
| Pod network policy | Wirescale agent (eBPF) |

### Cross-Cluster Route Distribution

Cross-cluster routes are aggregate prefixes distributed through the
**three-tier control hierarchy** (Section 6). Each node's agent receives
a small set of aggregate routes from its cluster controller:

```
Controller -> Agent push (periodic or on cluster topology change):

{
  "remote_clusters": [
    {
      "cluster_id": "cluster-2",
      "prefix": "3fff:1234:0002::/48",
      "gateways": [
        {"endpoint": "[3fff:1234:0002:ff01::fe]:51820", "pubkey": "abc..."},
        {"endpoint": "[3fff:1234:0002:ff02::fe]:51820", "pubkey": "def..."}
      ]
    },
    {
      "cluster_id": "cluster-3",
      "prefix": "3fff:1234:0003::/48",
      "gateways": [
        {"endpoint": "[3fff:1234:0003:ff01::fe]:51820", "pubkey": "ghi..."}
      ]
    }
  ]
}
```

The agent installs aggregate routes pointing to the gateway:

```bash
# Cross-cluster aggregate routes (installed by agent)
ip -6 route add 3fff:1234:0002::/48 via <local-gateway-addr>
ip -6 route add 3fff:1234:0003::/48 via <local-gateway-addr>
```

The gateway is a signaling waypoint for initial peer resolution (see
Section 10). After resolution, direct /64 routes override the aggregate.

### Typical Fabric Topology (Within a Cluster)

The fabric typically runs eBGP between each layer within a single cluster:

```
                    Spine switches (AS 65000)
                   /          |          \
                  /           |           \
        ToR-1 (AS 65001)  ToR-2 (AS 65002)  ToR-3 (AS 65003)
          |       |          |       |          |       |
       host-1  host-2    host-3  host-4     host-5  host-6
```

Each host peers with its ToR (or uses static routes provisioned by the
fabric automation). The host advertises its pod /64 with its rack
address as the next-hop. The ToR aggregates and re-advertises upstream
to the spines. **All of this is standard datacenter BGP and is outside
Wirescale's scope.**

### What Wirescale Expects from the Cluster Fabric

For Wirescale to function correctly within a cluster, the fabric MUST
provide:

1. **Reachability for the rack /64:** Hosts on the same rack can reach
   each other via L2 (NDP) on the shared rack /64 segment.

2. **Route for each pod /64:** The fabric routes each host's pod /64
   (next-hop = host's rack address) so that any host in the cluster can
   reach any other host's pods via native IPv6 forwarding.

3. **Default route:** Each host has a default IPv6 route (typically
   learned from the ToR via RA or BGP) for internet egress.

### Kernel Sysctls for Host-as-Router

The wirescale-agent configures the host to forward packets between pod
veths and the physical NIC:

```bash
# Accept RAs even with forwarding enabled (critical!)
# The host receives RAs from the ToR on the rack /64 for default route.
# Without accept_ra=2, enabling forwarding silently disables RA processing.
net.ipv6.conf.eth0.accept_ra = 2
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.eth0.forwarding = 1

# Proxy NDP is NOT needed:
# - Pod /64 reachability is via fabric BGP (ToR has a route, not an L2 adjacency)
# - Rack /64 uses standard NDP (hosts are on the same L2 segment)
net.ipv6.conf.eth0.proxy_ndp = 0
```

---

## 4. BGP Aggregation Across Sites

### The Key Principle

BGP aggregation is the standard mechanism for reducing routing table size
across administrative boundaries. Wirescale applies this naturally:

- **Within a site (intra-site fabric):** BGP announces /64 per host.
  Every host in the site has a route to every other host's /64. This is
  the standard datacenter BGP model and is unchanged.

- **Across sites (WAN/backbone):** BGP announces /48 per cluster (GUA)
  or /32 per cluster (ULA). NOT /64 per host. This reduces the WAN
  routing table from O(global_hosts) to O(clusters).

This is standard BGP aggregation -- nothing novel. What Wirescale adds
is the integration of this aggregation into the control hierarchy so that
nodes receive the right aggregate routes automatically.

### GUA Mode: /48 Aggregation on the WAN

In GUA mode, each cluster's /48 prefix is a single BGP announcement on
the WAN backbone:

```
Site A (DC-East):
  Cluster 1: 3fff:1234:0001::/48  <- announced to WAN as single /48
    Internal: 10,000 /64 host routes (fabric-only, never cross WAN)

Site B (DC-West):
  Cluster 2: 3fff:1234:0002::/48  <- announced to WAN as single /48
    Internal: 10,000 /64 host routes (fabric-only, never cross WAN)

Site C (DC-South):
  Cluster 3: 3fff:1234:0003::/48  <- announced to WAN as single /48
    Internal: 5,000 /64 host routes (fabric-only, never cross WAN)
```

WAN routing table at each site border router:

```
3fff:1234:0001::/48 -> local (this site)
3fff:1234:0002::/48 -> via WAN link to DC-West
3fff:1234:0003::/48 -> via WAN link to DC-South
```

Three routes, not 25,000. The WAN sees O(clusters), not O(hosts).

### ULA Mode: /32 Aggregation

In ULA mode, the aggregation is at /48 per cluster:

```
fd00:1234:0001::/48  -> Cluster 1 (local or via gateway)
fd00:1234:0002::/48  -> Cluster 2 (via gateway)
fd00:1234:0003::/48  -> Cluster 3 (via gateway)
```

Because ULA addresses are not globally routable, cross-cluster traffic
MUST traverse WireGuard tunnels regardless. The aggregate routes point
to gateway nodes that terminate the tunnels.

> **See also:** [EGRESS.md §3](EGRESS.md#3-nptv6-stateless-ipv6-prefix-translation)
> describes NPTv6 for ULA-to-GUA translation at egress gateways, enabling
> internet-bound traffic from ULA clusters without per-flow SNAT state.
> [§3.4](EGRESS.md#34-gua-mode-clusters) explains that GUA-mode clusters skip
> NPTv6 entirely since pod addresses are already globally routable.

### Multi-Cluster at a Single Site

Multiple clusters MAY share a physical site. In this case, intra-site
fabric can carry the aggregate routes without WAN involvement:

```
DC-East (single physical site):
  Cluster 1: 3fff:1234:0001::/48  (10K hosts, fabric A)
  Cluster 4: 3fff:1234:0004::/48  (5K hosts, fabric B)

  The site border routers have routes for both /48s.
  Cross-cluster traffic between Cluster 1 and Cluster 4
  stays within the site -- no WAN transit needed.
```

The signaling gateway model still applies: initial peer resolution goes
through the control hierarchy, and direct tunnels are established for
ongoing communication.

### Aggregation Rules

1. Host /64 routes MUST NOT be announced across cluster boundaries.
   Only the covering /48 (GUA) or /32 (ULA) aggregate is announced.

2. Site border routers MUST aggregate all host /64s within a cluster
   into the cluster's prefix before announcing to the WAN.

3. Within a cluster, the fabric MUST carry individual /64 routes per
   host. Aggregation within a cluster is NOT permitted because the
   fabric needs host-level granularity for forwarding.

4. Cross-cluster aggregate routes MUST be distributed to all nodes
   via the control hierarchy (global directory -> controller -> agent),
   not via fabric BGP. This keeps the Wirescale control plane and the
   fabric BGP independent.

---

## 5. Route Override: Direct Tunnels

### The Override Mechanism

When a node establishes a direct WireGuard tunnel to a remote host, a
/64 route is installed that overrides the aggregate:

```
Before direct tunnel:
  3fff:1234:0002::/48 via gateway          # aggregate for Cluster 2

After direct tunnel to host-42 in Cluster 2:
  3fff:1234:0002:0042::/64 dev wg0         # direct peer (more specific)
  3fff:1234:0002::/48 via gateway          # aggregate (unchanged)

Traffic to 3fff:1234:0002:0042::anything -> goes via wg0 (direct)
Traffic to 3fff:1234:0002:0099::anything -> goes via gateway (aggregate)
```

The /64 is more specific than the /48, so longest-prefix-match routing
sends traffic directly to the WireGuard peer, bypassing the gateway
entirely.

### Lifecycle of a Direct Peer Override

```
1. TRIGGER: First packet to remote host in Cluster 2
   - Matches aggregate route: 3fff:1234:0002::/48 via gateway
   - Gateway intercepts and initiates signaling-plane resolution

2. RESOLUTION: Signaling gateway resolves the destination
   - Agent queries local controller -> global directory -> remote controller
   - Remote controller returns: host public key + endpoint address
   - Agent establishes WireGuard peer for the specific /64

3. INSTALL: /64 route overrides aggregate
   - ip -6 route add 3fff:1234:0002:0042::/64 dev wg0
   - wg set wg0 peer <pubkey> endpoint [remote-rack-addr]:51820 \
         allowed-ips 3fff:1234:0002:0042::/64

4. FORWARD: Subsequent packets use direct path
   - Longest-prefix match: /64 > /48 -> direct WireGuard tunnel
   - No gateway involvement for data plane

5. GC: Idle timeout removes the override
   - After configurable idle period (default: 5 minutes with no traffic)
   - wg set wg0 peer <pubkey> remove
   - ip -6 route del 3fff:1234:0002:0042::/64 dev wg0
   - Falls back to aggregate route via gateway
```

### Properties of the Override Model

**Automatic failover.** If a direct tunnel fails (peer becomes
unreachable), the /64 route is removed and traffic falls back to the
aggregate via the gateway. The gateway can then re-initiate resolution,
potentially finding a new path.

**No stale state.** Direct overrides are transient. They exist only while
communication is active. When the GC timer fires, the override is removed
cleanly. There is no persistent state to become stale.

**Bounded per-node state.** The number of direct overrides on any node
is bounded by the number of active remote communication peers. A node
talking to 50 remote hosts has 50 override routes -- regardless of the
total number of hosts in the fleet.

**No routing protocol convergence.** Override installation and removal are
local operations. They do not trigger BGP updates, do not propagate to
other nodes, and do not require distributed consensus. This is strictly
local routing table manipulation.

---

## 6. Three-Tier Control Hierarchy

### Architecture

The control plane is organized into three tiers, each responsible for
a different scope of routing and peer information:

```
                    +-----------------------+
                    |   Global Directory    |
                    |   Knows:              |
                    |   - Cluster prefixes  |
                    |   - Gateway endpoints |
                    +-----------+-----------+
                       /        |        \
                      /         |         \
         +-----------+   +-----------+   +-----------+
         | Cluster   |   | Cluster   |   | Cluster   |
         | Controller|   | Controller|   | Controller|
         | (C1)      |   | (C2)      |   | (C3)      |
         | Knows:    |   | Knows:    |   | Knows:    |
         | - Host    |   | - Host    |   | - Host    |
         |   /64s    |   |   /64s    |   |   /64s    |
         | - Agents  |   | - Agents  |   | - Agents  |
         +-----+-----+   +-----+-----+   +-----+-----+
              /|\              /|\              /|\
             / | \            / | \            / | \
           Agents           Agents           Agents
           (nodes)          (nodes)          (nodes)
```

### Global Directory

The global directory is the top-level coordination point. It:

- **Maintains the cluster prefix registry:** Maps cluster IDs to their
  prefixes (e.g., "cluster-2" -> `3fff:1234:0002::/48`) and gateway
  endpoints.

- **Distributes aggregate routes:** Pushes the set of remote cluster
  prefixes + gateway info to each cluster controller.

- **Resolves cross-cluster lookups:** When a cluster controller receives
  a peer resolution request for a prefix outside its own cluster, it
  queries the global directory, which routes the request to the
  appropriate remote cluster controller.

The global directory does NOT handle data-plane traffic. It is a
signaling-plane component only.

**Availability:** The global directory MUST be highly available (replicated,
multi-region). However, it is queried only during cluster topology changes
(new cluster added, gateway failover) and cross-cluster peer resolution.
Steady-state intra-cluster operation does not depend on the global
directory.

### Cluster Controller

Each cluster runs its own controller instance. It:

- **Manages host /64 assignments:** Allocates /64 prefixes from the
  cluster's /48 (or /32) to each host.

- **Distributes local routes:** Ensures all nodes in the cluster know
  the /64-to-host mappings (via fabric BGP integration or direct push).

- **Caches aggregate routes:** Receives the set of remote cluster
  prefixes from the global directory and pushes them to local agents.

- **Handles cross-cluster peer resolution:** When a local agent needs
  to establish a direct tunnel to a remote host, the controller resolves
  the request via the global directory.

- **Manages WireGuard key material:** Distributes and rotates public
  keys for local hosts, provides keys to the global directory for
  cross-cluster peer resolution.

### Node Agent

Each node runs an agent that:

- **Maintains the local routing table:** Installs within-cluster /64
  routes (from fabric BGP or controller push) and cross-cluster aggregate
  routes (from controller push).

- **Handles on-demand peer resolution:** When the eBPF program detects
  traffic to a destination with no direct peer, the agent queries the
  controller for peer info and establishes the WireGuard peer.

- **Installs route overrides:** When a direct tunnel is established,
  the agent adds the /64 route override that bypasses the aggregate.

- **Garbage collects idle peers:** Removes direct WireGuard peers and
  their /64 route overrides after the idle timeout.

- **Enforces encryption and network policy:** Runs eBPF programs on
  pod veths for per-flow encryption decisions and access control.

### Agent State Summary

```
Node agent's routing knowledge:

1. LOCAL CLUSTER (from fabric BGP or controller):
   3fff:1234:0001:0001::/64 via <rack-addr-1>    # host-1
   3fff:1234:0001:0002::/64 via <rack-addr-2>    # host-2
   ...
   (typically 1K-10K entries)

2. REMOTE CLUSTERS (from controller, sourced from global directory):
   3fff:1234:0002::/48 via <gateway>              # Cluster 2
   3fff:1234:0003::/48 via <gateway>              # Cluster 3
   ...
   (typically tens to hundreds of entries)

3. DIRECT PEER OVERRIDES (from on-demand resolution, transient):
   3fff:1234:0002:0042::/64 dev wg0              # active peer in Cluster 2
   3fff:1234:0003:0017::/64 dev wg0              # active peer in Cluster 3
   ...
   (bounded by active communication peers, typically tens)
```

Total per-node state: O(local_hosts + clusters + active_peers)

---

## 7. WireGuard as Encryption-Only Layer

### The Paradigm Shift

In the base architecture, WireGuard serves dual duty: routing overlay +
encryption. With routable prefixes and fabric-managed or controller-managed
routing, routing is native. WireGuard's role shrinks to **transparent
encryption** for traffic that requires confidentiality.

This is how Cilium and Calico already use WireGuard in native routing
mode. Wirescale goes further: WireGuard peers are established **on-demand**
via the control hierarchy rather than statically configured for all nodes.

### On-Demand Peering Model

WireGuard peers MUST NOT be pre-established with every node in the cluster
or across clusters. Instead, peers are created on-demand when encrypted
communication is needed:

1. **Cold path (first packet to a new destination /64):** The eBPF program
   detects that encryption is required but no WireGuard peer exists for the
   destination. The packet is queued and the agent queries the controller
   for the peer information (public key, endpoint rack address) of the remote
   host that owns the destination /64. The peer is established, the queued
   packet is sent, and subsequent packets follow the warm path.

2. **Warm path (existing peer):** The WireGuard peer is already established.
   Packets are encrypted and forwarded immediately -- identical to the static
   peering case.

3. **Garbage collection:** Peers that have been idle (no traffic) for a
   configurable period (default: 5 minutes) SHOULD be removed. This keeps
   per-node WireGuard state proportional to active communication peers, not
   cluster size or fleet size.

This model means a node in a 100,000-node fleet that communicates with
50 remote nodes at any given time maintains only 50 WireGuard peers --
regardless of total fleet size. Per-node WireGuard state is
O(active_peers), not O(N).

### Architecture

```
Pod A (3fff:1234:0001:0001::a) on host-1 -> Pod B (3fff:1234:0001:0002::b) on host-2
  (same cluster, same site)
  host-1 rack addr: 3fff:1234:0001:ff01::11
  host-2 rack addr: 3fff:1234:0001:ff01::12

WITHOUT encryption (same-cluster, trusted fabric):
  Pod A -> veth -> host routing -> eth0 -> rack L2 -> host-2 eth0 -> veth -> Pod B
  (pure native IPv6, line rate, zero overhead)

WITH encryption (cross-cluster or policy requires it):
  Cold: Pod A -> veth -> eBPF -> queue -> agent queries controller -> peer established
  Warm: Pod A -> veth -> eBPF redirect -> wg0 -> encrypt -> eth0 (via rack addr)
  -> fabric -> remote host eth0 -> wg0 -> decrypt -> eBPF redirect -> veth -> Pod B
  (WireGuard overhead, but only when policy demands it)
```

### Encryption Decision Point

The eBPF program on each pod's veth makes the encryption decision per-
packet based on the destination:

```c
SEC("tc/egress")
int wirescale_egress(struct __sk_buff *skb) {
    struct ipv6hdr *ip6 = parse_ipv6(skb);

    // 1. Same node? -> direct delivery, no encryption
    if (is_local_pod(ip6->daddr))
        return TC_ACT_OK;

    // 2. Check encryption policy for this flow
    struct encrypt_policy *pol = bpf_map_lookup_elem(
        &encrypt_map, &ip6->daddr);

    if (pol && pol->require_encryption) {
        // Redirect to wg0 for encryption
        return bpf_redirect(wg0_ifindex, 0);
    }

    // 3. No encryption needed -- native routing
    return TC_ACT_OK;
}
```

The `encrypt_map` is populated by the agent based on policy:

| Destination Prefix | Encrypt? | Reason |
|-------------------|----------|--------|
| Same cluster prefix | No (default) | Trusted fabric |
| Remote cluster prefix | Yes | Cross-cluster = untrusted transit |
| External (::/0) | Policy-dependent | Application-layer encryption may suffice |
| Specific pod CIDR | Yes | Policy override (sensitive workload) |

### WireGuard Configuration (On-Demand Encryption Mode)

When WireGuard is encryption-only with on-demand peering, the interface
starts with no peers. Peers are added dynamically by the agent as needed:

```
[Interface]
ListenPort = 51820
PrivateKey = <generated-at-boot>
# No Address -- wg0 is not a routed interface, just an encryption hop
# Endpoint uses the host's rack address

# No static [Peer] sections -- peers are established on-demand:
#   1. eBPF detects encryption needed for destination /64
#   2. Agent queries controller: "who owns 3fff:1234:0002:0042::/64?"
#   3. Controller resolves (locally or via global directory)
#   4. Agent adds peer dynamically:
#        wg set wg0 peer <pubkey> endpoint [rack-addr]:51820 \
#            allowed-ips <destination-/64>
#   5. Peer is GC'd after idle timeout (default: 5 min)
```

Traffic doesn't "route through" wg0 in the normal sense. The eBPF program
explicitly redirects selected packets into wg0 for encryption, and wg0
delivers the encrypted UDP datagram out through the physical NIC. Return
traffic arrives as UDP on port 51820, WireGuard decrypts it, and the
kernel routes the inner packet to the destination pod.

---

## 8. Selective Encryption for Cross-Cluster Traffic

### Encryption Policy

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
metadata:
  name: default
spec:
  encryption:
    # Mode: "always" | "cross-cluster" | "cross-site" | "never" | "policy"
    mode: cross-cluster

    # Cluster boundaries (inferred from cluster prefix allocation):
    clusters:
      - name: cluster-1
        prefix: "3fff:1234:0001::/48"
      - name: cluster-2
        prefix: "3fff:1234:0002::/48"
      - name: cluster-3
        prefix: "3fff:1234:0003::/48"

    # Site boundaries (for cross-site mode):
    sites:
      - name: dc-east
        clusters: ["cluster-1", "cluster-4"]
      - name: dc-west
        clusters: ["cluster-2"]
      - name: dc-south
        clusters: ["cluster-3"]

    # Traffic within a cluster: unencrypted (native routing)
    # Traffic between clusters: WireGuard encrypted (direct tunnel after resolution)
    # Traffic between sites: WireGuard encrypted (always)

    # When mode is "policy", encryption is per-WirescalePolicy:
    # Each WirescalePolicy can set `encryption: required`
```

### Mode Details

**`always`:** All inter-node pod traffic goes through WireGuard, even
within the same cluster. Equivalent to the base overlay architecture.
Maximum security, lower performance for intra-cluster traffic.

**`cross-cluster`:** Intra-cluster traffic routes natively (line rate).
Cross-cluster traffic is encrypted via WireGuard using direct tunnels
established after signaling-plane resolution. This is the recommended
default for multi-cluster deployments.

**`cross-site`:** Same as `cross-cluster` but the trust boundary is the
physical site, not the cluster. Clusters co-located at the same site
communicate unencrypted; traffic between sites is encrypted. Useful when
multiple clusters share a trusted fabric within a single datacenter.

**`never`:** No WireGuard at all. Pure native routing everywhere. Suitable
when the entire network is trusted (single rack, MACsec-protected fabric)
or when encryption is handled at the application layer (mTLS).

**`policy`:** Per-flow encryption decisions based on WirescalePolicy:

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
          port: 443
      encryption: required     # <-- this flow must be encrypted
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: card-processor
      ports:
        - protocol: TCP
          port: 8443
      encryption: required
```

### Cross-Cluster Encryption via Direct Tunnels

The critical design choice: cross-cluster encryption uses **direct
WireGuard tunnels between communicating hosts**, not gateway relay.

```
WRONG (gateway as data relay):
  host-A (cluster-1) -> gateway-1 -> WAN -> gateway-2 -> host-B (cluster-2)
  Gateway is a throughput bottleneck. All cross-cluster traffic converges.

RIGHT (gateway as signaling waypoint, direct tunnel after resolution):
  Step 1: host-A -> gateway-1 -> signaling -> gateway-2 -> host-B (resolution)
  Step 2: host-A -> direct WireGuard tunnel -> host-B (data plane)
  Gateway is off the data path after the first packet.
```

This means:
- Cross-cluster throughput is NOT limited by gateway capacity
- Gateways handle only signaling (low bandwidth, low CPU)
- Each direct tunnel is point-to-point, encrypted end-to-end
- Gateway failure does not disrupt established tunnels (only new resolution)

### Performance Impact by Mode

| Mode | Intra-Cluster Throughput | Cross-Cluster Throughput | CPU Overhead |
|------|-------------------------|--------------------------|-------------|
| `never` | Line rate | Line rate (if direct path) | Minimal |
| `cross-cluster` | Line rate | WireGuard (~10G/core, direct tunnel) | Cross-cluster only |
| `cross-site` | Line rate (same site) | WireGuard (~10G/core, direct tunnel) | Cross-site only |
| `policy` | Line rate (unless policy says encrypt) | Varies | Per-flow |
| `always` | WireGuard limited | WireGuard limited | Every inter-node packet |

---

## 9. IPv4 Compatibility

The IPv4 compatibility story is unchanged from the base architecture.

### CLAT (Per-Pod IPv4)

Every pod gets a CLAT `clat0` interface with a CGNAT IPv4 address. The
deterministic mapping is:

```
100.64.N.P  <-->  3fff:1234:CCCC:N::P
```

where `CCCC` identifies the cluster. The eBPF CLAT program doesn't care
about the IPv6 scope -- it maps between two fixed addresses regardless.

### NAT64 (External IPv4 Destinations)

For reaching IPv4-only internet hosts, the NAT64 engine translates:

```
Pod: connect to 93.184.216.34 (example.com)
  -> DNS64 synthesizes AAAA: 64:ff9b::5db8:d822
  -> Pod sends IPv6 to 64:ff9b::5db8:d822
  -> NAT64 on node: IPv6 -> IPv4
  -> eBPF SNAT with node's IPv4 address
  -> Internet
```

This is identical to the base architecture.

### Outbound IPv6 (No SNAT in GUA Mode)

With GUA pod addresses, outbound IPv6 to the internet requires no
translation:

```
Pod (3fff:1234:0001:0001::a) -> connect to [2607:f8b0:4004::200e]:443
  -> Native IPv6 routing
  -> No SNAT, no NAT64, no translation of any kind
  -> Google sees source = 3fff:1234:0001:0001::a
  -> Return traffic routes directly back to pod
```

**No translation overhead for IPv6-to-IPv6 communication.** This is the
primary performance benefit of globally routable pods.

In ULA mode, outbound IPv6 to the internet requires SNAT at the site
border because ULA addresses are not globally routable. See
[EGRESS.md §3](EGRESS.md#3-nptv6-stateless-ipv6-prefix-translation) for the
NPTv6-based egress path that replaces per-flow SNAT with stateless prefix
translation.

### Inbound IPv4 to Pods

For services that need to accept IPv4 connections from the internet, use a
dedicated IPv4/IPv6 edge translator (NAT46/SIIT-DC/reverse proxy) to
translate inbound IPv4 to the pod's GUA IPv6:

```
Internet client (93.184.216.1) -> edge gateway IPv4 VIP
  -> IPv4/IPv6 translation at edge (deployment-specific mechanism)
  -> Forward to pod's GUA IPv6 address
  -> Pod receives connection from translated IPv6 source per edge policy
  -> Pod responds (IPv6 return path through edge translator)
  -> Edge gateway translates back to IPv4
  -> Internet client receives response
```

For services that only need IPv6 ingress, no gateway is needed -- clients
connect directly to the pod's GUA address.

---

## 10. Cross-Cluster Connectivity and Signaling Gateway

### Signaling Gateway Model

The gateway is a **signaling waypoint** for cross-cluster peer resolution,
NOT a data-plane relay for ongoing traffic. This is the critical distinction
from traditional VPN gateway architectures:

| Aspect | Traditional VPN Gateway | Wirescale Signaling Gateway |
|--------|------------------------|----------------------------|
| Data forwarding | All cross-site traffic flows through gateway | Only initial packets (until direct tunnel) |
| Throughput bottleneck | Yes -- gateway capacity limits cross-site BW | No -- direct tunnels bypass gateway |
| Gateway failure impact | All cross-site traffic drops | Only new peer resolution; existing tunnels survive |
| Scaling | Gateway must scale with total cross-site traffic | Gateway scales with peer resolution rate |
| Encryption termination | Gateway decrypts and re-encrypts | End-to-end between communicating hosts |

### Cross-Cluster Resolution Flow

When a node in Cluster 1 first needs to communicate with a host in
Cluster 2:

```
1. Node agent (Cluster 1) detects packet to 3fff:1234:0002:0042::/64
   - Matches aggregate route: 3fff:1234:0002::/48 via gateway
   - Packet reaches local gateway

2. Local gateway identifies this as a cross-cluster destination
   - Forwards resolution request to Cluster 1 controller

3. Cluster 1 controller queries global directory
   - "Which controller handles 3fff:1234:0002::/48?"
   - Global directory responds: Cluster 2 controller endpoint

4. Cluster 1 controller contacts Cluster 2 controller (mutual TLS)
   - "Peer info for host owning 3fff:1234:0002:0042::/64?"

5. Cluster 2 controller responds
   - Host public key, endpoint rack address, allowed-ips

6. Cluster 1 controller relays to node agent

7. Node agent establishes direct WireGuard tunnel
   - wg set wg0 peer <pubkey> endpoint [remote-addr]:51820 \
         allowed-ips 3fff:1234:0002:0042::/64
   - ip -6 route add 3fff:1234:0002:0042::/64 dev wg0

8. Direct tunnel active
   - All subsequent traffic to 3fff:1234:0002:0042::/64 goes direct
   - Gateway is no longer in the data path
```

### Gateway Responsibilities

The signaling gateway handles:

1. **Initial packet interception:** Receives packets matching the aggregate
   route and triggers resolution. During resolution, packets MAY be queued
   or the gateway MAY forward them via a default tunnel to the remote
   cluster gateway (for low-latency first-packet delivery).

2. **Resolution coordination:** Works with the local controller to resolve
   the remote host's peer information via the global directory.

3. **NAT traversal assistance:** For nodes behind NAT or restrictive
   firewalls that cannot establish direct tunnels, the gateway CAN relay
   traffic. This is the exceptional case, not the common path.

4. **Health monitoring:** Monitors the availability of direct tunnels and
   falls back to gateway relay if a direct tunnel fails and cannot be
   re-established.

### Gateway Sizing

Because the gateway handles signaling, not bulk data forwarding, it
requires minimal resources:

```
Resolution rate (typical): 10-100 new peer resolutions per second
Resolution cost: ~1 ms CPU per resolution (TLS handshake + lookup)
Gateway CPU: single core handles 1000+ resolutions/second
Gateway memory: connection tracking for active resolutions only

Contrast with data-relay gateway:
  Cross-cluster traffic: potentially 100+ Gbps aggregate
  Would require: dedicated high-throughput hardware, multiple NICs
  Wirescale avoids this entirely via direct tunnels.
```

### NAT and Restricted Environments

For nodes that cannot establish direct WireGuard tunnels (e.g., behind
CGNAT, restrictive firewalls, or asymmetric routing):

1. The agent attempts direct tunnel establishment as normal.
2. If the direct tunnel fails (no handshake completion within timeout),
   the agent falls back to **gateway relay mode**.
3. In relay mode, the gateway forwards data-plane traffic between the
   two nodes. This incurs the traditional gateway bottleneck but only
   for the specific unreachable nodes.
4. The agent periodically re-attempts direct tunnel establishment. If
   the network condition changes, the agent upgrades to direct tunnel
   and removes the relay.

Gateway relay SHOULD be treated as an exceptional condition. Operators
SHOULD monitor the fraction of traffic using relay mode and investigate
nodes that consistently require it.

### Control Federation (Mutual TLS)

Cross-cluster peer resolution requires controllers from different clusters
to communicate. This is secured via **mutual TLS with certificates anchored
to a shared root CA:**

```
Cluster 1 Controller                    Cluster 2 Controller
  |                                       |
  |  mutual TLS (certificates from        |
  |  shared root CA, per-cluster          |
  |  client/server certs)                 |
  |-------------------------------------->|
  |  "Peer info for /64 in your cluster?" |
  |                                       |
  |<--------------------------------------|
  |  "Here: pubkey, endpoint, allowed-ips"|
```

Trust boundaries:
- A controller MUST only provide peer information for nodes in its own
  cluster.
- A controller MUST validate that the requesting controller is a
  legitimate peer (certificate validation against shared root CA).
- The global directory MUST authenticate controller registrations and
  MUST NOT allow one cluster's controller to register prefixes belonging
  to another cluster.

### Hybrid: GUA Cluster + ULA Remote

A remote environment without globally routable IPv6 (e.g., a developer
office behind a residential ISP) can still join the fleet using ULA
addressing with WireGuard tunnels:

```
Cluster 1 (DC, GUA):     3fff:1234:0001::/48   (native routing)
Remote office (ULA):      fd00:1234:00ff::/48    (WireGuard overlay)

Gateway peers:
  Cluster 1 gateway -> WireGuard -> Remote office VPN endpoint
  AllowedIPs = fd00:1234:00ff::/48

Pods in Cluster 1 reach office pods via WireGuard through gateway.
Office pods reach Cluster 1 pods via WireGuard (encrypted, NATed if needed).
```

### External Peers (Unchanged)

External peers (developer laptops, CI runners) use `WirescaleExternalPeer`
CRDs exactly as in the base architecture. They connect via WireGuard to
a gateway node regardless of whether the cluster uses GUA or ULA internally.

---

## 11. Scaling Analysis

### Per-Node Routing State

The fundamental scaling property of the hierarchical design is that per-node
routing state is bounded by local cluster size plus the number of remote
clusters, NOT by the total number of hosts in the fleet:

```
Per-node routes = local_host_routes + remote_cluster_aggregates + active_direct_overrides

Where:
  local_host_routes        = O(hosts_in_cluster)     ~1K-10K
  remote_cluster_aggregates = O(clusters)             ~10-100
  active_direct_overrides   = O(active_remote_peers)  ~10-100 (bounded by workload)
```

### Comparison: Flat vs Hierarchical

| Scale | Flat /64 (all routes global) | Hierarchical (/64 local, /48 cross-cluster) |
|-------|------------------------------|---------------------------------------------|
| 1K hosts, 1 cluster | 1,000 routes/node | 1,000 routes/node |
| 10K hosts, 1 cluster | 10,000 routes/node | 10,000 routes/node |
| 10K hosts, 10 clusters (1K each) | 10,000 routes/node | 1,000 + 9 = 1,009 routes/node |
| 50K hosts, 10 clusters (5K each) | 50,000 routes/node | 5,000 + 9 = 5,009 routes/node |
| 100K hosts, 10 clusters (10K each) | 100,000 routes/node | 10,000 + 9 = 10,009 routes/node |
| 100K hosts, 100 clusters (1K each) | 100,000 routes/node | 1,000 + 99 = 1,099 routes/node |
| 500K hosts, 50 clusters (10K each) | 500,000 routes/node | 10,000 + 49 = 10,049 routes/node |

At 500K hosts with flat distribution, every node carries 500K routes.
With hierarchical aggregation, nodes carry ~10K routes. This is a 50x
reduction in per-node routing state.

### WireGuard Peer State

WireGuard peer state follows the same bounded pattern:

| Communication Pattern | Intra-Cluster Peers | Cross-Cluster Peers | Total |
|----------------------|--------------------|--------------------|-------|
| Service talking to 20 local + 5 remote hosts | 20 | 5 | 25 |
| Service talking to 100 local + 30 remote hosts | 100 | 30 | 130 |
| Maximum active peers (practical ceiling) | ~500 | ~200 | ~700 |

Per-node WireGuard state is O(active_peers), independent of fleet size.

### Control Plane Load

| Operation | Frequency | Cost |
|-----------|-----------|------|
| Intra-cluster /64 route update | Per host add/remove | O(1) per node (fabric BGP handles) |
| Cross-cluster aggregate update | Per cluster add/remove | O(1) per node (controller push) |
| Peer resolution (intra-cluster) | Per new communication pair | Controller lookup: ~1 ms |
| Peer resolution (cross-cluster) | Per new cross-cluster pair | Directory + controller lookup: ~5-50 ms |
| Peer GC | Per idle timeout | Local only: ~0 ms |

The control plane load is proportional to **peer churn** (new communication
pairs being established and torn down), not to cluster size or fleet size.
A fleet of 100K hosts where each node talks to 50 peers has the same
control plane load as a fleet of 10K hosts where each node talks to 50
peers.

### Fabric Routing Table (Within-Cluster)

The /64-per-host model keeps fabric routing state proportional to host
count, never pod count:

| Scale | Host /64 Routes | Per-Pod Routes in Fabric | Fabric Impact |
|-------|----------------|--------------------------|---------------|
| 100 hosts x 100 pods | 100 | 0 | Trivial for any ToR |
| 1,000 hosts x 100 pods | 1,000 | 0 | Standard single-site fabric |
| 10,000 hosts x 100 pods | 10,000 | 0 | Routine for modern spine/leaf |

Per-pod /128 routes exist only in the host kernel's local routing table
(installed by the CNI). They are **never** advertised into fabric BGP --
the covering /64 is sufficient.

Compare this to CNI implementations that push per-pod routes into the
fabric:

| Approach | 10K Hosts x 100 Pods | 100K Hosts x 100 Pods |
|----------|---------------------|-----------------------|
| /64-per-host (Wirescale) | 10K routes | 100K routes |
| Per-pod /128 in fabric | 1M routes | 10M routes (unworkable) |
| Full-mesh overlay (AllowedIPs) | 10K entries per node | 100K entries per node |

At 10 million routes, fabric BGP convergence times become unacceptable
and FIB memory on switching ASICs is exhausted. The /64-per-host model
avoids this entirely: the fabric MUST only carry /64 covering routes,
never individual /128 pod routes.

### WAN Routing Table (Cross-Cluster)

The hierarchical model applies the same aggregation principle to WAN
routing:

| Scale | Flat (all /64s on WAN) | Hierarchical (/48 per cluster on WAN) |
|-------|------------------------|---------------------------------------|
| 3 clusters, 30K hosts | 30,000 WAN routes | 3 WAN routes |
| 10 clusters, 100K hosts | 100,000 WAN routes | 10 WAN routes |
| 50 clusters, 500K hosts | 500,000 WAN routes | 50 WAN routes |

WAN routing at O(clusters) is trivial for any backbone. WAN routing at
O(hosts) is impractical at scale.

---

## 12. Packet Flow Walkthroughs

### Case 1: Pod-to-Pod, Same Node

```
Pod A (3fff:1234:0001:0001::a) -> Pod B (3fff:1234:0001:0001::b)
  |
  | eth0 -> veth_A -> host kernel routing
  | route: 3fff:1234:0001:0001::b/128 dev veth_B
  | -> veth_B -> Pod B eth0
  |
  | No WireGuard. No eBPF translation. Pure kernel forwarding.
  | Latency: ~2-5 us. Throughput: limited by veth, ~40+ Gbps.
```

### Case 2: Pod-to-Pod, Same Rack, Different Node (Same Cluster)

```
Pod A on host-1 (3fff:1234:0001:0001::a) -> Pod C on host-2 (3fff:1234:0001:0002::1)
  Both hosts are on rack 1: 3fff:1234:0001:ff01::/64
  |
  | eth0 -> veth -> host-1 routing
  | route: 3fff:1234:0001:0002::/64 via 3fff:1234:0001:ff01::12 dev eth0
  |   (installed by fabric BGP, next-hop = host-2's rack address)
  |   (host-2 is on the same L2 segment, so this is a single hop)
  v
  Physical NIC -> rack L2 switch -> host-2 physical NIC
  |
  | host-2 routing: 3fff:1234:0001:0002::1/128 dev veth_C
  | -> veth_C -> Pod C eth0
  |
  | No WireGuard. No encapsulation. Single L2 hop. Line rate.
```

### Case 3: Pod-to-Pod, Different Rack, Same Cluster

```
Pod A on host-1/rack-1 (3fff:1234:0001:0001::a)
  -> Pod D on host-3/rack-2 (3fff:1234:0001:0003::5)
  host-1 rack: 3fff:1234:0001:ff01::11
  host-3 rack: 3fff:1234:0001:ff02::11
  |
  | eth0 -> veth -> host-1 routing
  | route: 3fff:1234:0001:0003::/64 via 3fff:1234:0001:ff01::1 dev eth0
  |   (fabric BGP: ToR-1 learned host-3's /64 from ToR-2 via spine)
  v
  Physical NIC -> ToR-1 -> spine -> ToR-2 -> host-3 physical NIC
  |
  | host-3 routing: 3fff:1234:0001:0003::5/128 dev veth_D
  | -> veth_D -> Pod D eth0
  |
  | No WireGuard. Standard L3 fabric routing. Line rate.
```

### Case 4: Pod-to-Pod, Cross-Cluster, Cold Path (Signaling Resolution)

```
Pod A in Cluster-1 (3fff:1234:0001:0001::a)
  -> Pod X in Cluster-2 (3fff:1234:0002:0042::7)
  host-1 rack: 3fff:1234:0001:ff01::11
  No existing WireGuard peer for Cluster-2 host-42
  |
  | eth0 -> veth -> eBPF checks encrypt_map
  | 3fff:1234:0002::/48 -> require_encryption = true
  | No wg0 peer for 3fff:1234:0002:0042::/64 specifically
  | Packet matches aggregate route: 3fff:1234:0002::/48 via gateway
  v
  Packet reaches local gateway (signaling waypoint):
  | Gateway triggers peer resolution via controller
  | Controller queries global directory -> Cluster-2 controller
  | Cluster-2 controller responds: host-42 pubkey + rack addr
  | Controller relays to node agent on host-1
  v
  Agent on host-1 establishes direct WireGuard tunnel:
  | wg set wg0 peer <host42-pubkey> \
  |     endpoint [3fff:1234:0002:ff01::42]:51820 \
  |     allowed-ips 3fff:1234:0002:0042::/64
  | ip -6 route add 3fff:1234:0002:0042::/64 dev wg0
  v
  Queued packet released -> wg0 encrypts -> direct to host-42
  |
  | Cold path latency: ~10-50 ms (signaling round-trip + peer setup)
  | Amortized over connection lifetime -- subsequent packets are warm.
```

### Case 5: Pod-to-Pod, Cross-Cluster, Warm Path (Direct Tunnel)

```
Pod A in Cluster-1 (3fff:1234:0001:0001::a)
  -> Pod X in Cluster-2 (3fff:1234:0002:0042::7)
  Direct WireGuard tunnel to host-42 already established
  |
  | eth0 -> veth -> eBPF checks encrypt_map
  | 3fff:1234:0002::/48 -> require_encryption = true
  | bpf_redirect(wg0_ifindex)
  v
  wg0 on host-1:
  | peer: host-42 in Cluster-2, AllowedIPs = 3fff:1234:0002:0042::/64
  | encrypt -> UDP from [3fff:1234:0001:ff01::11]
  |            to [3fff:1234:0002:ff01::42]:51820
  v
  Physical NIC -> fabric -> WAN/backbone -> Cluster-2 fabric -> host-42
  |
  | wg0 on host-42: decrypt
  | -> kernel routing: 3fff:1234:0002:0042::7/128 dev veth_X
  | -> veth_X -> Pod X
  |
  | Direct tunnel. No gateway in the data path. WireGuard-limited throughput.
```

### Case 6: Pod to Internet (IPv6, Zero Overhead)

```
Pod A (3fff:1234:0001:0001::a) -> google.com [2607:f8b0:4004::200e]:443
  |
  | eth0 -> veth -> host routing
  | route: ::/0 via 3fff:1234:0001:ff01::1 (default via ToR)
  v
  Physical NIC -> ToR -> spine -> border -> internet
  |
  | No SNAT. No NAT64. No WireGuard. No translation.
  | Google sees source = 3fff:1234:0001:0001::a (pod's GUA)
  | Return traffic routes: border -> spine -> ToR -> host-1 -> pod
  |   (ToR knows 3fff:1234:0001:0001::/64 -> host-1 via fabric BGP)
  |
  | THIS IS THE IDEAL PATH. Zero overhead. Line rate.
```

### Case 7: Pod to Internet (IPv4 via NAT64)

```
Pod A (3fff:1234:0001:0001::a / 100.64.1.10) -> example.com (93.184.216.34)
  |
  | App calls connect("93.184.216.34", 80) -- IPv4 socket
  | clat0 TUN: IPv4 -> IPv6
  |   src: 3fff:1234:0001:0001::a
  |   dst: 64:ff9b::5db8:d822
  v
  eth0 -> veth -> host routing
  | route: 64:ff9b::/96 -> nat64 interface
  v
  nat64 eBPF: IPv6 -> IPv4
  | eBPF SNAT: src = host's public IPv4
  | dst = 93.184.216.34
  v
  Physical NIC -> internet (IPv4)
```

### Case 8: Internet to Pod (Explicit Ingress)

```
Client [2607:f8b0::1]:54321 -> Pod web (3fff:1234:0001:0001::a):443
  |
  | Internet -> border -> spine -> ToR-1
  | ToR-1 fabric BGP: 3fff:1234:0001:0001::/64 via host-1 rack addr
  | -> host-1 NIC (on rack /64)
  v
  XDP ingress firewall on eth0:
  | dst = 3fff:1234:0001:0001::a (matches local pod /64)
  | src = 2607:f8b0::1 (external -- not in any cluster prefix)
  | Check external_ingress_map: port 443, app=web-frontend -> ALLOW
  v
  Kernel routing: 3fff:1234:0001:0001::a/128 dev veth_web -> Pod eth0
  |
  | Pod handles TLS, responds
  | Return: src=3fff:1234:0001:0001::a -> veth -> host routing -> eth0
  |   -> ToR -> spine -> border -> internet (no SNAT needed)
```

### Case 9: Cross-Cluster, Tunnel GC'd, Re-Resolution

```
Pod A (Cluster-1) had a direct tunnel to host-42 (Cluster-2).
Tunnel was idle for > 5 minutes and was GC'd.
  |
  | Agent removes: wg set wg0 peer <host42-pubkey> remove
  | Agent removes: ip -6 route del 3fff:1234:0002:0042::/64 dev wg0
  |
  | Later, Pod A sends to Pod X on host-42 again:
  | -> Matches aggregate: 3fff:1234:0002::/48 via gateway
  | -> Cold path resolution repeats (Case 4)
  | -> New direct tunnel established, new /64 override installed
  |
  | Total cost of re-resolution: ~10-50 ms (one-time per reconnection)
```

---

## 13. Security: Internet-Routable Pods

### The Critical Difference

With ULA pods behind a WireGuard overlay, pods are invisible to the
internet by construction. With GUA pods, **every pod is reachable from
the internet** unless routing and firewalls block it. This makes policy
enforcement **mandatory for basic security.**

### Mandatory Default-Deny

Recommended baseline in GUA mode: install a cluster-wide default-deny
ingress policy for all pods:

```yaml
# Example baseline policy (cluster operator applied)
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: wirescale-default-deny-ingress
  namespace: "" # cluster-scoped, applies to all namespaces
  labels:
    wirescale.io/system: "true"
    wirescale.io/auto-generated: "true"
spec:
  podSelector: {}   # all pods
  policyTypes:
    - Ingress
  # No ingress rules = deny all inbound by default
```

When this baseline is enabled:
- Pod-to-pod communication within the cluster: **blocked** until explicitly
  allowed by a WirescalePolicy or NetworkPolicy
- Inbound from the internet: **blocked** by default
- Outbound from pods: **allowed** by default (can be restricted per-policy)

Operational requirement:
- Production deployments with internet-routable pod prefixes MUST enforce
  explicit ingress policy before exposing workloads externally.
- Platform defaults SHOULD include cluster-wide deny-baseline policy and
  narrowly scoped allow rules.

### Ingress Firewall (eBPF on Physical NIC)

In addition to per-pod policy on veths, the agent installs an XDP program
on the physical NIC that drops traffic to pod addresses from outside the
cluster unless it matches an explicit allow rule:

```c
SEC("xdp")
int wirescale_ingress_firewall(struct xdp_md *ctx) {
    struct ipv6hdr *ip6 = parse_ipv6(ctx);
    if (!ip6) return XDP_PASS;

    // Is destination a local pod address?
    if (!is_local_pod_prefix(ip6->daddr))
        return XDP_PASS;  // not our concern

    // Is source from within the cluster?
    if (is_cluster_prefix(ip6->saddr))
        return XDP_PASS;  // intra-cluster, handled by pod policy

    // External source -> pod: check ingress allow map
    struct ingress_key key = {
        .dst_prefix = ip6->daddr & pod_mask,
        .dst_port = parse_dst_port(ctx),
        .protocol = ip6->nexthdr,
    };

    struct ingress_value *val = bpf_map_lookup_elem(
        &external_ingress_map, &key);

    if (val && val->action == ALLOW)
        return XDP_PASS;

    // Default: drop external traffic to pods
    return XDP_DROP;
}
```

This XDP firewall runs at line rate (14-26 Mpps per core) and protects
pods before traffic even reaches the kernel stack.

### Exposing Services (Explicit Ingress)

To allow external traffic to reach a pod, a `WirescalePolicy` with
external ingress MUST be created:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: allow-web-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-frontend
  ingress:
    - from:
        - ipBlock:
            cidr: "::/0"         # allow from anywhere (IPv6)
        - ipBlock:
            cidr: "64:ff9b::/96" # allow from NAT64'd IPv4 clients
      ports:
        - protocol: TCP
          port: 443
```

The controller compiles this into XDP map entries on the relevant nodes,
opening port 443 inbound only for pods matching `app=web-frontend`.

### Rate Limiting and DDoS Protection

With internet-routable pods, DDoS becomes a concern. The XDP ingress
firewall supports per-destination rate limiting:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: rate-limited-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: public-api
  ingress:
    - from:
        - ipBlock:
            cidr: "::/0"
      ports:
        - protocol: TCP
          port: 443
      rateLimit:
        packetsPerSecond: 10000
        burstSize: 50000
        perSource: true           # per source /64
```

The rate limiter runs in XDP using a BPF `LRU_HASH` map keyed by source
/64 prefix, providing per-source-network rate limiting at line rate.

### Cross-Cluster Security Boundaries

The hierarchical model introduces additional security boundaries:

1. **Intra-cluster:** Standard pod policy (eBPF on veths). No encryption
   required by default (trusted fabric).

2. **Cross-cluster, same organization:** Authenticated via control
   federation (mutual TLS). Encrypted via direct WireGuard tunnels.
   Policy enforced at both endpoints.

3. **Cross-cluster, different organizations:** NOT supported without
   explicit federation configuration. The global directory MUST NOT
   automatically federate with unknown clusters.

Each boundary layer adds authentication and authorization checks. A
packet crossing from Cluster 1 to Cluster 2 passes through:
- Egress pod policy on source host (eBPF)
- WireGuard encryption (authentication via public key)
- Ingress pod policy on destination host (eBPF)
- Cross-cluster authorization (controller validated peer request)

---

## 14. Deployment Topologies

### Single Cluster, Bare Metal with Fabric BGP (Simplest)

```
Best for: Single-site production, 1K-10K hosts
Routing: Fabric-managed BGP (eBGP host-to-ToR)
Encryption: never or cross-site
State per node: O(hosts) -- all /64s in the cluster
Wirescale's role: IPAM, pod addressing, encryption, policy

Requires: BGP-capable fabric, /48 per cluster
No global directory needed for single-cluster deployments.
```

### Multi-Cluster, Single Site

```
Best for: Multiple teams or environments sharing a datacenter
Routing: Fabric BGP within each cluster + aggregate routes between clusters
Encryption: cross-cluster (different trust domains on shared fabric)
State per node: O(local_hosts + clusters)
Control: controller per cluster + global directory

Example:
  Cluster-Prod:  3fff:1234:0001::/48   (5K hosts)
  Cluster-Stage: 3fff:1234:0002::/48   (1K hosts)
  Cluster-Dev:   3fff:1234:0003::/48   (500 hosts)

  Each node in Cluster-Prod: 5,000 /64 routes + 2 aggregate routes
  Total state: ~5,002 routes (not 6,500)
```

### Multi-Cluster, Multi-Site

```
Best for: Geo-distributed production, 10K-100K+ hosts
Routing: Fabric BGP per site, /48 per cluster on WAN
Encryption: cross-cluster with direct tunnels after resolution
Control: controller per cluster + global directory (replicated multi-region)
State per node: O(local_hosts + clusters)

Example (3 sites, 10 clusters, 100K total hosts):
  DC-East:  Cluster 1-3  (30K hosts across 3 clusters)
  DC-West:  Cluster 4-6  (40K hosts across 3 clusters)
  DC-South: Cluster 7-10 (30K hosts across 4 clusters)

  Node in Cluster-1 (10K hosts):
    10,000 local /64 routes + 9 aggregate routes = 10,009 total
    Not: 100,000 global routes
```

### Cloud (AWS/GCP) with VPC Routing

```
Best for: Cloud-native deployments
Routing: Cloud provider fabric (ENI prefix delegation on AWS,
         /96 from subnet on GCP, or custom routes via cloud API)
Encryption: always or cross-VPC (cloud fabric may not be trusted)
IPv4: Dual-stack via cloud provider + NAT64 for gaps
MTU: 1500 (common cloud default) or up to 9001 on AWS ENA

Note: Not all clouds support /64-per-host. AWS gives /80 per ENI.
      GCP gives /96 per NIC. Wirescale adapts to whatever prefix
      length the cloud provides.
```

### Single Rack / Lab

```
Best for: Development, testing, small deployments
Routing: All hosts on one L2 segment, static routes or single ToR
Encryption: never or always (depending on trust model)
IPv4: NAT64 or dual-stack
MTU: 9000

Simplest deployment -- all pods reachable via L2 or single router hop.
```

### Hyperscale (100K+ Hosts, Multi-Cluster, Multi-Region)

```
Best for: Large-scale production, planet-scale
Routing: Fabric BGP per cluster, /48 per cluster on WAN backbone
Encryption: cross-cluster with direct tunnels (signaling gateway model)
Control: controller per cluster + global directory (multi-region HA)
State per node: O(local_hosts + clusters)

Scaling properties:
  Fabric routes per cluster:    1 x /64 per host (10K hosts = 10K routes)
  WAN routes per site:          1 x /48 per cluster (50 clusters = 50 routes)
  WireGuard peers per node:     only active communication partners (~50-200)
  Control plane load:           proportional to peer churn, not fleet size
  Cross-cluster trust:          mutual TLS federation via global directory

Requires:
  - Fabric-managed BGP at each site (standard spine/leaf)
  - wirescale-controller per cluster
  - Global directory (replicated across regions)
  - /48 per cluster from provider-assigned GUA space (or /32 ULA)
  - Signaling gateways per cluster (2-3 for HA)
```

---

## 15. Comparison: ULA Overlay vs Hierarchical GUA

| Property | ULA + WG Overlay | Flat GUA + Native | Hierarchical GUA + On-Demand |
|----------|-----------------|-------------------|------------------------------|
| **Intra-cluster pod-to-pod** | WireGuard (3-10 Gbps/core) | Line rate (native IPv6) | Line rate (native IPv6) |
| **Cross-cluster pod-to-pod** | WireGuard (static peers) | WireGuard (static peers) | WireGuard (direct tunnel, on-demand) |
| **Pod to IPv6 internet** | SNAT required | Direct, no SNAT | Direct, no SNAT |
| **Pod to IPv4 internet** | CLAT + NAT64 | CLAT + NAT64 | CLAT + NAT64 |
| **Internet to pod** | Not possible (proxy) | Direct (with policy) | Direct (with policy) |
| **Routing state per node** | O(N) -- AllowedIPs | O(global_hosts) -- all /64s | O(local_hosts + clusters) |
| **WireGuard state per node** | O(N) -- peer per node | O(N) or O(gateways) | O(active_peers) -- bounded |
| **WAN routing table** | N/A (overlay) | O(global_hosts) -- /64 per host | O(clusters) -- /48 per cluster |
| **Cross-cluster data path** | Via gateway (relay) | Via gateway (relay) | Direct tunnel (gateway off path) |
| **Gateway throughput** | Must handle all cross-site BW | Must handle all cross-site BW | Signaling only (minimal) |
| **Control plane** | K8s API (watch all nodes) | K8s API (IPAM only) | 3-tier: directory + controller + agent |
| **Cold path latency** | WireGuard handshake | N/A (static routes) | +10-50 ms (signaling resolution) |
| **Max practical scale** | ~1K nodes (O(N^2) state) | ~10K nodes (flat routing) | 100K+ nodes (hierarchical) |
| **Best for** | Hostile/shared networks | Single-cluster, bare metal | Multi-cluster, hyperscale |

### When to Use Which

**Use ULA + WireGuard Overlay when:**
- Running on shared/untrusted infrastructure (public cloud, multi-tenant)
- No control over the network fabric (can't get pod /64 routes installed)
- IPv6 globally routable space not available
- Maximum security is more important than maximum performance
- Small scale (< 1,000 nodes)

**Use Flat GUA + Native Routing when:**
- Single cluster, single site
- Full control over the network fabric (BGP routing for pod /64s)
- Performance is critical (financial trading, HPC, media streaming)
- No cross-cluster communication needed
- Scale up to ~10,000 nodes per cluster

**Use Hierarchical GUA + On-Demand Peering when:**
- Multiple clusters across one or more sites
- Operating at 10,000+ total nodes
- Per-node state MUST remain bounded regardless of fleet growth
- Cross-cluster encryption is required but gateway relay is a bottleneck
- The deployment spans multiple sites or regions
- Gateway should be signaling-only, not a data-plane chokepoint

**Use both simultaneously (hybrid) when:**
- Some clusters use GUA (datacenter, bare metal)
- Some environments use ULA (developer offices, restricted networks)
- Migrating from overlay to native routing incrementally
- Different clusters have different security requirements
