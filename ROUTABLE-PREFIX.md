# Wirescale: Globally Routable /64-per-Host Design

> What changes when every host in the fleet owns a dedicated /64 from
> globally routable address space, and how Wirescale adapts its
> architecture to exploit native IPv6 reachability.
>
> Status: design document for routable-prefix mode. Treat statements as target
> architecture unless explicitly tied to implementation artifacts.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

---

## Table of Contents

1. [The /64-per-Host Model](#1-the-64-per-host-model)
2. [What Changes from the Base Architecture](#2-what-changes-from-the-base-architecture)
3. [Address Architecture](#3-address-architecture)
4. [Routing: Fabric-Managed BGP](#4-routing-fabric-managed-bgp)
5. [WireGuard as Encryption-Only Layer](#5-wireguard-as-encryption-only-layer)
6. [Selective Encryption Modes](#6-selective-encryption-modes)
7. [IPv4 Compatibility in the GUA Model](#7-ipv4-compatibility-in-the-gua-model)
8. [Security: When Pods Are Internet-Routable](#8-security-when-pods-are-internet-routable)
9. [Multi-Site and Hybrid Connectivity](#9-multi-site-and-hybrid-connectivity)
10. [CNI Plugin Changes](#10-cni-plugin-changes)
11. [Packet Flow Walkthroughs](#11-packet-flow-walkthroughs)
12. [Deployment Topologies](#12-deployment-topologies)
13. [Comparison: ULA Overlay vs GUA Native](#13-comparison-ula-overlay-vs-gua-native)

---

## 1. The /64-per-Host Model

### Concept

Every host in the fleet receives a dedicated **/64 prefix** from globally
routable IPv6 address space (GUA -- Global Unicast Addresses, `2000::/3`).
Every pod on that host gets an address from the host's /64. These addresses
are internet-routable when route advertisement and perimeter policy allow it,
without NAT, tunnels, or overlays in the same-site native path.

```
Site allocation:     2001:db8:0a00::/48     (65,536 /64s available, documentation prefix)
  Host worker-1:     2001:db8:0a00:0001::/64
    Pod A:           2001:db8:0a00:0001::a/128
    Pod B:           2001:db8:0a00:0001::b/128
  Host worker-2:     2001:db8:0a00:0002::/64
    Pod C:           2001:db8:0a00:0002::1/128
  Host worker-3:     2001:db8:0a00:0003::/64
    ...
```

The /64 is the natural operational unit for IPv6 subnets: SLAAC on standard
Ethernet links expects a 64-bit IID, and many production designs optimize
around /64 boundaries. NDP itself is not /64-exclusive. A /64 provides 2^64
addresses per host -- more than enough for any conceivable pod density.

### Why This Matters

With globally routable pod addresses:
- **No overlay network needed for reachability** -- pods reach each other
  and the internet via native IP routing
- **No SNAT for outbound traffic** -- the pod's real address is preserved
  end-to-end
- **Direct inbound connectivity** -- external clients can reach pods
  directly (when policy allows)
- **WireGuard is optional for reachability** -- it becomes a pure
  encryption layer, activated only when confidentiality is required
- **Maximum performance** -- no encapsulation overhead for unencrypted
  same-site traffic

---

## 2. What Changes from the Base Architecture

The base ARCHITECTURE.md assumed ULA addresses (`fd12:3456:7800::/48`) with a
WireGuard overlay providing both reachability and encryption. The /64-per-
host model fundamentally restructures the data plane:

| Aspect | Base (ULA + WG Overlay) | /64-per-Host (GUA + Native Routing) |
|--------|------------------------|--------------------------------------|
| Pod IPv6 addresses | ULA (`fd12:3456:7800:N::P`) | GUA (`2001:db8:0a00:N::P`) |
| Inter-node reachability | WireGuard tunnel | Native IP routing (BGP) |
| Encryption | Always (WireGuard) | Selective (WireGuard when needed) |
| Internet reachability | Via NAT64 gateway | Direct (pods are globally routable) |
| Inbound from internet | Not possible without proxy | Direct to pod (filtered by policy) |
| Routing protocol | None (WireGuard AllowedIPs) | Fabric BGP (managed by network, not Wirescale) |
| SNAT for outbound | MASQUERADE at NAT64 | None (preserve pod source IP) |
| IPv4 for pods | CLAT -> NAT64 | CLAT -> NAT64 (unchanged) |
| Performance ceiling | WireGuard crypto throughput | Line rate (native forwarding) |
| Policy enforcement | eBPF on veth | eBPF on veth (now critical for security) |

### Components That Change

```
REMOVED:
  - WireGuard as routing overlay (for same-site traffic)
  - ULA address allocation

ADDED:
  - /64 prefix allocation from site CIDR
  - Ingress firewall (pods are internet-exposed)
  - Selective encryption policy (encrypt cross-site, optional same-site)

UNCHANGED:
  - wirescale-controller (IPAM, policy compilation, mesh topology)
  - wirescale-agent (eBPF policy, NAT64/CLAT, WireGuard for cross-site)
  - wirescale-cni (pod netns setup)
  - CRD model (WirescaleMesh, WirescaleNode, WirescalePolicy)
  - DNS architecture (CoreDNS + dns64)
  - IPv4 compatibility (CLAT + NAT64)
  - Fabric BGP routing (managed by the network, not Wirescale)
```

---

## 3. Address Architecture

### Allocation Hierarchy

```
Documentation prefix:    3fff:0a00::/48      (example only; replace in production)
  Site A (DC-East):      3fff:0a00::/48      (65,536 /64s)
    Rack /64s:           3fff:0a00:ff00::/56 (256 /64s, one per rack)
      Rack 1:            3fff:0a00:ff01::/64 (shared L2, all hosts in rack)
      Rack 2:            3fff:0a00:ff02::/64
      ...
    Pod /64s:            3fff:0a00:0000::/52 (4,096 /64s, one per host)
      worker-1:          3fff:0a00:0001::/64
      worker-2:          3fff:0a00:0002::/64
      ...
      worker-4096:       3fff:0a00:0fff::/64
    Services:            3fff:0a00:f000::/52 (service VIPs)

  Site B (DC-West):      3fff:0b00::/48
    ...
```

`3fff::/20` is currently designated for documentation/example usage. Replace
the example block above with provider-assigned production GUA ranges.

### Dual-Address Model: Rack /64 + Pod /64

Every host has **two IPv6 addresses from two different /64 prefixes**:

1. **Rack address (/128 from the rack's /64):** The host's identity on the
   data center fabric. All hosts in the same rack share one /64 on the L2
   segment connecting them to the ToR switch. Each host gets a single /128
   from this prefix. Used for: management, WireGuard endpoints,
   node-to-node communication, and as the BGP next-hop for the pod /64
   (configured by the fabric, not Wirescale).

2. **Pod prefix (dedicated /64):** A separate /64 routed to this host for
   pod addressing. Every pod on the host gets a /128 from this prefix.
   The fabric routes this prefix to the host (via BGP or static config).

```
Rack 1 (ToR-1):
  Rack /64:    3fff:0a:ff01::/64  (shared L2 segment)
  ToR switch:  3fff:0a:ff01::1/128

  Host worker-1:
    eth0 (rack):   3fff:0a:ff01::11/128  (from rack /64)
    Pod /64:       3fff:0a:0001::/64     (dedicated, routed to this host)
      gateway:     3fff:0a:0001::1
      Pod A:       3fff:0a:0001::a
      Pod B:       3fff:0a:0001::b

  Host worker-2:
    eth0 (rack):   3fff:0a:ff01::12/128  (from rack /64)
    Pod /64:       3fff:0a:0002::/64     (dedicated, routed to this host)
      gateway:     3fff:0a:0002::1
      Pod C:       3fff:0a:0002::1a

Rack 2 (ToR-2):
  Rack /64:    3fff:0a:ff02::/64
  ToR switch:  3fff:0a:ff02::1/128

  Host worker-3:
    eth0 (rack):   3fff:0a:ff02::11/128
    Pod /64:       3fff:0a:0003::/64
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
  WireGuard endpoint:  [3fff:0a:ff01::11]:51820  (rack address)
  wg0 has no IP assigned -- it's an encryption-only device
```

This means WireGuard peers use the rack address to reach each other,
while pod traffic is routed via the pod /64. The two address spaces serve
completely different purposes and never overlap.

### Pod Address Assignment

The CNI assigns addresses directly (no SLAAC, no DHCPv6):

```
IPAM strategy: sequential from pool, skip gateway and reserved

Pool:     3fff:0a:0001::a  through  3fff:0a:0001:ffff:ffff:ffff:ffff
Reserved: 3fff:0a:0001::0  (subnet-router anycast, RFC 4291)
          3fff:0a:0001::1  (host gateway)
          3fff:0a:0001::2  through ::9 (infrastructure, future use)
Available: ~18.4 quintillion addresses (2^64 - 10)
```

DAD (Duplicate Address Detection) is disabled on pod interfaces because the
IPAM is authoritative and no other device shares the link:

```bash
sysctl -w net.ipv6.conf.eth0.accept_dad=0    # inside pod netns
```

### IPv4 Addresses (CLAT, Unchanged)

IPv4 pod addresses still use the CGNAT range from the base architecture:

```
Pod IPv4 (CLAT):   100.64.N.P/32
Mapping:           100.64.N.P  <-->  3fff:0a:N::P
```

The mapping is now from CGNAT to GUA instead of CGNAT to ULA, but the
mechanism is identical: stateless CLAT translation at the pod veth.

---

## 4. Routing: Fabric-Managed BGP

### Assumption: The Fabric Handles BGP

Wirescale assumes the data center network fabric already manages BGP
routing for both the rack /64 and pod /64 prefixes. This is the standard
operating model in modern data center networks:

- **The rack /64** is a directly-connected L2 segment on the ToR. The
  ToR learns host addresses via NDP and has a connected route for the
  rack prefix. No configuration needed from Wirescale.

- **The pod /64** is routed to each host by the fabric. The ToR learns
  each host's pod /64 (next-hop = host's rack address) through the
  existing fabric BGP configuration -- eBGP from host to ToR, or static
  provisioning, or whatever mechanism the network team has deployed.

Wirescale does **not** embed a BGP speaker. The routing infrastructure
is managed by the network operations team using their existing tools
(BIRD, FRR, SONiC, Arista EOS, etc.). This is the right separation of
concerns:

| Responsibility | Owner |
|---------------|-------|
| Pod /64 allocation per host | Wirescale controller (IPAM) |
| Route advertisement (pod /64 → host) | Fabric BGP (network team) |
| Pod address assignment within /64 | Wirescale CNI |
| Per-pod /128 host routes | Wirescale CNI (local only, not in BGP) |
| Encryption policy | Wirescale agent |
| Pod network policy | Wirescale agent (eBPF) |

### Typical Fabric Topology

The fabric typically runs eBGP between each layer:

```
                    Spine switches (AS 65000)
                   /          |          \
                  /           |           \
        ToR-1 (AS 65001)  ToR-2 (AS 65002)  ToR-3 (AS 65003)
        3fff:0a:ff01::1   3fff:0a:ff02::1   3fff:0a:ff03::1
          |       |          |       |          |       |
       host-1  host-2    host-3  host-4     host-5  host-6
       ::11    ::12       ::11    ::12       ::11    ::12
```

Each host peers with its ToR (or uses static routes provisioned by the
fabric automation). The host advertises its pod /64 with its rack
address as the next-hop. The ToR aggregates and re-advertises upstream
to the spines. **All of this is outside Wirescale's scope.**

### What Wirescale Expects from the Fabric

For Wirescale to function correctly, the fabric must provide:

1. **Reachability for the rack /64:** Hosts on the same rack can reach
   each other via L2 (NDP) on the shared rack /64 segment.

2. **Route for each pod /64:** The fabric routes each host's pod /64
   (next-hop = host's rack address) so that any host in the site can
   reach any other host's pods via native IPv6 forwarding.

3. **Default route:** Each host has a default IPv6 route (typically
   learned from the ToR via RA or BGP) for internet egress.

The `WirescaleNode` CRD records each node's addressing for Wirescale's
own use (IPAM, encryption policy, WireGuard peer config) but does **not**
drive any BGP configuration:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleNode
metadata:
  name: worker-1
spec:
  rackAddress: "3fff:0a:ff01::11"     # host's address on rack /64
  podCIDR: "3fff:0a:0001::/64"        # host's dedicated pod /64
  site: "dc-east"                      # for encryption policy decisions
```

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

## 5. WireGuard as Encryption-Only Layer

### The Paradigm Shift

In the base architecture, WireGuard serves dual duty: routing overlay +
encryption. With globally routable /64s and fabric-managed routing, routing is native.
WireGuard's role shrinks to **transparent encryption** for traffic that
requires confidentiality.

This is how Cilium and Calico already use WireGuard in native routing
mode.

### Architecture

```
Pod A (3fff:0a:0001::a) on host-1 -> Pod B (3fff:0a:0002::b) on host-2
  host-1 rack addr: 3fff:0a:ff01::11
  host-2 rack addr: 3fff:0a:ff01::12

WITHOUT encryption (same-site, trusted fabric):
  Pod A -> veth -> host routing -> eth0 -> rack L2 -> host-2 eth0 -> veth -> Pod B
  (pure native IPv6, line rate, zero overhead)

WITH encryption (cross-site, or policy requires it):
  Pod A -> veth -> eBPF redirect -> wg0 -> encrypt -> eth0 (via rack addr)
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
| Same site /48 | No (default) | Trusted fabric |
| Remote site /48 | Yes | Cross-site = untrusted transit |
| External (::/0) | Policy-dependent | TLS may protect payload, but transport encryption requirements vary |
| Specific pod CIDR | Yes | Policy override (sensitive workload) |

### WireGuard Configuration (Encryption-Only Mode)

When WireGuard is encryption-only, its configuration is simpler:

```
[Interface]
ListenPort = 51820
PrivateKey = <generated-at-boot>
# No Address -- wg0 is not a routed interface, just an encryption hop
# Endpoint uses the host's rack address (3fff:0a:ff01::11)

[Peer]  # Remote site gateway
PublicKey = <site-B-gateway-key>
Endpoint = [3fff:0b:ff01::1]:51820   # Site B gateway's rack address
AllowedIPs = 3fff:0b::/48            # All of Site B's address space
```

Traffic doesn't "route through" wg0 in the normal sense. The eBPF program
explicitly redirects selected packets into wg0 for encryption, and wg0
delivers the encrypted UDP datagram out through the physical NIC. Return
traffic arrives as UDP on port 51820, WireGuard decrypts it, and the
kernel routes the inner packet to the destination pod.

---

## 6. Selective Encryption Modes

### WirescaleMesh Encryption Policy

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
metadata:
  name: default
spec:
  encryption:
    # Mode: "always" | "cross-site" | "never" | "policy"
    mode: cross-site

    # When mode is "cross-site", define site boundaries:
    sites:
      - name: dc-east
        prefixes: ["3fff:0a::/48"]
      - name: dc-west
        prefixes: ["3fff:0b::/48"]
    # Traffic within a site: unencrypted (native routing)
    # Traffic between sites: WireGuard encrypted

    # When mode is "policy", encryption is per-WirescalePolicy:
    # Each WirescalePolicy can set `encryption: required`
```

### Mode Details

**`always`:** All inter-node pod traffic goes through WireGuard, even
same-site. Equivalent to the base architecture. Maximum security, lower
performance for same-site traffic.

**`cross-site`:** Same-site traffic routes natively (line rate). Cross-site
traffic is encrypted via WireGuard. This is the recommended default for
multi-site deployments. Assumes the intra-site fabric is trusted (or
protected by MACsec at the switch level).

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

### Performance Impact by Mode

| Mode | Same-Site Throughput | Cross-Site Throughput | CPU Overhead |
|------|---------------------|-----------------------|-------------|
| `never` | Line rate | Line rate (if direct path) | Minimal |
| `cross-site` | Line rate | WireGuard limited (~10G/core) | Cross-site only |
| `policy` | Line rate (unless policy says encrypt) | Varies | Per-flow |
| `always` | WireGuard limited | WireGuard limited | Every inter-node packet |

---

## 7. IPv4 Compatibility in the GUA Model

The IPv4 compatibility story changes slightly with globally routable pods.

### CLAT (Per-Pod IPv4)

Unchanged from the base architecture. Every pod gets a CLAT `clat0`
interface with a CGNAT IPv4 address. The deterministic mapping is:

```
100.64.N.P  <-->  3fff:0a:N::P
```

The only difference: the IPv6 side is now a GUA instead of ULA. The eBPF
CLAT program doesn't care -- it maps between two fixed addresses regardless
of their scope.

### NAT64 (External IPv4 Destinations)

For reaching IPv4-only internet hosts, the NAT64 engine still translates:

```
Pod: connect to 93.184.216.34 (example.com)
  -> DNS64 synthesizes AAAA: 64:ff9b::5db8:d822
  -> Pod sends IPv6 to 64:ff9b::5db8:d822
  -> NAT64 on node: IPv6 -> IPv4
  -> MASQUERADE with node's IPv4 address
  -> Internet
```

This is identical to the base architecture.

### Outbound IPv6 (No SNAT!)

This is the major improvement. In the base architecture, outbound IPv6
to the internet required SNAT because ULA addresses are not routable.
With GUA pod addresses:

```
Pod (3fff:0a:0001::a) -> connect to [2607:f8b0:4004::200e]:443 (google.com)
  -> Native IPv6 routing
  -> No SNAT, no NAT64, no translation of any kind
  -> Google sees source = 3fff:0a:0001::a
  -> Return traffic routes directly back to pod
```

**No translation overhead for IPv6-to-IPv6 communication.** This is the primary
performance benefit of globally routable pods.

### Inbound IPv4 to Pods

For services that need to accept IPv4 connections from the internet, use a
dedicated IPv4/IPv6 edge translator (for example NAT46/SIIT-DC/reverse proxy)
to translate inbound IPv4 to the pod's GUA
IPv6:

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

## 8. Security: When Pods Are Internet-Routable

### The Critical Difference

With ULA pods behind a WireGuard overlay, pods are invisible to the
internet by construction. With GUA pods, **every pod is reachable from
the internet** unless routing and firewalls block it. This makes policy
enforcement not just
important but **mandatory for basic security.**

### Mandatory Default-Deny

Recommended baseline in GUA mode: install a cluster-wide default-deny ingress
policy for all pods:

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
external ingress must be created:

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

---

## 9. Multi-Site and Hybrid Connectivity

### Cross-Site Architecture

The /64-per-host model shines in multi-site deployments. Each site has
its own /48. Within a site, pods route natively. Between sites, WireGuard
encrypts the transit:

```
Site A (DC-East)                    Site B (DC-West)
3fff:0a::/48                    3fff:0b::/48
  |                                   |
  +-- gateway-a                       +-- gateway-b
  |   WireGuard peer: gateway-b       |   WireGuard peer: gateway-a
  |   Cross-site encrypted transit    |   Cross-site encrypted transit
  |                                   |
  +-- worker-1..100                   +-- worker-1..100
      Fabric routes pod /64s              Fabric routes pod /64s
      Native routing within site          Native routing within site
```

### Site Gateways

Each site has 2-3 gateway nodes (for HA) that:
1. Peer with all other sites' gateways via WireGuard
2. Advertise the remote site's /48 as reachable through themselves
   (the fabric routes cross-site traffic to the gateway)
3. Act as transit routers for cross-site pod traffic

The gateway's WireGuard config (using rack addresses as endpoints):

```
[Interface]
ListenPort = 51820
PrivateKey = <key>
# Gateway's own endpoint: its rack address, e.g. [3fff:0a:ff01::11]:51820

[Peer]  # Site B gateway 1 (rack 1 in DC-West)
PublicKey = <site-b-gw1-key>
Endpoint = [3fff:0b:ff01::11]:51820  # Site B rack 1 address
AllowedIPs = 3fff:0b::/48

[Peer]  # Site B gateway 2 (rack 2 in DC-West, HA)
PublicKey = <site-b-gw2-key>
Endpoint = [3fff:0b:ff02::11]:51820  # Site B rack 2 address
AllowedIPs = 3fff:0b::/48
```

In a gateway-transit variant of `cross-site` mode, worker nodes may not need
their own cross-site WireGuard peering. In a distributed variant, workers run
`wg0` and peer directly with remote-site gateways.

Mode requirement:
- A deployment MUST choose one cross-site encryption topology per environment
  (`gateway-transit` or `distributed`) and document packet-flow assumptions
  accordingly.

### Hybrid: GUA Site + ULA Remote

A remote site without globally routable IPv6 (e.g., a developer office
behind a residential ISP) can still join the mesh using the base
architecture's ULA + WireGuard overlay model:

```
Site A (DC, GUA):  3fff:0a::/48  (native routing)
Site B (Office, ULA): fd00:ws:b::/48  (WireGuard overlay)

Gateway-A peers with Office-VPN peer:
  AllowedIPs = fd00:ws:b::/48

Pods in Site A reach Office pods via WireGuard through gateway.
Office pods reach Site A pods via WireGuard (encrypted, NATed if needed).
```

### External Peers (Unchanged)

External peers (developer laptops, CI runners) use `WirescaleExternalPeer`
CRDs exactly as in the base architecture. They connect via WireGuard to
a gateway node regardless of whether the site uses GUA or ULA internally.

---

## 10. CNI Plugin Changes

### Address Assignment

The CNI plugin changes are minimal. Instead of assigning from a ULA range,
it assigns from the node's GUA /64:

```
CNI ADD:
  1. Read node's pod CIDR from WirescaleNode CRD: 3fff:0a:0001::/64
  2. Allocate next available address: 3fff:0a:0001::a
  3. Create veth pair, assign address in pod netns
  4. Set gateway: 3fff:0a:0001::1 (host's address on pod subnet)
  5. Set MTU: physical MTU (no WireGuard overhead for native traffic)
       OR: physical MTU - 80 if always-encrypt mode
  6. Assign CLAT IPv4: 100.64.1.10 (via clat0 TUN, unchanged)

Note: the pod gateway (3fff:0a:0001::1) is on the pod /64, NOT the rack /64.
The host has addresses on both prefixes:
  - 3fff:0a:ff01::11  (rack /64, on eth0, faces the fabric)
  - 3fff:0a:0001::1   (pod /64, on the internal bridge, faces pods)
```

### MTU Handling

A key benefit: when encryption is `cross-site` or `never`, same-site pod
traffic doesn't traverse WireGuard. The pod MTU can be the full physical
MTU minus only the veth overhead (negligible):

| Encryption Mode | Pod MTU (1500 physical) | Pod MTU (9000 jumbo) |
|----------------|------------------------|---------------------|
| `never` | 1500 | 9000 |
| `cross-site` | 1500 (same-site) / 1420 (cross-site, PMTUD) | 9000 / 8920 |
| `always` | 1420 | 8920 |

For `cross-site` mode, Path MTU Discovery handles the MTU difference
transparently. Cross-site packets that are too large receive ICMPv6
"Packet Too Big" from the gateway's WireGuard interface, and the source
pod adjusts its PMTU accordingly.

### Host Route Installation

The CNI installs a host route for each pod on the host's routing table:

```bash
# Inside host netns (done by CNI):
ip -6 route add 3fff:0a:0001::a/128 dev veth_podA
```

The fabric advertises the covering /64 via BGP. The per-pod /128 routes
are local to the host only -- they don't appear in fabric BGP (the /64
is sufficient for external routing).

---

## 11. Packet Flow Walkthroughs

### Case 1: Pod-to-Pod, Same Node (GUA)

```
Pod A (3fff:0a:0001::a) -> Pod B (3fff:0a:0001::b)
  |
  | eth0 -> veth_A -> host kernel routing
  | route: 3fff:0a:0001::b/128 dev veth_B
  | -> veth_B -> Pod B eth0
  |
  | No WireGuard. No eBPF translation. Pure kernel forwarding.
  | Latency: ~2-5 us. Throughput: limited by veth, ~40+ Gbps.
```

### Case 2a: Pod-to-Pod, Same Rack, Different Node (Native IPv6)

```
Pod A on host-1 (3fff:0a:0001::a) -> Pod C on host-2 (3fff:0a:0002::1)
  Both hosts are on rack 1: 3fff:0a:ff01::/64
  |
  | eth0 -> veth -> host-1 routing
  | route: 3fff:0a:0002::/64 via 3fff:0a:ff01::12 dev eth0
  |   (installed by fabric BGP, next-hop = host-2's rack address)
  |   (host-2 is on the same L2 segment, so this is a single hop)
  v
  Physical NIC -> rack L2 switch -> host-2 physical NIC
  |
  | host-2 routing: 3fff:0a:0002::1/128 dev veth_C
  | -> veth_C -> Pod C eth0
  |
  | No WireGuard. No encapsulation. Single L2 hop. Line rate.
```

### Case 2b: Pod-to-Pod, Different Rack, Same Site (Native IPv6)

```
Pod A on host-1/rack-1 (3fff:0a:0001::a) -> Pod D on host-3/rack-2 (3fff:0a:0003::5)
  host-1 rack address: 3fff:0a:ff01::11
  host-3 rack address: 3fff:0a:ff02::11
  |
  | eth0 -> veth -> host-1 routing
  | route: 3fff:0a:0003::/64 via 3fff:0a:ff01::1 dev eth0
  |   (fabric BGP: ToR-1 learned host-3's /64 from ToR-2 via spine)
  |   (next-hop rewritten by ToR to reach host-3's rack address)
  v
  Physical NIC -> ToR-1 -> spine -> ToR-2 -> host-3 physical NIC
  |
  | host-3 routing: 3fff:0a:0003::5/128 dev veth_D
  | -> veth_D -> Pod D eth0
  |
  | No WireGuard. Standard L3 fabric routing. Line rate.
```

### Case 3: Pod-to-Pod, Cross-Site (WireGuard Encrypted)

```
Pod A in DC-East (3fff:0a:0001::a) -> Pod X in DC-West (3fff:0b:0003::7)
  host-1 rack address: 3fff:0a:ff01::11
  |
  | eth0 -> veth -> eBPF checks encrypt_map
  | 3fff:0b::/48 -> require_encryption = true
  | bpf_redirect(wg0_ifindex)
  v
  wg0 on host-1:
  | peer: dc-west-gateway, AllowedIPs = 3fff:0b::/48
  | encrypt -> UDP from [3fff:0a:ff01::11] to [3fff:0b:ff01::11]:51820
  |   (outer header uses rack addresses for both endpoints)
  v
  Physical NIC -> ToR -> spine -> DCI/MPLS -> DC-West spine -> ToR -> gateway
  |
  | wg0 on dc-west-gateway: decrypt
  | -> kernel routing: 3fff:0b:0003::/64 via host-X's rack address
  | -> fabric -> host-X
  | -> veth -> Pod X
```

### Case 4: Pod to Internet (IPv6, Zero Overhead)

```
Pod A (3fff:0a:0001::a) -> google.com [2607:f8b0:4004::200e]:443
  |
  | eth0 -> veth -> host routing
  | route: ::/0 via 3fff:0a:ff01::1 (default via ToR on rack /64)
  v
  Physical NIC -> ToR -> spine -> border -> internet
  |
  | No SNAT. No NAT64. No WireGuard. No translation.
  | Google sees source = 3fff:0a:0001::a (pod's GUA from pod /64)
  | Return traffic routes: border -> spine -> ToR-1 -> host-1 -> pod
  |   (ToR knows 3fff:0a:0001::/64 -> host-1 via fabric BGP)
  |
  | THIS IS THE IDEAL PATH. Zero overhead. Line rate.
```

### Case 5: Pod to Internet (IPv4 via NAT64)

```
Pod A (3fff:0a:0001::a / 100.64.1.10) -> example.com (93.184.216.34)
  |
  | App calls connect("93.184.216.34", 80) -- IPv4 socket
  | clat0 TUN: IPv4 -> IPv6
  |   src: 3fff:0a:0001::a
  |   dst: 64:ff9b::5db8:d822
  v
  eth0 -> veth -> host routing
  | route: 64:ff9b::/96 -> nat64 interface
  v
  nat64 eBPF: IPv6 -> IPv4
  | MASQUERADE: src = host's public IPv4
  | dst = 93.184.216.34
  v
  Physical NIC -> internet (IPv4)
```

### Case 6: Internet to Pod (Explicit Ingress)

```
Client [2607:f8b0::1]:54321 -> Pod web (3fff:0a:0001::a):443
  |
  | Internet -> border -> spine -> ToR-1
  | ToR-1 fabric BGP: 3fff:0a:0001::/64 via 3fff:0a:ff01::11 (host-1)
  | -> host-1 NIC (on rack /64)
  v
  XDP ingress firewall on eth0:
  | dst = 3fff:0a:0001::a (matches local pod /64)
  | src = 2607:f8b0::1 (external -- not in any cluster prefix)
  | Check external_ingress_map: port 443, app=web-frontend -> ALLOW
  v
  Kernel routing: 3fff:0a:0001::a/128 dev veth_web -> Pod eth0
  |
  | Pod handles TLS, responds
  | Return: src=3fff:0a:0001::a -> veth -> host routing -> eth0
  |   -> ToR -> spine -> border -> internet (no SNAT needed)
```

---

## 12. Deployment Topologies

### Bare Metal with Fabric BGP (Recommended)

```
Best for: Production data centers, high performance
Routing: Fabric-managed BGP (eBGP host-to-ToR, managed by network team)
Encryption: cross-site (same-site traffic is native)
IPv4: NAT64 on each node for outbound
MTU: 9000 (jumbo frames on fabric)

Requires: BGP-capable fabric with pod /64 routes, /48 per site
Wirescale's role: IPAM, pod addressing, encryption, policy -- not routing
```

### Cloud (AWS/GCP) with VPC Routing

```
Best for: Cloud-native deployments
Routing: Cloud provider fabric (ENI prefix delegation on AWS,
         /96 from subnet on GCP, or custom routes via cloud API)
Encryption: always or cross-VPC (cloud fabric may not be trusted)
IPv4: Dual-stack via cloud provider + NAT64 for gaps
MTU: 1500 (common cloud default) or up to 9001 on AWS ENA (environment-dependent)

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

---

## 13. Comparison: ULA Overlay vs GUA Native

| Property | ULA + WireGuard Overlay | GUA + Native Routing |
|----------|------------------------|---------------------|
| **Same-site pod-to-pod** | WireGuard encrypted (3-10 Gbps/core) | Line rate (native IPv6) |
| **Cross-site pod-to-pod** | WireGuard encrypted | WireGuard encrypted (same) |
| **Pod to IPv6 internet** | SNAT required | Direct, no SNAT |
| **Pod to IPv4 internet** | CLAT + NAT64 | CLAT + NAT64 (same) |
| **Internet to pod** | Not possible (proxy required) | Direct (with policy) |
| **Setup complexity** | Low (no fabric config needed) | Medium (fabric must route pod /64s) |
| **Network requirements** | Any (even NAT'd IPv4) | Routable IPv6 + fabric with BGP routing |
| **Security posture** | Implicitly isolated | Explicitly firewalled (mandatory policy) |
| **MTU overhead** | -80 bytes (WireGuard) | 0 (native) |
| **Latency overhead** | +encrypt/decrypt time | 0 (native) |
| **CPU overhead** | ChaCha20 per packet | 0 (kernel forwarding only) |
| **Operational visibility** | Pod IPs not meaningful externally | Pod IPs visible in flow logs, ACLs, firewalls |
| **Best for** | Hostile/shared networks, overlay-first | Dedicated infrastructure, performance-critical |

### When to Use Which

**Use ULA + WireGuard Overlay when:**
- Running on shared/untrusted infrastructure (public cloud, multi-tenant)
- No control over the network fabric (can't get pod /64 routes installed)
- IPv6 globally routable space not available
- Maximum security is more important than maximum performance

**Use GUA + Native Routing when:**
- Running on dedicated infrastructure (own data center, bare metal)
- Full control over the network fabric (BGP routing for pod /64s)
- Performance is critical (financial trading, HPC, media streaming)
- Direct internet accessibility for services is desired
- Operating at scale where WireGuard per-packet overhead is measurable

**Use both simultaneously (hybrid) when:**
- Multi-site with GUA within each site and WireGuard between sites
- Some workloads need encryption even within the site (PCI compliance)
- Migrating from overlay to native routing incrementally
