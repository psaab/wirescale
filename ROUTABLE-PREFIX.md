# Wirescale: Globally Routable /64-per-Host Design

> What changes when every host in the fleet owns a dedicated /64 from
> globally routable address space, and how Wirescale adapts its
> architecture to exploit native IPv6 reachability.

---

## Table of Contents

1. [The /64-per-Host Model](#1-the-64-per-host-model)
2. [What Changes from the Base Architecture](#2-what-changes-from-the-base-architecture)
3. [Address Architecture](#3-address-architecture)
4. [Routing: BGP to the Fabric](#4-routing-bgp-to-the-fabric)
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
are routable on the internet without NAT, without tunnels, without overlays.

```
Site allocation:     2001:db8:site::/48     (65,536 /64s available)
  Host worker-1:     2001:db8:site:0001::/64
    Pod A:           2001:db8:site:0001::a/128
    Pod B:           2001:db8:site:0001::b/128
  Host worker-2:     2001:db8:site:0002::/64
    Pod C:           2001:db8:site:0002::1/128
  Host worker-3:     2001:db8:site:0003::/64
    ...
```

The /64 is the natural unit for IPv6 subnets: SLAAC mandates it, NDP
assumes it, and switch ASICs optimize for it. A /64 provides 2^64
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

The base ARCHITECTURE.md assumed ULA addresses (`fd00:ws::/48`) with a
WireGuard overlay providing both reachability and encryption. The /64-per-
host model fundamentally restructures the data plane:

| Aspect | Base (ULA + WG Overlay) | /64-per-Host (GUA + Native Routing) |
|--------|------------------------|--------------------------------------|
| Pod IPv6 addresses | ULA (`fd00:ws:N::P`) | GUA (`2001:db8:site:N::P`) |
| Inter-node reachability | WireGuard tunnel | Native IP routing (BGP) |
| Encryption | Always (WireGuard) | Selective (WireGuard when needed) |
| Internet reachability | Via NAT64 gateway | Direct (pods are globally routable) |
| Inbound from internet | Not possible without proxy | Direct to pod (filtered by policy) |
| Routing protocol | None (WireGuard AllowedIPs) | BGP (eBGP to ToR or iBGP mesh) |
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
  - BGP speaker per node (embedded GoBGP or BIRD)
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
```

---

## 3. Address Architecture

### Allocation Hierarchy

```
RIR/LIR allocation:     2001:db8::/32          (provider allocation)
  Site A (DC-East):      2001:db8:0a::/48       (65,536 /64s)
    Infra (p2p links):   2001:db8:0a:ff00::/56  (256 /64s for p2p)
    Hosts:               2001:db8:0a:0000::/52  (4,096 /64s for hosts)
      worker-1:          2001:db8:0a:0001::/64
      worker-2:          2001:db8:0a:0002::/64
      ...
      worker-4096:       2001:db8:0a:1000::/64
    Services:            2001:db8:0a:f000::/52  (service VIPs)

  Site B (DC-West):      2001:db8:0b::/48
    ...
```

### Per-Host Addressing

Each host has two distinct address scopes:

```
Host worker-1:
  Uplink interface (eth0):
    Link-local:    fe80::1/64            (always present)
    P2P to ToR:    2001:db8:0a:ff01::1/127  (BGP peering)
    OR: use link-local only for BGP (RFC 5549 unnumbered)

  Pod network (internal routing):
    Pod CIDR:      2001:db8:0a:0001::/64
    Gateway:       2001:db8:0a:0001::1   (host acts as gateway)
    Pod A:         2001:db8:0a:0001::a
    Pod B:         2001:db8:0a:0001::b
    ...

  WireGuard (for cross-site encryption):
    wg0 endpoint:  [2001:db8:0a:ff01::1]:51820
    wg0 address:   (none needed -- encryption only, no routing)
```

### Pod Address Assignment

The CNI assigns addresses directly (no SLAAC, no DHCPv6):

```
IPAM strategy: sequential from pool, skip gateway and reserved

Pool:     2001:db8:0a:0001::a  through  2001:db8:0a:0001:ffff:ffff:ffff:ffff
Reserved: 2001:db8:0a:0001::0  (subnet-router anycast, RFC 4291)
          2001:db8:0a:0001::1  (host gateway)
          2001:db8:0a:0001::2  through ::9 (infrastructure, future use)
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
Mapping:           100.64.N.P  <-->  2001:db8:0a:N::P
```

The mapping is now from CGNAT to GUA instead of CGNAT to ULA, but the
mechanism is identical: stateless CLAT translation at the pod veth.

---

## 4. Routing: BGP to the Fabric

### Why BGP

With globally routable /64 prefixes per host, the network fabric must know
which host owns which /64. BGP is the standard mechanism for this:

- Proven at scale (the internet runs on it)
- Dynamic -- handles host additions, failures, and migrations
- Policy-rich -- can express preferences, communities, prepending
- Supported by all data center switches (Arista, Cisco, Juniper, SONiC)
- Well-understood by network operations teams

### Topology: eBGP to ToR

The recommended deployment is **eBGP peering from each host to its
Top-of-Rack (ToR) switch**:

```
                    Spine switches (AS 65000)
                   /          |          \
                  /           |           \
        ToR-1 (AS 65001)  ToR-2 (AS 65002)  ToR-3 (AS 65003)
          |       |          |       |          |       |
       host-1  host-2    host-3  host-4     host-5  host-6
       AS 65011 AS 65012  AS 65021 AS 65022  AS 65031 AS 65032
```

Each host runs its own private ASN and peers with its ToR switch.
The host advertises its /64 pod prefix. The ToR aggregates and
re-advertises upstream to the spines.

### Wirescale BGP Speaker

The wirescale-agent embeds a BGP speaker (GoBGP library). Configuration
is driven by the `WirescaleMesh` and `WirescaleNode` CRDs:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleMesh
metadata:
  name: default
spec:
  routing:
    mode: bgp                    # "bgp" | "static" | "wireguard-only"
    bgp:
      localASNRange: "65010-65999"  # auto-assign per node
      # OR: localASN: 65010         # single ASN (iBGP)
      peerGroups:
        - name: tor
          peerASN: 65001
          # Auto-discover peer from default gateway, or explicit:
          # peerAddress: "2001:db8:0a:ff01::0"
          addressFamilies:
            - ipv6Unicast
          exportPrefixes:
            - podCIDR                # export this node's /64 pod prefix
          importPrefixes:
            - "0.0.0.0/0"           # default route
            - "::/0"                # default route
```

The agent translates this into GoBGP API calls:

```go
// Pseudocode for BGP setup
bgpServer := gobgp.NewBgpServer()

// Configure local AS (auto-assigned from range based on node index)
bgpServer.Start(&config.Global{
    ASN:      uint32(65010 + nodeIndex),
    RouterID: nodeIPv4,  // BGP requires 32-bit router ID
    ListenAddresses: []string{nodeIPv6},
})

// Add ToR peer
bgpServer.AddPeer(&config.Neighbor{
    PeerASN:  65001,
    Address:  torAddress,
    AFISAFIs: []config.AfiSafi{{Name: "ipv6-unicast"}},
})

// Advertise pod /64
bgpServer.AddPath(&table.Path{
    Prefix: podCIDRv6,  // "2001:db8:0a:0001::/64"
    NextHop: nodeIPv6,
})
```

### Alternative: iBGP with Route Reflectors

For environments where per-host ASNs are impractical, iBGP with route
reflectors works:

```
All hosts: AS 65000
Route reflectors (3 for HA): AS 65000, cluster-id per RR
Each host peers with 2 RRs
RRs reflect all /64 routes to all clients
```

This is the Calico model and scales to thousands of nodes with 3-5
route reflectors.

### Alternative: Static Routes

For small clusters or cloud environments where BGP is unavailable, the
agent can configure static routes via the WirescaleNode CRD. The
controller computes routes and each agent installs them:

```bash
# On host-1, for reaching pods on host-2:
ip -6 route add 2001:db8:0a:0002::/64 via 2001:db8:0a:ff02::1 dev eth0
```

This doesn't scale well but works for clusters under ~50 nodes.

### Kernel Sysctls for Host-as-Router

```bash
# Accept RAs even with forwarding enabled (critical!)
net.ipv6.conf.eth0.accept_ra = 2
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.eth0.forwarding = 1

# Proxy NDP is NOT needed -- BGP handles reachability
net.ipv6.conf.eth0.proxy_ndp = 0
```

---

## 5. WireGuard as Encryption-Only Layer

### The Paradigm Shift

In the base architecture, WireGuard serves dual duty: routing overlay +
encryption. With globally routable /64s and BGP, routing is native.
WireGuard's role shrinks to **transparent encryption** for traffic that
requires confidentiality.

This is how Cilium and Calico already use WireGuard in native routing
mode.

### Architecture

```
Pod A (2001:db8:0a:1::a) -> Pod B (2001:db8:0a:2::b)

WITHOUT encryption (same-site, trusted fabric):
  Pod A -> veth -> host routing -> eth0 -> fabric -> host-2 eth0 -> veth -> Pod B
  (pure native IPv6, line rate, zero overhead)

WITH encryption (cross-site, or policy requires it):
  Pod A -> veth -> eBPF redirect -> wg0 -> encrypt -> eth0 -> fabric
  -> host-2 eth0 -> wg0 -> decrypt -> eBPF redirect -> veth -> Pod B
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
| External (::/0) | No | Already TLS, no benefit |
| Specific pod CIDR | Yes | Policy override (sensitive workload) |

### WireGuard Configuration (Encryption-Only Mode)

When WireGuard is encryption-only, its configuration is simpler:

```
[Interface]
ListenPort = 51820
PrivateKey = <generated-at-boot>
# No Address -- wg0 is not a routed interface, just an encryption hop

[Peer]  # Remote site gateway
PublicKey = <site-B-gateway-key>
Endpoint = [2001:db8:0b:ff01::1]:51820
AllowedIPs = 2001:db8:0b::/48    # All of Site B's address space
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
        prefixes: ["2001:db8:0a::/48"]
      - name: dc-west
        prefixes: ["2001:db8:0b::/48"]
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
100.64.N.P  <-->  2001:db8:0a:N::P
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
Pod (2001:db8:0a:1::a) -> connect to [2607:f8b0:4004::200e]:443 (google.com)
  -> Native IPv6 routing
  -> No SNAT, no NAT64, no translation of any kind
  -> Google sees source = 2001:db8:0a:1::a
  -> Return traffic routes directly back to pod
```

**Zero overhead for IPv6-to-IPv6 communication.** This is the primary
performance benefit of globally routable pods.

### Inbound IPv4 to Pods

For services that need to accept IPv4 connections from the internet, a
dedicated NAT64 ingress gateway translates inbound IPv4 to the pod's GUA
IPv6:

```
Internet client (93.184.216.1) -> NAT64 gateway IPv4 VIP
  -> NAT64: embed client IPv4 in 64:ff9b::
  -> Forward to pod's GUA IPv6 address
  -> Pod receives connection from 64:ff9b::5db8:d801
  -> Pod responds (IPv6 to 64:ff9b:: prefix)
  -> NAT64 gateway translates back to IPv4
  -> Internet client receives response
```

For services that only need IPv6 ingress, no gateway is needed -- clients
connect directly to the pod's GUA address.

---

## 8. Security: When Pods Are Internet-Routable

### The Critical Difference

With ULA pods behind a WireGuard overlay, pods are invisible to the
internet by construction. With GUA pods, **every pod is reachable from
the internet** unless firewalled. This makes policy enforcement not just
important but **mandatory for basic security.**

### Mandatory Default-Deny

Wirescale in GUA mode **automatically installs a default-deny ingress
policy** for all pods. This is not optional:

```yaml
# Auto-generated by wirescale-controller at cluster init
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

This means:
- Pod-to-pod communication within the cluster: **blocked** until explicitly
  allowed by a WirescalePolicy or NetworkPolicy
- Inbound from the internet: **blocked** by default
- Outbound from pods: **allowed** by default (can be restricted per-policy)

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
2001:db8:0a::/48                    2001:db8:0b::/48
  |                                   |
  +-- gateway-a                       +-- gateway-b
  |   BGP to internet + Site B        |   BGP to internet + Site A
  |   WireGuard peer: gateway-b       |   WireGuard peer: gateway-a
  |                                   |
  +-- worker-1..100                   +-- worker-1..100
      BGP to local ToR                    BGP to local ToR
      Native routing within site          Native routing within site
```

### Site Gateways

Each site has 2-3 gateway nodes (for HA) that:
1. Peer with all other sites' gateways via WireGuard
2. Run BGP to advertise the local site's /48 to remote sites (over WireGuard)
3. Act as transit routers for cross-site pod traffic

The gateway's WireGuard config:

```
[Interface]
ListenPort = 51820
PrivateKey = <key>

[Peer]  # Site B gateway 1
PublicKey = <site-b-gw1-key>
Endpoint = [2001:db8:0b:ff01::1]:51820
AllowedIPs = 2001:db8:0b::/48

[Peer]  # Site B gateway 2 (HA)
PublicKey = <site-b-gw2-key>
Endpoint = [2001:db8:0b:ff02::1]:51820
AllowedIPs = 2001:db8:0b::/48
```

Worker nodes don't need WireGuard at all (in `cross-site` encryption
mode). Cross-site traffic is routed via BGP to the local gateway, which
encrypts and forwards.

### Hybrid: GUA Site + ULA Remote

A remote site without globally routable IPv6 (e.g., a developer office
behind a residential ISP) can still join the mesh using the base
architecture's ULA + WireGuard overlay model:

```
Site A (DC, GUA):  2001:db8:0a::/48  (native routing)
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
  1. Read node's pod CIDR from WirescaleNode CRD: 2001:db8:0a:1::/64
  2. Allocate next available address: 2001:db8:0a:1::a
  3. Create veth pair, assign address in pod netns
  4. Set gateway: 2001:db8:0a:1::1 (host's address on pod bridge)
  5. Set MTU: physical MTU (no WireGuard overhead for native traffic)
       OR: physical MTU - 80 if always-encrypt mode
  6. Assign CLAT IPv4: 100.64.1.10 (via clat0 TUN, unchanged)
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
ip -6 route add 2001:db8:0a:1::a/128 dev veth_podA
```

The host then advertises the covering /64 via BGP. The per-pod /128 routes
are local only -- they don't leak into BGP (the /64 is sufficient for
external routing).

---

## 11. Packet Flow Walkthroughs

### Case 1: Pod-to-Pod, Same Node (GUA)

```
Pod A (2001:db8:0a:1::a) -> Pod B (2001:db8:0a:1::b)
  |
  | eth0 -> veth_A -> host kernel routing
  | route: 2001:db8:0a:1::b/128 dev veth_B
  | -> veth_B -> Pod B eth0
  |
  | No WireGuard. No eBPF translation. Pure kernel forwarding.
  | Latency: ~2-5 us. Throughput: limited by veth, ~40+ Gbps.
```

### Case 2: Pod-to-Pod, Same Site, Different Node (Native IPv6)

```
Pod A on host-1 (2001:db8:0a:1::a) -> Pod C on host-2 (2001:db8:0a:2::1)
  |
  | eth0 -> veth -> host-1 routing
  | route: 2001:db8:0a:2::/64 via 2001:db8:0a:ff02::1 dev eth0
  |   (learned via BGP from host-2's advertisement)
  v
  Physical NIC -> fabric -> ToR -> host-2 physical NIC
  |
  | host-2 routing: 2001:db8:0a:2::1/128 dev veth_C
  | -> veth_C -> Pod C eth0
  |
  | No WireGuard. No encapsulation. Line rate.
  | The fabric routes native IPv6 -- this is just standard IP forwarding.
```

### Case 3: Pod-to-Pod, Cross-Site (WireGuard Encrypted)

```
Pod A in DC-East (2001:db8:0a:1::a) -> Pod X in DC-West (2001:db8:0b:3::7)
  |
  | eth0 -> veth -> eBPF checks encrypt_map
  | 2001:db8:0b::/48 -> require_encryption = true
  | bpf_redirect(wg0_ifindex)
  v
  wg0 on host-1:
  | peer: dc-west-gateway, AllowedIPs = 2001:db8:0b::/48
  | encrypt -> UDP to [2001:db8:0b:ff01::1]:51820
  v
  Physical NIC -> internet/MPLS/DCI -> DC-West gateway
  |
  | wg0 on dc-west-gateway: decrypt
  | -> kernel routing: 2001:db8:0b:3::/64 via host-X
  | -> fabric -> host-X
  | -> veth -> Pod X
```

### Case 4: Pod to Internet (IPv6, Zero Overhead)

```
Pod A (2001:db8:0a:1::a) -> google.com [2607:f8b0:4004::200e]:443
  |
  | eth0 -> veth -> host routing
  | route: ::/0 via 2001:db8:0a:ff01::0 (default via ToR)
  v
  Physical NIC -> ToR -> spine -> border -> internet
  |
  | No SNAT. No NAT64. No WireGuard. No translation.
  | Google sees source = 2001:db8:0a:1::a
  | Return traffic routes directly back.
  |
  | THIS IS THE IDEAL PATH. Zero overhead. Line rate.
```

### Case 5: Pod to Internet (IPv4 via NAT64)

```
Pod A (2001:db8:0a:1::a / 100.64.1.10) -> example.com (93.184.216.34)
  |
  | App calls connect("93.184.216.34", 80) -- IPv4 socket
  | clat0 TUN: IPv4 -> IPv6
  |   src: 2001:db8:0a:1::a
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
Client [2607:f8b0::1]:54321 -> Pod web (2001:db8:0a:1::a):443
  |
  | Internet -> border -> spine -> ToR -> host-1 NIC
  v
  XDP ingress firewall on eth0:
  | dst = 2001:db8:0a:1::a (local pod)
  | src = 2607:f8b0::1 (external)
  | Check external_ingress_map: port 443, app=web-frontend -> ALLOW
  v
  Kernel routing -> veth -> Pod eth0
  |
  | Pod handles TLS, responds
  | Return traffic routes directly (no SNAT needed)
```

---

## 12. Deployment Topologies

### Bare Metal with eBGP to ToR (Recommended)

```
Best for: Production data centers, high performance
Routing: eBGP per-host to ToR switches
Encryption: cross-site (same-site traffic is native)
IPv4: NAT64 on each node for outbound
MTU: 9000 (jumbo frames on fabric)

Requires: BGP-capable ToR switches, /48 per site
```

### Cloud (AWS/GCP) with VPC Routing

```
Best for: Cloud-native deployments
Routing: Cloud provider fabric (ENI prefix delegation on AWS,
         /96 from subnet on GCP, or custom routes via cloud API)
Encryption: always or cross-VPC (cloud fabric may not be trusted)
IPv4: Dual-stack via cloud provider + NAT64 for gaps
MTU: 1500 (cloud MTU limitation) or 8996 (jumbo in AWS)

Note: Not all clouds support /64-per-host. AWS gives /80 per ENI.
      GCP gives /96 per NIC. Wirescale adapts to whatever prefix
      length the cloud provides.
```

### Single Rack / Lab

```
Best for: Development, testing, small deployments
Routing: Static routes (no BGP needed)
Encryption: never or always (depending on trust model)
IPv4: NAT64 or dual-stack
MTU: 9000

Simplest deployment -- no BGP, no gateways, just direct routing.
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
| **Setup complexity** | Low (no BGP, no fabric config) | Medium (BGP peering, prefix allocation) |
| **Network requirements** | Any (even NAT'd IPv4) | Routable IPv6 + BGP-capable fabric |
| **Security posture** | Implicitly isolated | Explicitly firewalled (mandatory policy) |
| **MTU overhead** | -80 bytes (WireGuard) | 0 (native) |
| **Latency overhead** | +encrypt/decrypt time | 0 (native) |
| **CPU overhead** | ChaCha20 per packet | 0 (kernel forwarding only) |
| **Operational visibility** | Pod IPs not meaningful externally | Pod IPs visible in flow logs, ACLs, firewalls |
| **Best for** | Hostile/shared networks, overlay-first | Dedicated infrastructure, performance-critical |

### When to Use Which

**Use ULA + WireGuard Overlay when:**
- Running on shared/untrusted infrastructure (public cloud, multi-tenant)
- No control over the network fabric (can't configure BGP)
- IPv6 globally routable space not available
- Maximum security is more important than maximum performance

**Use GUA + Native Routing when:**
- Running on dedicated infrastructure (own data center, bare metal)
- Full control over the network fabric (BGP-capable ToR switches)
- Performance is critical (financial trading, HPC, media streaming)
- Direct internet accessibility for services is desired
- Operating at scale where WireGuard per-packet overhead is measurable

**Use both simultaneously (hybrid) when:**
- Multi-site with GUA within each site and WireGuard between sites
- Some workloads need encryption even within the site (PCI compliance)
- Migrating from overlay to native routing incrementally
