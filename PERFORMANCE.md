# Wirescale: Line-Rate Performance Engineering

> How Wirescale achieves wire-speed IPv4/IPv6 throughput on an IPv6-only
> underlay with WireGuard encryption, NAT64/CLAT translation, and hyperscale
> state efficiency through hierarchical prefix aggregation and on-demand
> peering.
>
> Status: performance design and target guidance. Numeric values without a
> benchmark citation should be treated as estimates/targets, not guaranteed
> production measurements.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

---

## Table of Contents

1. [Performance Budget](#1-performance-budget)
2. [WireGuard at Line Rate](#2-wireguard-at-line-rate)
3. [eBPF NAT64/CLAT Fast Path](#3-ebpf-nat64clat-fast-path)
4. [Packet Pipeline Architecture](#4-packet-pipeline-architecture)
5. [On-Demand Peering Performance](#5-on-demand-peering-performance)
6. [Three-Tier Control Plane Performance](#6-three-tier-control-plane-performance)
7. [State Scaling Analysis](#7-state-scaling-analysis)
8. [Hierarchical Prefix Aggregation and Forwarding](#8-hierarchical-prefix-aggregation-and-forwarding)
9. [Cross-Cluster Performance](#9-cross-cluster-performance)
10. [Signaling Gateway Performance](#10-signaling-gateway-performance)
11. [Control Plane Scalability](#11-control-plane-scalability)
12. [Kernel Tuning](#12-kernel-tuning)
13. [Hardware Acceleration](#13-hardware-acceleration)
14. [Benchmarks and Targets](#14-benchmarks-and-targets)
15. [MTU Strategy](#15-mtu-strategy)

---

## 1. Performance Budget

Every packet in Wirescale traverses up to three processing stages. To hit
line rate, each stage must be fast enough that the aggregate cost stays
under the per-packet time budget.

### Time Budget per Packet

| Link Speed | Packet Rate (1500B) | Time Budget per Packet |
|------------|--------------------|-----------------------|
| 10 Gbps    | ~812 kpps          | ~1,230 ns             |
| 25 Gbps    | ~2.03 Mpps         | ~493 ns               |
| 40 Gbps    | ~3.25 Mpps         | ~308 ns               |
| 100 Gbps   | ~8.12 Mpps         | ~123 ns               |

### Cost of Each Stage (Approximate, Single Core)

| Stage | Technique | Per-Packet Cost | Throughput/Core |
|-------|-----------|----------------|-----------------|
| WireGuard encrypt/decrypt | Kernel module + GRO/GSO | ~150-300 ns (amortized) | 3-10 Gbps |
| NAT64 translation | TC eBPF | ~50-100 ns | 2-5 Mpps |
| CLAT translation | TC eBPF | ~50-100 ns | 2-5 Mpps |
| Policy enforcement | eBPF map lookup | ~20-50 ns | 10+ Mpps |
| Routing decision | Kernel FIB / eBPF | ~20-40 ns | 10+ Mpps |

The critical insight: **GRO/GSO amortization is the key to line rate.**
Instead of processing 812,000 individual packets per second on a 10G link,
GRO coalesces them into ~13,000 superpackets (64KB each). The per-packet
cost drops proportionally because WireGuard encrypts one superpacket instead
of ~50 individual MTU-sized packets.

---

## 2. WireGuard at Line Rate

### Kernel Module, Not wireguard-go

Wirescale uses the **in-kernel WireGuard module** (Linux >= 5.6), not
wireguard-go. The reasons are decisive for line-rate performance:

| Property | Kernel WireGuard | wireguard-go |
|----------|-----------------|--------------|
| Syscalls per packet | 0 (runs in softirq) | 2+ (TUN read/write + UDP send/recv) |
| Memory copies | 0 extra (operates on sk_buff in-place) | 2+ (kernel <-> userspace) |
| GRO/GSO | Native, zero-config | Requires Linux >= 6.2 TUN GSO |
| Multi-core decrypt | padata API (automatic) | goroutine pool (GC pauses) |
| Max single-peer throughput | ~10 Gbps/core (AVX-512) | ~7 Gbps (best case, Tailscale tuned) |

### GRO/GSO: The Throughput Multiplier

WireGuard's performance story changed fundamentally across several kernel
releases:

**Linux 5.19:** Initial GRO offload for WireGuard. The NIC's hardware GRO
coalesces multiple WireGuard UDP datagrams into a single sk_buff before
handing it to the WireGuard driver. One decryption call processes the
coalesced superpacket.

**Linux 6.2:** TUN driver gains UDP GSO/GRO support (relevant for
wireguard-go fallback mode).

**Linux 6.13:** Big TCP GSO support for WireGuard. Allows GSO frames up to
**512 KB** (vs. 64 KB previously). A single encrypt/decrypt call now covers
up to ~340 MTU-sized packets. Measured **15% throughput improvement** over
64 KB GSO.

```
Without GRO/GSO:
  812,000 packets/sec × 300 ns/packet = 243 ms of CPU/sec = ~4 Gbps/core

With GRO (64KB coalescing, ~50:1 ratio):
  16,240 superpackets/sec × 300 ns/packet = 4.9 ms of CPU/sec = headroom

With Big TCP GSO (512KB, ~340:1):
  2,388 superpackets/sec × 300 ns/packet = 0.7 ms of CPU/sec = trivial
```

When GSO is working well, encryption overhead can drop substantially and the
bottleneck often shifts toward memory bandwidth and PCIe.

### Threaded NAPI: Unlocking Multi-Core

On older kernels, WireGuard RX processing can bottleneck in a single poll
context. Newer kernels improve this behavior; validate against your target
kernel before assuming single-core limits.

**Wirescale enables threaded NAPI on every `wg0` interface:**

```bash
echo 1 > /sys/class/net/wg0/threaded
```

This moves NAPI polling from the softirq context to a dedicated kthread
that the scheduler can migrate across cores.

**Impact:**
- 16 tunnels, 32 cores, standard NAPI: ~13 Gbps
- 16 tunnels, 32 cores, threaded NAPI: **~48 Gbps** (3.7x)

Target behavior: wirescale-agent enables threaded NAPI at boot (implementation
status depends on release).

### Multi-Tunnel Scaling

With on-demand peering (see [Section 5](#5-on-demand-peering-performance)),
each node maintains WireGuard peers only for active connections -- typically
10-50 active peers rather than N-1 in a full mesh. Encryption and packet
processing work distributes across multiple cores, subject to kernel
scheduler behavior and workload mix.

On a node with active peers (typically 10-50) and 32 available cores:
- TX/RX work can spread across many cores
- Aggregate throughput can increase substantially with threaded NAPI
- On-demand peering reduces the number of concurrent tunnels, which
  concentrates crypto work on fewer cores but also reduces total CPU usage
- Use local benchmarks to determine realistic ceilings

For single-peer scenarios (e.g., a two-node cluster), the single-core
encryption limit applies (~3-10 Gbps depending on CPU). The Netdev 0x18
"WireGuard Inline" research proposes future kernel patches to parallelize
single-peer encryption.

### Avoiding Kernel Conntrack

Since Wirescale uses no nftables/iptables rules, the kernel conntrack
module is never loaded. Without netfilter hooks, packets bypass conntrack
entirely -- no `notrack` rules needed. If conntrack is loaded by another
subsystem (e.g., Cilium, kube-proxy), the agent SHOULD unload it or
configure `net.netfilter.nf_conntrack_max = 0` to minimize overhead. The
Wirescale data path uses eBPF-only forwarding with its own BPF hash map
for NAT64 connection state.

---

## 3. eBPF NAT64/CLAT Fast Path

### Why TC eBPF, Not XDP

XDP runs at the NIC driver level before sk_buff allocation and is typically
the fastest eBPF hook point. For this design, translation is done in TC on
virtual/tunnel paths for three reasons:

1. WireGuard's `wg0` is a virtual L3 device with no Ethernet header. XDP
   programs that parse `struct ethhdr` will fault.
2. XDP on `wg0` can only run in `xdpgeneric` mode (software emulation),
   which is slower than TC.
3. IPv4-to-IPv6 translation grows the packet by 20 bytes.
   `bpf_xdp_adjust_head()` requires pre-allocated headroom that the
   WireGuard driver doesn't guarantee. TC's `bpf_skb_change_proto()`
   handles this correctly.

**TC eBPF (clsact qdisc) on the `nat64` interface is the canonical hook in this
document.** It keeps translation logic on one explicit path and avoids
virtual-device XDP caveats.

### Where XDP IS Used

XDP runs on the **physical NIC** (`eth0`) for:
- Early drop of malformed/attack traffic (DDoS mitigation)
- RSS steering of WireGuard UDP flows across RX queues
- Pre-filtering before packets enter the WireGuard decrypt path

This protects the WireGuard crypto path from being overwhelmed by junk
traffic at up to 26 Mpps per core.

### NAT64 eBPF Program (TC on nat64 Interface Ingress)

The NAT64 translation program attaches to the `nat64` interface TC ingress
hook. Host routing sends packets destined for `64:ff9b::/96` to this
interface:

```
nat64 interface receives IPv6 packet
  |
  | TC ingress eBPF fires
  v
Match dst in 64:ff9b::/96?
  |
  | Yes: extract embedded IPv4 from last 32 bits
  v
bpf_skb_change_proto(skb, ETH_P_IP, 0)
  | (shrinks sk_buff: 40-byte IPv6 hdr -> 20-byte IPv4 hdr)
  v
Write IPv4 header:
  - src: 169.254.64.X (mapped from pod's IPv6, stateless)
  - dst: extracted IPv4 address
  - TTL from hop limit
  v
bpf_l3_csum_replace() -- IPv4 header checksum
bpf_l4_csum_replace() -- TCP/UDP pseudo-header checksum delta
  v
bpf_redirect(phys_ifindex, 0) -- send out physical NIC
  |
  v
SIIT-DC stateless translation -- src becomes 100.64.H.P (EAM from pod ULA, zero map lookups)
  |
  v
Wire
```

**Performance:** The eBPF translation path is O(1) per packet -- pure
arithmetic address derivation (CGNAT `100.64.H.P` ↔ pod ULA), fixed-cost
header rewrite, and a single redirect. SIIT-DC translation (RFC 7755 with
EAM per RFC 7757) is fully stateless: the return path derives the pod's IPv6
address from the CGNAT destination alone -- zero map lookups. No state table,
no kernel conntrack, no nftables.

### CLAT eBPF Program (TC on Pod veth)

For pod-local IPv4 (CLAT), the translation runs on the pod's veth pair
rather than on `wg0`. This avoids an extra hop through the host routing
table:

```
Pod sends IPv4 packet via clat0 TUN
  |
  v
TC egress eBPF on host-side veth:
  - Match IPv4 packet from pod's CLAT range
  - bpf_skb_change_proto(skb, ETH_P_IPV6, 0)
  - Deterministic mapping: 100.64.N.P -> fd00:1234:CCCC:HHHH::P
  - If dst is another pod: dst 100.64.M.Q -> fd00:1234:CCCC:HHHH::Q
  - If dst is external: dst X.Y.Z.W -> 64:ff9b::X.Y.Z.W
  - Checksum fixup
  - TC_ACT_OK (continue to host routing as IPv6)
```

The reverse path (IPv6 -> IPv4 for return traffic) runs on TC ingress of
the same veth.

**Key optimization:** When both source and destination are mesh pods, the
CLAT translation converts IPv4 to IPv6 at the source veth, the packet
travels through the WireGuard mesh as native IPv6, and the destination
veth's CLAT converts back. **No NAT64 engine is involved for intra-mesh
IPv4 traffic.** The entire path is stateless and symmetric.

### GRO/GSO Interaction with eBPF Translation

When `bpf_skb_change_proto()` is called, the kernel marks the sk_buff as
`SKB_GSO_DODGY`. The GSO engine then re-validates and re-segments the
packet. This means:

1. WireGuard decrypts a GRO superpacket (one call, 64-512 KB)
2. The TC eBPF NAT64 program translates the superpacket header **once**
3. GSO re-segments into MTU-sized IPv4 packets at the physical NIC

The NAT64 translation cost is amortized across the entire superpacket,
not paid per-MTU-segment. This is critical for line-rate performance.

### IPv6 Extension Header Parsing in eBPF Programs

The NAT64 translation logic parses the fixed 40-byte IPv6 header to
extract `nexthdr`, source/destination addresses, and transport-layer
fields. In production traffic, IPv6 packets MAY carry an extension
header chain between the fixed header and the upper-layer payload.
Extension header types include Hop-by-Hop Options (0), Routing (43),
Fragment (44), Destination Options (60), Authentication Header (51),
and ESP (50).

#### eBPF Verifier Constraints

The BPF verifier prohibits unbounded loops. Parsing a variable-length
extension header chain therefore requires an unrolled loop with a
compile-time maximum iteration count. Each iteration reads the
`nexthdr` and `hdrextlen` fields, advances the parse offset, and
checks packet bounds via `skb->data` / `skb->data_end` comparisons.

The enforcement eBPF programs MUST support a chain depth of at least
**6 extension headers**. Implementations SHOULD support up to 8 where
verifier complexity budget permits. A chain depth of 6 covers all
standard extension header types defined in RFC 8200 Section 4.1.

```c
// Unrolled extension header walk (conceptual)
#define MAX_EXT_HEADERS 6

__u8 nexthdr = ip6->nexthdr;
__u32 offset = sizeof(struct ipv6hdr);

#pragma unroll
for (int i = 0; i < MAX_EXT_HEADERS; i++) {
    if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP ||
        nexthdr == IPPROTO_ICMPV6 || nexthdr == IPPROTO_NONE)
        break;
    struct ipv6_opt_hdr *ext = (void *)data + offset;
    if ((void *)(ext + 1) > data_end)
        return TC_ACT_SHOT;  // truncated
    nexthdr = ext->nexthdr;
    offset += (ext->hdrlen + 1) * 8;  // Fragment hdr: fixed 8 bytes
    if (offset > skb->len)
        return TC_ACT_SHOT;
}
```

#### Fragment Header Handling

The Fragment header (nexthdr 44) is fixed at 8 bytes and does not carry
an `hdrlen` field. The parser MUST special-case it. Non-initial fragments
(fragment offset != 0) lack transport headers entirely; the enforcement
program MUST NOT attempt to extract port numbers from fragments and
SHOULD apply identity-only policy (no port match) or pass them to the
slow path.

#### Exceeding Maximum Chain Depth

If the parser exhausts `MAX_EXT_HEADERS` iterations without reaching a
transport header, the program MUST fall back to one of two strategies:

1. **Pass to slow path (recommended):** Return `TC_ACT_OK` with a
   metadata flag that causes the agent's userspace component to inspect
   the packet. This preserves connectivity for unusual but legitimate
   traffic.
2. **Drop:** Return `TC_ACT_SHOT`. This is acceptable under a strict
   security posture where unknown header chains are treated as evasion
   attempts. Operators MUST be able to select this behavior via the
   `WirescaleAgent` CRD field `extensionHeaderPolicy` (`pass` or `drop`,
   default `pass`).

#### Performance Impact

Each extension header adds one bounds check, one 8-byte read, and one
offset advance -- approximately **5-10 ns per header** on current
hardware. For the common case (zero extension headers), the unrolled
loop adds negligible overhead because the first iteration immediately
hits a transport-layer `nexthdr` and breaks. Worst case with 6
extension headers adds ~30-60 ns, which remains well within the
per-packet enforcement budget of ~50-80 ns documented in
[SECURITY.md](SECURITY.md) Section 7.

The NAT64 translation path MUST perform the same extension header walk
before extracting transport-layer checksums. The GRO/GSO amortization
described above applies identically: the extension header parse cost is
paid once per superpacket, not per MTU-segment.

#### Monitoring

The agent SHOULD expose a per-node metric
`wirescale_ext_header_depth_exceeded_total` counting packets that hit
the maximum chain depth. A sustained non-zero rate MAY indicate evasion
attempts or misconfigured middleboxes injecting extension headers.

> **See also:** [EGRESS.md](EGRESS.md) Section 3 adds NPTv6 (stateless
> prefix translation) to the eBPF translation pipeline for outbound
> internet traffic. Section 11 of the same document provides the full
> egress pipeline performance budget (~115 ns per packet), covering
> policy enforcement, FQDN lookup, rate limiting, and NPTv6 translation.

---

## 4. Packet Pipeline Architecture

### Complete Fast Path (Pod-to-External IPv4)

```
Pod app: connect("93.184.216.34", 80)
  |
  | clat0 TUN (in pod netns)
  | IPv4 -> IPv6 stateless translation
  v
eth0 (pod side) -> veth (host side)
  |
  | TC eBPF on veth: CLAT IPv4->IPv6
  | src: fd00:1234:0001:0001::5, dst: 64:ff9b::5db8:d822
  v
Host routing table:
  64:ff9b::/96 -> nat64 dummy interface
  |
  v
nat64 interface:
  TC eBPF: IPv6->IPv4 translation
  bpf_skb_change_proto() + bpf_redirect(eth0)
  |
  v
SIIT-DC stateless: src = 100.64.H.P (EAM from pod ULA, no state table)
  |
  v
Physical NIC TX (hardware checksum offload)
  |
  v
Wire (IPv4 packet, source = node's IPv4)
```

**Total eBPF programs in path: 2** (CLAT on veth + NAT64 on nat64 iface)
**Kernel stack traversals:** minimal in this design (validate with tracing)
**Copy behavior:** optimized for in-place sk_buff manipulation where possible

### Complete Fast Path (Pod-to-Pod Cross-Node, IPv6 Native)

```
Pod A: send to fd00:1234:0002:0001::7
  |
  v
eth0 -> veth -> host routing
  |
  | route: fd00:1234:0002:0001::/64 dev wg0
  v
wg0: WireGuard encrypt (kernel, GRO/GSO)
  |
  | UDP encapsulate to [node-2-ipv6]:51820
  v
Physical NIC TX
  ~~ network ~~
Physical NIC RX (node 2)
  |
  | Hardware GRO coalesces WireGuard UDP datagrams
  v
wg0: WireGuard decrypt (kernel, padata multi-core)
  |
  v
Host routing -> veth -> Pod B eth0
```

**eBPF programs in path: 0** (pure IPv6, no translation needed)
**This is the fastest possible path** -- native kernel WireGuard with GRO/GSO.

### Complete Fast Path (Pod-to-Pod Cross-Node, IPv4 via CLAT)

```
Pod A: send to 100.64.2.7
  |
  v
clat0 -> TC eBPF on veth:
  100.64.1.5 -> fd00:1234:0001:0001::5 (src)
  100.64.2.7 -> fd00:1234:0002:0001::7 (dst)  [deterministic, no NAT64 prefix!]
  |
  v
Host routing: fd00:1234:0002:0001::/64 dev wg0
  |
  v
wg0: WireGuard encrypt (GRO/GSO)
  ~~ network ~~
wg0: WireGuard decrypt (node 2)
  |
  v
Host routing -> veth
  |
  | TC eBPF on veth (ingress):
  | fd00:1234:0001:0001::5 -> 100.64.1.5 (src)
  | fd00:1234:0002:0001::7 -> 100.64.2.7 (dst)
  v
clat0 TUN -> Pod B app sees IPv4
```

**eBPF programs in path: 2** (CLAT at each end)
**NAT64 engine: not involved** (intra-mesh IPv4 maps directly to IPv6)
**Key insight:** The WireGuard tunnel always carries native IPv6. The CLAT
translation happens at the pod boundary, not at the tunnel boundary. The
mesh never sees IPv4 packets.

### Warm Path vs. Cold Path (On-Demand Peering)

With on-demand peering (see [Section 5](#5-on-demand-peering-performance)),
the packet pipeline has two modes depending on whether a WireGuard peer
already exists for the destination.

**Warm path (cached peer exists):** Identical to the fast paths shown above.
The packet hits eBPF, enters WireGuard, and goes to wire. There is zero
additional overhead compared to a full mesh -- the same GRO/GSO amortization
applies, and the same throughput targets hold.

**Cold path (first packet to new peer):** See the detailed cold-path
breakdown in [Section 5](#5-on-demand-peering-performance) for intra-cluster
and [Section 9](#9-cross-cluster-performance) for cross-cluster resolution
chains.

---

## 5. On-Demand Peering Performance

On-demand peering eliminates O(N^2) state by having nodes maintain WireGuard
peers only for active connections. This is the key architectural change that
enables hyperscale operation. See [ARCHITECTURE.md](ARCHITECTURE.md) for
the design rationale and [SECURITY.md](SECURITY.md) for the identity and
authorization model.

### Warm Path (Cached Peer Exists)

When a WireGuard peer already exists for the destination /64 prefix, the
data path is identical to a full-mesh topology:

- Packet hits eBPF at egress, enters WireGuard, goes to wire
- Zero additional overhead compared to full mesh
- Same GRO/GSO amortization, same throughput targets
- Same per-packet latency as measured in
  [Section 14](#14-benchmarks-and-targets)

The warm path is the steady-state path. In typical workloads where traffic
follows power-law distributions, the vast majority of packets traverse
the warm path.

> **See also:** For external (internet-bound) traffic, the egress data
> path adds policy enforcement and NPTv6/NAT64 translation stages beyond
> the WireGuard peering layer. See [EGRESS.md](EGRESS.md) for the full
> egress-specific pipeline and performance characteristics.

### Cold Path: Intra-Cluster (First Packet to New Peer)

When a packet arrives at egress and no WireGuard peer exists for the
destination /64 prefix, the agent MUST establish the peer before the packet
can be transmitted. For intra-cluster destinations, the resolution chain
involves only the local cluster controller:

```
Intra-cluster cold path:
  1. Egress eBPF detects missing peer           ~microseconds
  2. Agent → local wirescale-control via gRPC    ~5-10 ms
  3. Agent configures WireGuard peer             ~1-2 ms
  4. WireGuard handshake (1 RTT, same DC)        ~0.1-1 ms
  Total:                                         ~7-15 ms
```

| Step | Operation | Latency |
|------|-----------|---------|
| 1 | Egress eBPF detects missing peer | ~microseconds |
| 2 | Agent queries wirescale-control via gRPC | ~5-10 ms |
| 3 | Agent configures WireGuard peer | ~1-2 ms |
| 4 | WireGuard handshake (1 RTT) | ~0.1 ms (same-DC), ~50 ms (cross-site) |
| **Total** | **Same-DC cold path** | **~7-15 ms** |
| **Total** | **Cross-site (same cluster)** | **~55-70 ms** |

**TCP interaction:** The first TCP SYN is queued during peer setup. The TCP
retransmit timer (default ~1s) provides ample budget for the cold-path
establishment latency. The SYN-ACK returns over the now-established warm
path. Application-visible latency is limited to the cold-path setup time
on the first connection only.

**UDP interaction:** For UDP traffic, the first packet(s) MAY be queued or
dropped during peer setup depending on agent buffer capacity. Protocols
that tolerate packet loss (DNS, QUIC) recover naturally. For latency-
sensitive UDP flows, applications SHOULD pre-warm the path by sending a
probe packet.

### Cold Path: Cross-Cluster (Signaling Resolution Chain)

Cross-cluster cold paths traverse the full three-tier hierarchy. The
signaling gateway handles initial resolution only -- it is NOT in the
steady-state data path:

```
Cross-cluster cold path:
  1. Packet matches aggregate route → hits agent (cache miss)    ~microseconds
  2. Agent → local wirescale-control                             ~5-10 ms
  3. Controller → wirescale-directory (global)                   ~5-10 ms
  4. Controller → remote cluster wirescale-control               ~10-30 ms
  5. Agent configures WireGuard peer                             ~1-2 ms
  6. WireGuard handshake (1 RTT, cross-site)                     ~10-100 ms
  Total:                                                         ~30-150 ms
```

| Step | Operation | Latency |
|------|-----------|---------|
| 1 | Packet matches aggregate route, agent cache miss | ~microseconds |
| 2 | Agent → local wirescale-control | ~5-10 ms |
| 3 | Local controller → wirescale-directory | ~5-10 ms |
| 4 | Local controller → remote cluster controller | ~10-30 ms (varies by distance) |
| 5 | Agent configures WireGuard peer | ~1-2 ms |
| 6 | WireGuard handshake (cross-site RTT) | ~10-100 ms |
| **Total** | **Cross-cluster cold path** | **~30-150 ms** |

After the cold path completes, the WireGuard tunnel operates directly
between the source and destination nodes. All subsequent packets take the
warm path with zero signaling overhead. The signaling gateway and
directory are never touched again for this peer pair.

### Peer Garbage Collection

The agent runs periodic garbage collection to remove idle peers and reclaim
state:

- GC cycle: every 30 seconds
- Idle detection: `wg show wg0 dump` provides last-handshake timestamp
  per peer
- Peers idle longer than `peer_idle_timeout` (default 5 minutes) are
  removed via `wg set wg0 peer <key> remove`
- GC cost: O(active_peers) per cycle, ~1 ms for 100 peers
- GC overhead is negligible compared to packet processing

**Hysteresis:** The agent SHOULD implement hysteresis to avoid thrashing
on peers near the idle threshold. A peer that receives traffic during the
GC decision window MUST NOT be removed.

### Cold Path Recovery and Caching

After a cross-cluster cold path completes, the agent caches the peer
resolution result locally. If the peer is garbage-collected and later
needed again, the agent SHOULD use cached resolution data (subject to
TTL) to skip the full signaling chain. This reduces repeat cold-path
latency to approximately the intra-cluster level:

| Scenario | First Cold Path | Cached Cold Path |
|----------|----------------|-----------------|
| Intra-cluster | ~7-15 ms | ~7-15 ms (same) |
| Cross-cluster | ~30-150 ms | ~7-15 ms (cache hit) |

### Thundering Herd / Cold Start Mitigation

When a large deployment restarts -- node pool replacement, cluster upgrade,
or mass pod rescheduling -- thousands of agents simultaneously query
wirescale-control for peer resolution and identity lookups. Without
mitigation, this thundering herd can overwhelm the control plane and
cascade into TCP SYN retry exhaustion.

#### Agent-Side Mitigations

**Jittered startup delay.** Each agent MUST delay its first gRPC
connection by a random interval drawn from `[0, startup_jitter_max]`
(default: 5s for <= 1K nodes, 15s for <= 10K nodes; configurable via
the `WirescaleAgent` CRD). During the jitter window the agent MUST
still configure `wg0` and install routes from any persisted peer cache
(see Pre-Warming below) -- only connectivity hints are restored;
authorization state is NOT loaded from disk. Only the control-plane
connection is deferred.

**Exponential backoff on cache misses.** When the agent's cache is cold,
the first packets to many destinations trigger simultaneous cache misses.
The agent MUST rate-limit outbound queries to wirescale-control:

- Initial query rate cap: 50 queries/sec per agent.
- On repeated failures (HTTP 429 or gRPC RESOURCE_EXHAUSTED), the agent
  MUST apply exponential backoff: base interval 100 ms, multiplier 2x,
  maximum interval 10 seconds.
- Queries MUST be batched where possible -- a single gRPC call SHOULD
  resolve up to 100 identity or peer lookups.

**Circuit breaker.** If wirescale-control returns errors for more than
50% of requests in a 10-second sliding window, the agent MUST open its
circuit breaker:

- While open, the agent MUST NOT send new queries. It MUST serve traffic
  using whatever cached connectivity hints exist (stale entries with
  extended TTL). Authorization state (access grants, peer authorization
  tokens) MUST NOT have its TTL extended -- entries MUST fail closed on
  expiry even while the circuit breaker is open. See
  [SECURITY.md: Cached State Classification](SECURITY.md#cached-state-classification).
- The agent MUST attempt a single probe query every 5 seconds.
- After 3 consecutive successful probes, the circuit breaker closes and
  normal querying resumes.

#### Control-Side Mitigations

**Request prioritization.** Wirescale-control MUST prioritize requests
during cold-start bursts:

| Priority | Request Type | Rationale |
|----------|-------------|-----------|
| 1 (highest) | Intra-cluster peer lookups | Local traffic is most latency-sensitive |
| 2 | Identity lookups for active flows | Required for policy enforcement |
| 3 | Cross-cluster peer resolution | Can tolerate higher latency |
| 4 (lowest) | Bulk policy pulls | Can be deferred until burst subsides |

**Per-node rate limiting.** Wirescale-control MUST enforce per-node rate
limits (default: 200 queries/sec per node, 10K queries/sec aggregate per
replica). Excess requests MUST receive gRPC `RESOURCE_EXHAUSTED`, which
triggers the agent's exponential backoff.

#### Pre-Warming: Persisted Peer Cache

To minimize cold-start latency, the agent SHOULD persist a snapshot of
its connectivity hint cache to local disk. **Only connectivity hints are
eligible for disk persistence and startup restore.** Authorization state
(access grant rules, peer authorization tokens, revocation status) MUST
NOT be persisted or restored from disk -- see
[SECURITY.md: Cached State Classification](SECURITY.md#cached-state-classification)
for the full rationale and normative requirements.

- **Snapshot frequency:** Every 60 seconds and on graceful shutdown.
- **Snapshot contents (connectivity hints only):**
  - WireGuard peer public keys and endpoints
  - Allowed CIDRs and routes
  - Identity cache entries (IP-to-identity mappings) with remaining TTLs
  - Cluster topology data (gateway endpoints, prefix allocations)
- **Excluded from snapshot (authorization state):**
  - `WirescaleAccessGrant`-derived policy rules
  - Signed peer authorization tokens
  - Revocation status records
  - Policy generation numbers
- **Snapshot location:** `/var/lib/wirescale/peer-cache.json` (or a
  configurable path).
- **Recovery behavior:** On startup, the agent MUST load the snapshot
  and install WireGuard peers and routes immediately, before contacting
  wirescale-control. Restored connectivity hint entries MUST be marked
  stale and refreshed within `stale_refresh_window` (default: 30
  seconds). The agent MUST NOT install any authorization state from the
  snapshot -- if authorization state entries are present in a snapshot
  written by an older agent version, they MUST be silently discarded
  and the discard MUST be counted via the
  `wirescale_authz_disk_restore_filtered_total` metric.
- **Staleness bound:** If a cached connectivity hint entry is older than
  `max_stale_age` (default: 10 minutes), the agent MUST discard it
  rather than install a potentially-invalid peer.

Pre-warming reduces cold-start resolution from full cold-path latency
(~7-15 ms intra-cluster, ~30-150 ms cross-cluster) to near-zero for
previously-active peers.

#### Startup Authorization Revalidation

After restoring connectivity hints from disk and establishing a
connection to `wirescale-control`, the agent MUST revalidate all
authorization state from the control plane before granting access to
authorization-gated resources:

1. **Access grants:** The agent queries `wirescale-control` for all
   active `WirescaleAccessGrant` rules that apply to local pods. Only
   grants confirmed as valid by control are installed in the BPF policy
   map. This query SHOULD be batched with the initial policy pull.
2. **Peer authorization:** For each restored WireGuard peer, the agent
   confirms the peer's authorization status with control. Peers whose
   authorization has expired or been revoked MUST be removed.
3. **Revocation status:** The agent fetches the current revocation list
   from control. Any peer found on the revocation list MUST be removed
   immediately, even if the peer's connectivity hints were successfully
   restored.

If `wirescale-control` is unreachable at startup, the agent MUST operate
in degraded mode: connectivity hints are used for existing peer sessions
(WireGuard handles authentication independently), but all
authorization-gated operations (new access grants, new peer
authorizations) MUST be denied until control becomes reachable. The
agent MUST expose `wirescale_agent_degraded_mode{reason="control_unreachable"}`
as a gauge metric while in this state.

#### TCP SYN Retry Budget Interaction

During mass cold start, application pods send TCP SYNs to destinations
whose WireGuard peers do not yet exist. The SYN is queued in the agent's
buffer while the cold path resolves. If resolution takes too long, TCP
retransmit timers fire:

| TCP Retry | Time Since SYN | Risk |
|-----------|---------------|------|
| SYN+0     | 0 ms          | Queued in agent buffer |
| Retry 1   | ~1,000 ms     | Cold path SHOULD complete (7-150 ms) |
| Retry 2   | ~3,000 ms     | Only if control is overloaded |
| Retry 3   | ~7,000 ms     | Circuit breaker likely open |

- The agent's packet queue MUST hold at least the first SYN for each
  destination (default buffer: 64 packets per pending peer).
- With pre-warming and jittered startup, cold-path latency SHOULD
  remain within the first TCP retransmit window (1 second) for the
  vast majority of flows.
- If cold-path resolution exceeds 3 seconds, the agent MUST log a
  warning and emit a `wirescale_cold_path_timeout_total` metric.
  Applications will see elevated latency but MUST NOT see failures
  unless the cold path exceeds the application's connect timeout.

### QUIC and UDP Protocols Through Cold Paths

Section 5 documents the cold-path interaction with TCP, noting that the
TCP SYN retransmit timer (~1s default) provides ample budget for the
7-15 ms intra-cluster establishment latency. UDP-based protocols have
fundamentally different retry semantics and MUST be handled explicitly.

#### The UDP Cold-Path Problem

When a packet triggers the cold path and no WireGuard peer exists, the
kernel has no transport-layer state to hold the packet. Unlike TCP, where
the SYN sits in the socket's retransmit queue, UDP packets are
fire-and-forget at the transport layer. If the agent drops or fails to
queue the triggering packet, recovery depends entirely on the
application-layer protocol -- or does not happen at all.

#### Agent Queuing for UDP

The wirescale-agent MUST maintain a per-destination packet queue for
cold-path establishment. When egress eBPF detects a missing peer, it
MUST redirect the packet to a userspace capture ring (via
`bpf_ringbuf_output` or `BPF_MAP_TYPE_QUEUE`) rather than silently
dropping it. The agent replays queued packets once the WireGuard peer
is established.

Queue parameters:
- **Capacity:** 64 packets per destination (configurable via
  `WirescaleAgent` CRD field `coldPathQueueSize`).
- **Timeout:** Queued packets MUST be dropped if peer establishment
  does not complete within 5 seconds (configurable via
  `coldPathQueueTimeout`).
- **Memory bound:** Total cold-path queue memory MUST NOT exceed 16 MB
  per node to prevent resource exhaustion from scanning or port sweeps.

This queuing mechanism benefits all UDP protocols equally: DNS, QUIC,
gaming, VoIP, and any custom UDP application.

#### QUIC-Specific Considerations

QUIC (RFC 9000) uses UDP and manages its own connection establishment,
loss detection, and retry logic. Several QUIC behaviors interact with
cold-path latency:

**Initial handshake.** QUIC clients send an Initial packet containing a
CRYPTO frame. If the WireGuard peer is not yet established, the agent's
packet queue holds this Initial packet. QUIC's Probe Timeout (PTO,
typically ~1s initial value per RFC 9002 Section 6.2) provides
sufficient budget for intra-cluster cold paths (~7-15 ms). Cross-cluster
cold paths (~30-150 ms) also complete well within a single PTO.

**0-RTT early data.** QUIC clients with cached session tickets MAY send
0-RTT data in the same flight as the Initial packet. This early data
is not retransmittable by QUIC's loss recovery if it was never
acknowledged. The agent's cold-path queue MUST capture 0-RTT packets
alongside the Initial packet so they are delivered intact after peer
establishment. Without queuing, 0-RTT data is irrecoverably lost and
the connection falls back to 1-RTT, adding one RTT of latency.

**Retry packets.** QUIC servers MAY respond with a Retry packet for
address validation. Retry interactions add one additional RTT before
the handshake proceeds. The cold-path queue MUST be bidirectional:
if the responding server's node also needs to establish a return peer,
the Retry packet is queued on that side as well.

#### Protocols Without Application-Layer Retry

Certain UDP protocols lack any retry mechanism:

| Protocol | Retry Behavior | Cold-Path Risk |
|----------|---------------|----------------|
| DNS (stub) | Client retries after 1-5s | Low: queue covers the gap |
| DNS (iterative) | Resolver retries after ~2s | Low |
| QUIC | PTO-based, ~1s initial | Low with queuing |
| NTP | Poll interval 64-1024s | Negligible |
| syslog (UDP) | No retry | Loss acceptable |
| Gaming/VoIP (RTP) | No retry, tolerates loss | First 7-150 ms of media lost |

For latency-sensitive real-time protocols (VoIP, gaming), applications
SHOULD pre-warm the WireGuard peer path by sending an initial probe
packet during connection setup. The warm-path latency (~0.1 ms) is
documented in Section 5 and imposes no ongoing penalty.

#### Guidance for Operators

1. Applications using QUIC through Wirescale SHOULD NOT disable 0-RTT
   solely due to cold-path concerns. The agent's packet queue preserves
   0-RTT data during peer establishment.
2. Operators running latency-sensitive UDP workloads (sub-millisecond
   budgets) SHOULD configure pre-warming via the `WirescaleAgent` CRD
   field `preWarmDestinations` to avoid first-packet cold-path delays.
3. The agent SHOULD expose `wirescale_cold_path_queue_drops_total` and
   `wirescale_cold_path_queue_depth` metrics per node for observability.

---

## 6. Three-Tier Control Plane Performance

Wirescale uses a three-tier control hierarchy that separates global
directory functions from per-cluster control and per-node agent state.
This hierarchy ensures that control plane load scales with local cluster
size and active flow count, not with global fleet size. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full design and
[SECURITY.md](SECURITY.md) for the authentication and authorization model.

### Tier 1: Global Directory (`wirescale-directory`)

The global directory maintains O(clusters) state -- it maps cluster IDs
to gateway endpoints and certificate authorities. It does NOT handle
per-node or per-pod state.

| Property | Value |
|----------|-------|
| State size | O(clusters) -- typically < 1000 entries |
| Query rate (steady state) | Low -- only on cross-cluster cache misses |
| Query rate (burst) | ~100-500 queries/sec during large-scale cold starts |
| Latency target | < 10 ms p99 |
| Availability | 3-5 replicas across regions, Raft or etcd-backed |
| Bandwidth | Negligible -- metadata only, no bulk data |

Because the directory handles only cluster-level metadata, a single
3-replica deployment can serve a fleet of 1000+ clusters. The directory
is NOT in any hot path -- it is consulted only during cross-cluster
peer resolution cache misses.

### Tier 2: Cluster Controller (`wirescale-control`)

Each cluster runs its own wirescale-control instances. The controller
knows about local nodes and pods and handles identity resolution, peer
brokering, and policy distribution within the cluster.

| Operation | Latency Target | Throughput Target |
|-----------|---------------|-------------------|
| Peer lookup (by /64 prefix) | < 10 ms p99 | 10K queries/sec per replica |
| Identity lookup (by IP) | < 10 ms p99 | 50K queries/sec per replica |
| Policy pull (per node) | < 100 ms p99 | 1K pulls/sec per replica |
| Node registration | < 50 ms p99 | 100/sec per replica |
| Cross-cluster resolution (via directory) | < 50 ms p99 | 1K queries/sec per replica |

**Horizontal scaling:** wirescale-control is stateless -- it reads from
the Kubernetes API server and maintains a local watch cache. Replicas
scale horizontally with no coordination overhead:

- 3 replicas handle ~30K peer lookups/sec
- With 10K nodes, each establishing ~5 new peers/sec during normal churn:
  50K lookups/sec total, requiring ~5 replicas
- Each replica SHOULD be sized for ~10K queries/sec with < 10 ms p99
  latency

### Tier 3: Node Agent (`wirescale-agent`)

The node agent maintains minimal state: only active WireGuard peers and
a pull-based identity/policy cache. It does NOT watch cluster-wide
resources.

| Property | Value |
|----------|-------|
| WireGuard peers | ~10-50 active (on-demand) |
| Identity cache | ~1K entries (active flows only) |
| Policy map | Local pods only |
| CRD watches | O(1) -- own node resources only |
| gRPC connections | 1-3 persistent to wirescale-control replicas |
| Memory overhead | < 50 MB regardless of cluster/fleet size |

**Pull-based model:** The agent queries wirescale-control on demand
(cache miss) rather than receiving pushed updates for every change in
the cluster. This eliminates the O(N) watch bandwidth that full-mesh
architectures require.

### Agent-to-Control Communication

The agent communicates with wirescale-control over gRPC with mTLS. The
connection SHOULD be persistent (HTTP/2 multiplexing) to avoid TLS
handshake overhead on every query:

- Connection establishment: ~10-20 ms (one-time, at agent startup)
- Per-query overhead on existing connection: ~1-2 ms (serialization +
  network RTT within the cluster)
- The agent SHOULD maintain a connection pool to multiple control replicas
  for failover

### Identity Cache Performance

The agent maintains a local identity cache to avoid redundant control plane
queries. Because traffic patterns follow power-law distributions, a small
cache captures most active flows:

- Typical cache hit ratio: > 95%
- At 95% hit ratio with 10K nodes x 1K new flows/sec = 500 cache
  misses/sec cluster-wide
- wirescale-control handles 500 identity lookups/sec easily with 1 replica
- Cache entries SHOULD be refreshed on a TTL basis (default 60s) and
  invalidated on demand when the agent receives policy update notifications
  for its own pods

---

## 7. State Scaling Analysis

The transition from full-mesh to on-demand peering with hierarchical
prefix aggregation fundamentally changes how per-node resource usage
scales. See [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) for the addressing
model and [ARCHITECTURE.md](ARCHITECTURE.md) for the three-tier
hierarchy.

### The Core Insight: O(1) Per-Node State Relative to Fleet Size

In the full-mesh model, every node holds O(total_hosts) routing state
and O(total_pods) identity state. This collapses at scale. With
on-demand peering and hierarchical prefix aggregation, per-node state
is determined by three factors:

1. **Local cluster size** -- O(local_hosts) intra-cluster /64 routes
2. **Number of remote clusters** -- O(clusters) aggregate routes
3. **Active flow count** -- O(active_flows) identity cache entries

Total per-node state: **O(local_hosts + clusters)**, which is
independent of global fleet size.

### Per-Node Resource Comparison

| Metric | Full Mesh (Broken) | On-Demand Peering (Hyperscale) |
|--------|-------------------|-------------------------------|
| WireGuard peers per node | N-1 | ~10-50 active |
| Routes per node | O(all_hosts) | O(local_hosts + clusters) |
| Identity cache per node | O(all_pods) | O(active_flows) ~1K entries |
| Policy map per node | Grows with cluster | Local pods only |
| CRD watches per node | O(N) events/sec | O(1) own node only |
| Cross-cluster routing | O(remote_hosts) per cluster | O(remote_clusters) |
| Memory per WireGuard peer | ~400 bytes | ~400 bytes (same) |
| Total WG memory (10K nodes, 1 cluster) | ~4 MB/node | ~4-20 KB/node |
| Total WG memory (100K nodes, 10 clusters) | ~40 MB/node | ~4-20 KB/node (unchanged) |
| Total WG memory (1M nodes, 100 clusters) | ~400 MB/node | ~4-20 KB/node (unchanged) |
| Identity cache memory | ~10 MB/node (100K pods) | ~100 KB/node (~1K entries) |

### State Scaling at Hyperscale

The following table shows how per-node state remains bounded as fleet
size grows across clusters:

| Scale | Nodes | Clusters | Routes/Node | Identity Cache/Node | FIB Entries |
|-------|-------|----------|-------------|--------------------|----|
| Single cluster | 10K | 1 | 10K /64s | ~1K active | 10K |
| Multi-cluster | 10K × 10 | 10 | 10K + 9 aggregates | ~1K active | ~10K |
| Hyperscale | 10K × 100 | 100 | 10K + 99 aggregates | ~1K active | ~10K |
| Mega-scale | 10K × 1000 | 1000 | 10K + 999 aggregates | ~1K active | ~11K |

**Key insight: per-node state grows with local cluster size + number of
clusters, NOT with global fleet size.** At 10M nodes across 1000 clusters,
each node still has ~11K routes and ~1K identity cache entries -- the same
order of magnitude as a single 10K-node cluster.

### Why This Matters: Memory and CPU

| Fleet Size | Full Mesh Memory/Node | Hyperscale Memory/Node | Reduction |
|-----------|----------------------|----------------------|-----------|
| 10K nodes, 1 cluster | ~14 MB | ~120 KB | 117x |
| 100K nodes, 10 clusters | ~140 MB | ~120 KB | 1,167x |
| 1M nodes, 100 clusters | ~1.4 GB | ~120 KB | 11,667x |
| 10M nodes, 1000 clusters | ~14 GB | ~130 KB | 107,692x |

Full-mesh memory estimates include WireGuard peer state (~400 bytes/peer),
identity cache (~100 bytes/entry), and FIB entries (~64 bytes/route).
Hyperscale estimates use ~50 active peers, ~1K identity cache entries,
and ~11K FIB entries.

### Control Plane Event Rate Comparison

| Event Type | Full Mesh (per node) | On-Demand (per node) |
|-----------|---------------------|---------------------|
| CRD watch events | O(N) events/sec | O(1) own-node events/sec |
| Identity updates | O(pod_churn) fleet-wide | O(active_flow_churn) local |
| Route updates | O(host_churn) fleet-wide | O(local_host_churn + cluster_add/remove) |
| Policy updates | O(policy_churn) fleet-wide | O(local_pod_policy_churn) |

At 100K nodes with 1% hourly churn, full-mesh produces ~280 events/sec/node
of background watch traffic. On-demand peering produces ~0.003 events/sec/node
(own-node changes only). This is a 5 orders of magnitude reduction.

---

## 8. Hierarchical Prefix Aggregation and Forwarding

The /64-per-host addressing model (see
[ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md)) combined with contiguous per-cluster
prefix allocation enables hierarchical route aggregation that keeps FIB size
bounded regardless of fleet scale.

### Prefix Allocation Hierarchy

```
Global allocation (ULA or GUA):
  Fleet:    fd00:1234::/32      (ULA) or 3fff:1234::/32  (GUA)
    |
    +-- Cluster A: fd00:1234:0001::/48                   (/48 per cluster)
    |     +-- Host 1: fd00:1234:0001:0001::/64           (/64 per host)
    |     +-- Host 2: fd00:1234:0001:0002::/64
    |     +-- ...
    |     +-- Host N: fd00:1234:0001:HHHH::/64
    |
    +-- Cluster B: fd00:1234:0002::/48
    |     +-- Host 1: fd00:1234:0002:0001::/64
    |     +-- ...
    |
    +-- Cluster C: fd00:1234:0003::/48
          +-- ...
```

Each cluster receives a contiguous prefix (/48 for ULA, /48 for GUA).
Within a cluster, each host receives a /64 from that prefix. This
hierarchical allocation enables single-entry aggregate routes for
cross-cluster traffic.

### Intra-Cluster Routing Table

Within a cluster, each node maintains O(local_hosts) /64 routes:

| Cluster Size | /64 Route Entries | FIB Lookup Depth |
|-------------|------------------|------------------|
| 100 hosts | 100 | ~7 |
| 1K hosts | 1K | ~10 |
| 10K hosts | 10K | ~14 |
| 50K hosts | 50K | ~16 |

These routes point to the WireGuard interface with the appropriate peer.
Pod-level /128 routes exist only on the local host for intra-node delivery.

### Cross-Cluster Aggregate Routes

For traffic destined to remote clusters, each node installs one aggregate
route per remote cluster prefix:

```
# Intra-cluster: 10K individual /64 routes
fd00:1234:0001:0001::/64 dev wg0 peer <host-1-key>
fd00:1234:0001:0002::/64 dev wg0 peer <host-2-key>
...
fd00:1234:0001:2710::/64 dev wg0 peer <host-10000-key>

# Cross-cluster: one aggregate per remote cluster
fd00:1234:0002::/48 dev wg0 metric 100    # → Cluster B
fd00:1234:0003::/48 dev wg0 metric 100    # → Cluster C
fd00:1234:0004::/48 dev wg0 metric 100    # → Cluster D
...
```

When a packet matches an aggregate route and no specific /64 peer exists,
the agent intercepts it and triggers the cross-cluster cold path
(see [Section 5](#5-on-demand-peering-performance)).

### Total FIB Size at Scale

| Scale | Local /64s | Cluster Aggregates | Total FIB Entries |
|-------|-----------|-------------------|------------------|
| 10K nodes, 1 cluster | 10K | 0 | 10K |
| 10K nodes, 10 clusters | 10K | 9 | ~10K |
| 10K nodes, 100 clusters | 10K | 99 | ~10K |
| 10K nodes, 1000 clusters | 10K | 999 | ~11K |
| 50K nodes, 100 clusters | 50K | 99 | ~50K |

The key property: **adding remote clusters adds one FIB entry per cluster,
not one entry per remote host.** 1000 remote clusters with 10K nodes each
(10M total remote nodes) adds only 1000 FIB entries.

### Kernel FIB Lookup Performance

The kernel FIB uses a longest-prefix-match trie. Lookup cost is
O(log N) where N is the number of prefix entries:

| FIB Size | Prefix Comparisons per Lookup | Lookup Cost |
|----------|-------------------------------|-------------|
| 1K | ~10 | ~20-30 ns |
| 10K | ~14 | ~25-40 ns |
| 50K | ~16 | ~30-45 ns |
| 100K | ~17 | ~35-50 ns |

FIB lookup remains trivial even at 50K local hosts. At ~20-40 ns per
lookup (see [Section 1](#1-performance-budget)), prefix-based forwarding
adds negligible overhead to the packet pipeline.

### Comparison with Per-Pod Routing

Per-pod routing (as used by some CNIs) inserts a /128 route for every pod
in the cluster. At scale:

- 1M pods = 1M FIB entries, deeper trie, slower lookups
- Route update churn: O(pod_churn) events/sec across all nodes
- Each route update triggers FIB rebalancing

With hierarchical prefix aggregation:
- 10K hosts + 100 clusters = ~10K FIB entries regardless of pod count
- Route update churn: O(host_churn + cluster_churn) -- orders of magnitude
  less than pod churn
- Pod creation/deletion does NOT affect the FIB on any node (local or
  remote)

---

## 9. Cross-Cluster Performance

Wirescale supports cross-cluster communication through the three-tier
control hierarchy with signaling gateways. The performance characteristics
differ from same-cluster communication in cold-path latency only -- the
steady-state data path is identical.

### Cross-Cluster Cold Path (Detailed)

The full cross-cluster resolution chain, step by step:

```
Pod A (Cluster X) → Pod B (Cluster Y):

1. Pod A sends to fd00:1234:CCCC:HHHH::P (matches aggregate route fd00:1234:CCCC::/48)
   Agent intercepts: no WireGuard peer for destination /64           ~μs

2. Agent → local wirescale-control (Cluster X)
   "Resolve fd00:1234:CCCC:HHHH::/64 -- which host, which cluster?" ~5-10 ms
   Controller sees prefix belongs to Cluster Y's allocation.

3. Controller (Cluster X) → wirescale-directory
   "What is the gateway endpoint and CA for Cluster Y?"              ~5-10 ms
   Directory returns: gateway_endpoint, cluster_ca, auth_token

4. Controller (Cluster X) → Controller (Cluster Y)
   "Resolve fd00:1234:CCCC:HHHH::/64 to host endpoint and public key" ~10-30 ms
   Remote controller returns: host_endpoint, wireguard_pubkey,
   allowed_ips, identity_metadata

5. Agent configures WireGuard peer with remote host's details         ~1-2 ms

6. WireGuard initiator handshake (1 RTT to remote host)              ~10-100 ms
   Direct tunnel established between source and destination nodes.

7. Queued packet transmitted. All subsequent packets use warm path.

Total first-packet latency: ~30-150 ms (varies by geographic distance)
```

### Steady-State Cross-Cluster Performance

After peer establishment, cross-cluster encrypted performance is identical
to same-cluster encrypted performance at the same physical distance.
WireGuard does not distinguish between same-cluster and cross-cluster
peers -- the crypto overhead is the same.

**Critical property: the signaling gateway is NOT in the data path.**
After the initial resolution, the WireGuard tunnel runs directly between
the two nodes. This means:

- No throughput bottleneck at the gateway
- No added latency in steady state
- No single point of failure for established flows
- No bandwidth overhead proportional to cross-cluster traffic volume

### Cross-Cluster Identity Resolution

Cross-cluster identity lookups go through the three-tier resolution path:

- First lookup: ~30-50 ms (full chain through directory)
- Cached lookup: ~5-10 ms (local controller has cached remote mapping)
- Identity cache TTL applies across cluster boundaries
- At typical cache hit ratios (> 95%), full-chain lookups are rare in
  steady state
- The agent SHOULD pre-fetch identities for known cross-cluster
  communication patterns during peer establishment

### Cross-Cluster Latency Comparison

| Scenario | Cold Path (First Packet) | Warm Path (Steady State) |
|----------|------------------------|-------------------------|
| Intra-cluster, same DC | ~7-15 ms | Wire latency only (~0.1 ms) |
| Intra-cluster, cross-site | ~55-70 ms | Wire latency only (~1-50 ms) |
| Cross-cluster, same region | ~30-60 ms | Wire latency only (~1-10 ms) |
| Cross-cluster, cross-region | ~60-150 ms | Wire latency only (~10-100 ms) |

The warm-path latency is determined entirely by physical network distance
and WireGuard crypto overhead (~5-10 μs). The control plane adds zero
latency to established flows.

---

## 10. Signaling Gateway Performance

The signaling gateway handles cross-cluster peer resolution requests. It
is a control-plane component only -- it never touches data-plane packets.

### Signaling Gateway Is NOT a Data-Path Component

This distinction is critical for understanding the performance model:

| Property | Traditional VPN Gateway | Wirescale Signaling Gateway |
|----------|----------------------|---------------------------|
| Data path | All cross-cluster traffic flows through | Never in data path |
| Throughput limit | Gateway bandwidth caps cross-cluster | No throughput limit |
| Latency impact | Added hop on every packet | Zero after initial resolution |
| Scaling model | Scale with traffic volume | Scale with new-flow rate only |
| Failure impact | All cross-cluster traffic drops | Only new connections affected |

### Signaling Load Model

The gateway handles signaling traffic only: cross-cluster peer resolution
requests and responses. The load is proportional to the rate of new
cross-cluster connections, NOT to the volume of cross-cluster traffic.

| Metric | Estimate |
|--------|---------|
| Signaling message size | ~500 bytes (pubkey + endpoint + metadata) |
| Cold-path resolutions/sec (steady state) | ~10-100 per cluster |
| Cold-path resolutions/sec (burst, e.g. failover) | ~1K-10K per cluster |
| Bandwidth (steady state) | < 100 KB/s |
| Bandwidth (burst) | < 5 MB/s |
| CPU per resolution | < 0.1 ms (metadata lookup + auth check) |

### Signaling Gateway Sizing

| Fleet Scale | Clusters | Peak Resolutions/sec | Recommended Replicas |
|-----------|---------|---------------------|---------------------|
| Small | 5-10 | ~500 | 2-3 |
| Medium | 10-50 | ~5K | 3-5 |
| Large | 50-200 | ~20K | 5-10 |
| Hyperscale | 200-1000 | ~100K | 10-20 |

The gateway scales horizontally. Each replica handles ~10K resolutions/sec.
State is minimal (O(clusters) directory entries) and can be replicated
across all instances.

### Failure Modes

| Failure | Impact | Recovery |
|---------|--------|----------|
| Gateway replica fails | Load redistributes to remaining replicas | Automatic via load balancer |
| All gateways fail | New cross-cluster connections fail | Existing tunnels continue working |
| Gateway slow (> 100 ms) | Cross-cluster cold path degrades | Circuit breaker; cached resolutions still work |

Existing WireGuard tunnels are unaffected by gateway failures because the
gateway is not in the data path. Only new cross-cluster peer establishments
require the gateway.

---

## 11. Control Plane Scalability

This section analyzes the scalability limits of each tier in the control
hierarchy and identifies the bottlenecks at each scale point.

### Global Directory Scalability

The global directory (wirescale-directory) is the simplest component to
scale because it maintains minimal state:

| Property | Value |
|----------|-------|
| State per cluster | ~1 KB (endpoint, CA cert, metadata) |
| Total state (1000 clusters) | ~1 MB |
| Read:write ratio | ~1000:1 (reads dominate) |
| Write events | Cluster add/remove, gateway endpoint change |
| Consistency model | Eventually consistent (TTL-based refresh) |

The directory SHOULD be backed by a replicated key-value store (etcd or
similar). At 1 MB of total state, the entire directory fits in memory on
every replica. Query latency is bounded by network RTT, not by lookup
cost.

**Scaling limit:** The directory is effectively unbounded -- 10K clusters
would still be < 10 MB of state. The bottleneck shifts to human
operational complexity long before the directory becomes a technical
constraint.

### Cluster Controller Scalability

The cluster controller (wirescale-control) is the most heavily loaded
component in the hierarchy. Its scalability is determined by:

1. **Kubernetes API server watch efficiency** -- each replica watches
   node, pod, and identity CRDs for the local cluster
2. **Query rate from agents** -- proportional to new-flow rate across
   all nodes
3. **Cross-cluster resolution forwarding** -- queries proxied through
   to remote clusters

| Cluster Size | Agent Query Rate | Controller Replicas | API Server Load |
|-------------|-----------------|--------------------|----|
| 1K nodes | ~5K queries/sec | 1-2 | Light |
| 5K nodes | ~25K queries/sec | 3-5 | Moderate |
| 10K nodes | ~50K queries/sec | 5-10 | Significant |
| 50K nodes | ~250K queries/sec | 25-50 | Heavy (shard API server) |

**Scaling limit:** At 50K+ nodes per cluster, the Kubernetes API server
itself becomes the bottleneck for watch efficiency. Clusters SHOULD be
kept at 10K nodes or fewer, with cross-cluster federation used to scale
beyond that.

### Node Agent Scalability

The node agent has the simplest scalability story because its resource
usage is bounded by active flow count, not cluster or fleet size:

| Metric | 1K-Node Cluster | 10K-Node Cluster | 10M-Node Fleet |
|--------|----------------|-----------------|----------------|
| WireGuard peers | ~10-50 | ~10-50 | ~10-50 |
| Identity cache | ~1K entries | ~1K entries | ~1K entries |
| FIB entries | ~1K | ~10K | ~10K + ~1K aggregates |
| Memory | ~20 MB | ~30 MB | ~30 MB |
| CPU (control plane) | < 1% | < 1% | < 1% |

**Scaling limit:** The agent is effectively O(1) relative to fleet size.
Its resource usage is determined entirely by local workload communication
patterns.

### End-to-End Control Plane Latency Budget

| Path | Component Chain | Total Latency Target |
|------|---------------|---------------------|
| Intra-cluster peer setup | Agent → Controller → Agent | < 15 ms p99 |
| Cross-cluster peer setup | Agent → Controller → Directory → Remote Controller → Agent | < 150 ms p99 |
| Identity resolution (cached) | Agent local cache | < 1 ms p99 |
| Identity resolution (miss) | Agent → Controller | < 10 ms p99 |
| Policy refresh | Agent → Controller | < 100 ms p99 |

---

## 12. Kernel Tuning

The wirescale-agent applies these sysctls automatically on startup. These
settings are valid for both intra-cluster and cross-cluster peering
topologies.

### Network Buffers

```bash
# UDP socket buffers -- critical above 1 Gbps
net.core.rmem_max = 134217728          # 128 MB
net.core.wmem_max = 134217728          # 128 MB
net.core.rmem_default = 16777216       # 16 MB
net.core.wmem_default = 16777216       # 16 MB
net.ipv4.udp_mem = 4096 87380 134217728

# TCP buffers (for GRO superpackets)
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 131072 134217728
```

### NAPI and Backlog

```bash
# Increase NAPI budget for high-PPS workloads
net.core.netdev_budget = 1200          # default 300
net.core.netdev_budget_usecs = 4000    # default 2000
net.core.netdev_max_backlog = 10000    # default 1000
```

### Congestion Control

```bash
# BBR reduces bufferbloat through WireGuard tunnels
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

### Forwarding

```bash
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
```

### BPF JIT

```bash
# eBPF JIT compilation -- strongly recommended for production datapaths
net.core.bpf_jit_enable = 1
```

### RSS / RPS / RFS on Physical NIC

The wirescale-agent configures Receive Packet Steering to distribute
WireGuard UDP flows across all CPU cores:

```bash
# Enable RPS on all RX queues (all CPUs)
for q in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo ffffffff > "$q"     # adjust mask for CPU count
done

# Enable RFS (Receive Flow Steering) for socket locality
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
for q in /sys/class/net/eth0/queues/rx-*/rps_flow_cnt; do
    echo 4096 > "$q"
done
```

For NICs with hardware RSS (Intel E810, Mellanox ConnectX), configure RSS for
outer UDP WireGuard tuples by default; document vendor-specific inner-flow
hashing separately if supported:

```bash
ethtool -N eth0 rx-flow-hash udp4 sdfn    # src/dst IP + src/dst port
ethtool -N eth0 rx-flow-hash udp6 sdfn
```

### NUMA-Aware Packet Processing

Section 12 documents RSS/RPS configuration for distributing WireGuard
UDP flows across CPU cores. At 40-100 Gbps link speeds, multi-core
distribution alone is insufficient -- cross-NUMA memory accesses add
~70-100 ns of latency per cache-line miss and reduce effective memory
bandwidth by 30-50%. Wirescale deployments at these speeds MUST ensure
NUMA-local affinity for all components of the packet processing pipeline.

#### NUMA Locality Requirements

The following components participate in per-packet processing and MUST
be co-located on the same NUMA node as the physical NIC:

1. **NIC interrupt handlers (hardirq).** IRQ affinity MUST pin NIC
   receive interrupts to CPUs on the NUMA node local to the NIC's PCIe
   slot.
2. **NAPI poll / softirq threads.** These run on the CPU that received
   the interrupt and inherit its NUMA placement from IRQ affinity.
3. **XDP programs on the physical NIC.** XDP runs in softirq context
   on the interrupt CPU; correct IRQ affinity ensures NUMA locality.
4. **WireGuard kthreads (threaded NAPI on wg0).** After decryption,
   threaded NAPI kthreads SHOULD be affined to the same NUMA node via
   `taskset` or cgroup cpuset. The scheduler MAY migrate them otherwise.
5. **BPF map memory.** Maps used in the hot path (identity_cache,
   policy_map, peer_cache) SHOULD be allocated on NUMA-local memory.

#### IRQ Affinity Configuration

The wirescale-agent MUST configure NIC IRQ affinity at startup. For a
NIC on NUMA node 0 with CPUs 0-15:

```bash
# Identify NUMA node for the NIC
NIC_NUMA=$(cat /sys/class/net/eth0/device/numa_node)
# Get CPU list for that NUMA node
NUMA_CPUS=$(cat /sys/devices/system/node/node${NIC_NUMA}/cpulist)

# Pin each NIC IRQ to NUMA-local CPUs
for irq in $(grep eth0 /proc/interrupts | awk -F: '{print $1}'); do
    echo "$NUMA_CPUS" > /proc/irq/${irq}/smp_affinity_list
done
```

When RPS is used (software steering), the `rps_cpus` mask documented in
Section 12 MUST be restricted to NUMA-local CPUs rather than set to
`ffffffff`. Steering packets to a remote NUMA node for softirq processing
negates the benefit of multi-core distribution.

#### WireGuard kthread Affinity

Threaded NAPI kthreads for `wg0` appear as `napi/wg0-<N>` in the
process table. The agent SHOULD pin these to the NIC-local NUMA node:

```bash
for pid in $(pgrep -f 'napi/wg0'); do
    taskset -pc "$NUMA_CPUS" "$pid"
done
```

If the system has multiple NICs on different NUMA nodes (e.g., bonded
interfaces), the agent MUST identify which physical NIC carries WireGuard
traffic and pin kthreads to that NIC's NUMA node.

#### BPF Map NUMA Allocation

BPF maps are allocated from the CPU that calls `bpf_map_create`. The
agent MUST ensure that map creation runs on a NUMA-local CPU so the
backing pages are allocated from local memory. For the hot-path maps
(identity_cache, policy_map, peer_cache), this avoids cross-NUMA
lookups on every packet.

```bash
# Run BPF loader pinned to NUMA-local CPUs
numactl --cpunodebind=$NIC_NUMA --membind=$NIC_NUMA \
    wirescale-agent load-bpf
```

Alternatively, the agent MAY use `set_mempolicy(MPOL_BIND)` before map
creation to force NUMA-local allocation programmatically.

#### XDP Redirect and NUMA Boundaries

`bpf_redirect_map` and `bpf_redirect` transmit packets on the target
device's TX queue. If the target NIC is on a different NUMA node than
the source NIC, the redirect crosses a NUMA boundary. This scenario
arises when NAT64 redirects from a `nat64` dummy interface to a physical
NIC on a different NUMA node.

Deployments MUST ensure the physical NIC used for WireGuard egress is
on the same NUMA node as the NIC used for WireGuard ingress. On systems
with a single NIC this is automatic. On multi-NIC systems, the agent
SHOULD log a warning if NUMA mismatch is detected.

#### Monitoring

Operators SHOULD use the following tools to verify NUMA-local operation:

| Tool | Purpose |
|------|---------|
| `numastat -p $(pgrep wirescale)` | Per-node memory allocation for the agent |
| `numastat -m` | System-wide NUMA memory distribution |
| `perf stat -e node-load-misses` | Cross-NUMA cache-line transfers |
| `cat /proc/interrupts` | Verify IRQ distribution across CPUs |
| `lstopo` (hwloc) | Visualize NIC-to-NUMA topology |

A sustained `node-load-misses` rate above 5% of total memory accesses
during packet processing indicates NUMA misconfiguration. The agent
SHOULD expose `wirescale_numa_cross_node_redirects_total` as a
Prometheus metric when redirect targets cross NUMA boundaries.

---

## 13. Hardware Acceleration

### Tier 1: Available Now

| Technology | Throughput | Availability |
|-----------|-----------|-------------|
| Kernel WireGuard + GRO/GSO | 10-15 Gbps/core | Linux >= 5.19 |
| + Big TCP GSO (512 KB) | +15% over 64KB GSO | Linux >= 6.13 |
| + Threaded NAPI | 48 Gbps (multi-tunnel) | Linux >= 5.17 |
| + AVX-512 ChaCha20-Poly1305 | ~10 Gbps/core | Intel Xeon, AMD Zen 4+ |
| eBPF JIT (TC NAT64) | 2-5 Mpps/core | Linux >= 5.0 |
| NIC hardware GRO/checksum | Frees CPU cycles | All modern NICs |

NPTv6 egress translation uses the same eBPF JIT TC path as NAT64 and
benefits from identical GRO/GSO amortization. See [EGRESS.md](EGRESS.md)
Section 3 for the NPTv6 implementation and Section 11 for offload
interaction.

### Tier 2: Available with Specialized Hardware

| Technology | Throughput | Requirements |
|-----------|-----------|-------------|
| Intel QAT Gen3 + VPP | ~46 Gbps | Xeon Scalable 4th gen, VPP dataplane |
| Intel QAT Gen2 + VPP | ~10 Gbps | Xeon D-2700, VPP dataplane |
| AF_XDP zero-copy | 10-20 Mpps I/O | Intel E810/i40e/ice, mlx5 |

### Tier 3: Future / Research

| Technology | Potential | Status |
|-----------|----------|--------|
| WireGuard Inline (Netdev 0x18) | 2x single-tunnel throughput | Research, not upstreamed |
| DPDK MoonWire pipeline | ~40 Gbps, 6.2 Mpps | Academic prototype |
| NIC ChaCha20 offload | Line rate at any speed | No vendor support yet |
| io_uring for wireguard-go | Lower syscall overhead | No implementation yet |

### Recommended Configuration by Link Speed

**10 Gbps (most common in k8s):**
- Kernel WireGuard + GRO/GSO = sufficient on any modern CPU
- Single core can handle 10G with GSO amortization
- No special hardware needed

**25 Gbps:**
- Kernel WireGuard + threaded NAPI
- Enable RSS on physical NIC for multi-core RX distribution
- AVX-512 helpful but not required
- 2-4 cores dedicated to crypto

**40-100 Gbps:**
- Multi-tunnel architecture (natural in a mesh with many peers)
- Threaded NAPI mandatory
- Jumbo frames (MTU 9000) strongly recommended
- Consider VPP + QAT for 100G single-tunnel scenarios
- AF_XDP for NAT64 I/O path for maximum throughput at 100G+

---

## 14. Benchmarks and Targets

### Baseline: Unencrypted IPv6 (Ceiling)

| Link | iperf3 TCP | iperf3 UDP |
|------|-----------|-----------|
| 10G  | 9.4 Gbps  | 9.8 Gbps  |
| 25G  | 23.5 Gbps | 24.5 Gbps |

### Target: Wirescale Encrypted IPv6 (Pod-to-Pod)

| Link | Target | Technique |
|------|--------|-----------|
| 10G  | 9.0+ Gbps (96% line rate) | Kernel WG + GRO/GSO |
| 25G  | 20+ Gbps (80% line rate) | + threaded NAPI + RSS |
| 100G | 40-60 Gbps | + multi-tunnel + jumbo frames |

### Target: Wirescale IPv4 via CLAT (Pod-to-Pod)

| Link | Target | Additional Cost vs. Pure IPv6 |
|------|--------|------------------------------|
| 10G  | 8.5+ Gbps | ~5% overhead (2 × TC eBPF CLAT) |
| 25G  | 18+ Gbps | ~10% overhead |

### Target: Wirescale IPv4 via NAT64 (Pod-to-External)

| Link | Target | Additional Cost vs. Pure IPv6 |
|------|--------|------------------------------|
| 10G  | 8.0+ Gbps | ~10% overhead (CLAT + NAT64 + eBPF SNAT) |
| 25G  | 16+ Gbps | ~15% overhead |

### Known Bottleneck: Single-Peer Encryption

The kernel WireGuard TX path pins each peer's encryption worker to one
CPU core. A single peer (two-node cluster) is limited to that core's
ChaCha20 throughput:

| CPU | Single-Peer Max |
|-----|----------------|
| Intel Xeon (no AVX-512) | ~3-5 Gbps |
| Intel Xeon (AVX-512) | ~8-10 Gbps |
| AMD EPYC (Zen 4, AVX-512) | ~8-10 Gbps |
| Apple M2 (ARM NEON) | ~5-7 Gbps |

This is a kernel architectural limitation. The Netdev 0x18 "WireGuard
Inline" proposal addresses it but has not been upstreamed.

### Target: Cold-Path Latency

| Scenario | Target p50 | Target p99 |
|----------|-----------|-----------|
| Intra-cluster, same-DC | < 10 ms | < 15 ms |
| Intra-cluster, cross-site | < 60 ms | < 100 ms |
| Cross-cluster, same region | < 50 ms | < 80 ms |
| Cross-cluster, cross-region | < 100 ms | < 150 ms |
| Cached cross-cluster (GC'd peer) | < 10 ms | < 15 ms |
| Peer GC cycle (100 active peers) | < 1 ms | < 5 ms |

### Target: Control Plane Latency

| Operation | Target p50 | Target p99 |
|-----------|-----------|-----------|
| Peer lookup (intra-cluster) | < 5 ms | < 10 ms |
| Peer lookup (cross-cluster, cold) | < 30 ms | < 50 ms |
| Identity lookup (cached) | < 0.1 ms | < 1 ms |
| Identity lookup (miss) | < 5 ms | < 10 ms |
| Policy pull (per node) | < 50 ms | < 100 ms |
| Node registration | < 25 ms | < 50 ms |
| Directory query | < 5 ms | < 10 ms |
| Identity cache hit ratio | > 95% | > 90% (cold start) |

### Target: State Efficiency at Scale

| Scale | WG Memory/Node | Identity Cache/Node | FIB Entries/Node |
|-------|---------------|--------------------|-----------------|
| 1K nodes, 1 cluster | < 20 KB | < 100 KB | ~1K |
| 10K nodes, 1 cluster | < 20 KB | < 100 KB | ~10K |
| 10K × 10 clusters | < 20 KB | < 100 KB | ~10K |
| 10K × 100 clusters | < 20 KB | < 100 KB | ~10K |
| 10K × 1000 clusters | < 20 KB | < 100 KB | ~11K |

Per-node WireGuard memory and identity cache MUST remain bounded
independent of fleet size. FIB entries scale with local host count plus
cluster count, not with total hosts or pod count (see
[Section 8](#8-hierarchical-prefix-aggregation-and-forwarding)).

### Target: Signaling Gateway Performance

| Metric | Target |
|--------|--------|
| Resolution latency (p50) | < 20 ms |
| Resolution latency (p99) | < 50 ms |
| Resolution throughput (per replica) | > 10K/sec |
| Steady-state bandwidth | < 100 KB/s per cluster |
| Burst bandwidth (failover) | < 5 MB/s per cluster |
| Data-plane overhead | Zero (not in path) |

---

## 15. MTU Strategy

MTU misconfiguration is a common cause of WireGuard underperformance.
Incorrect MTU causes either fragmentation (CPU-expensive) or path MTU
black holes (connections hang).

### Overhead Calculation

```
WireGuard outer header (over IPv6 underlay):
  IPv6 header:       40 bytes
  UDP header:         8 bytes
  WireGuard data hdr:16 bytes (type/reserved + receiver index + counter)
  Poly1305 tag:      16 bytes
  ─────────────────────────
  Total overhead:    80 bytes
```

For IPv6-underlay WireGuard paths in this architecture:
- Inner packet MTU MUST be `Physical MTU - 80`.
- Pod MTU SHOULD reserve additional safety margin for extension headers.

### Configuration

| Physical MTU | Inner MTU (wg0) | Pod MTU (eth0) | TCP MSS |
|-------------|----------------|---------------|---------|
| 1500 | 1420 | 1412 (safety margin) | 1372 (IPv6 TCP) / 1352 (IPv4 via CLAT) |
| 9000 (jumbo) | 8920 | 8912 | 8872 / 8852 |

The pod MTU SHOULD be set 8 bytes below the WireGuard inner MTU as a safety
margin for extension headers and translation overhead.

### MSS Clamping

Target behavior: wirescale-agent SHOULD program MSS clamping to prevent TCP connections from
sending oversized segments:

```
table inet wirescale_mss {
    chain forward {
        type filter hook forward priority mangle; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }
}
```

### Jumbo Frame Recommendation

For clusters with jumbo frame support, **MTU 9000 is often beneficial.** The
benefits can compound:

1. Fewer packets per unit of data = less per-packet overhead
2. GRO/GSO can build larger superpackets = better amortization
3. Less CPU time in packet processing = more headroom for encryption
4. ~15-25% throughput improvement at 10G, more at higher speeds

Target behavior: wirescale-agent auto-detects physical MTU and configures wg0
and pod MTUs accordingly.

### MTU for Cross-Cluster Tunnels

Cross-cluster tunnels MAY traverse paths with different physical MTUs
than intra-cluster tunnels. The agent SHOULD:

1. Use PMTUD (Path MTU Discovery) for cross-cluster WireGuard endpoints
2. Set the inner MTU conservatively (based on minimum known path MTU)
3. Fall back to 1420 inner MTU if PMTUD is unavailable

---

## Appendix A: Monitoring Performance

### WireGuard Handshake and Transfer Stats

```bash
# Per-peer stats
wg show wg0

# Detailed: transfer bytes, last handshake, endpoint
wg show wg0 dump
```

### eBPF Program Stats

```bash
# NAT64 program packet counts
bpftool prog show
bpftool map dump name nat64_stats

# TC filter stats
tc -s filter show dev wg0 ingress
tc -s filter show dev nat64 ingress
```

### Per-CPU Utilization

```bash
# Identify which cores handle WireGuard work
perf top -g -p $(pgrep -f kworker.*wg)

# Softirq distribution
watch -n1 'cat /proc/softirqs | grep NET'

# Check if a single core is bottlenecked
mpstat -P ALL 1
```

### Throughput Validation

```bash
# Encrypted pod-to-pod throughput
kubectl exec -it netperf-client -- iperf3 -c <pod-ipv6> -t 30

# IPv4 via CLAT throughput
kubectl exec -it netperf-client -- iperf3 -c <pod-ipv4> -t 30

# IPv4 via NAT64 to external
kubectl exec -it netperf-client -- iperf3 -c <external-ipv4> -t 30
```

### Control Plane Monitoring

```bash
# Agent cache statistics
curl -s localhost:9091/metrics | grep wirescale_cache

# Controller query rate and latency
curl -s localhost:9092/metrics | grep wirescale_control_query

# Directory resolution rate
curl -s localhost:9093/metrics | grep wirescale_directory

# Cross-cluster cold-path latency histogram
curl -s localhost:9091/metrics | grep wirescale_cold_path_duration
```

---

## Appendix B: Companion Documents

| Document | Coverage |
|----------|---------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Three-tier hierarchy, component design, CRDs, packet flows |
| [SECURITY.md](SECURITY.md) | Identity model, mTLS, policy enforcement, eBPF security maps |
| [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) | /64-per-host addressing, BGP integration, GUA allocation |
| [CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md) | Architecture comparison with Cilium CNI |
