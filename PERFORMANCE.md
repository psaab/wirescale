# Wirescale: Line-Rate Performance Engineering

> How Wirescale achieves wire-speed IPv4/IPv6 throughput on an IPv6-only
> underlay with WireGuard encryption and NAT64/CLAT translation.

---

## Table of Contents

1. [Performance Budget](#1-performance-budget)
2. [WireGuard at Line Rate](#2-wireguard-at-line-rate)
3. [eBPF NAT64/CLAT Fast Path](#3-ebpf-nat64clat-fast-path)
4. [Packet Pipeline Architecture](#4-packet-pipeline-architecture)
5. [Kernel Tuning](#5-kernel-tuning)
6. [Hardware Acceleration](#6-hardware-acceleration)
7. [Benchmarks and Targets](#7-benchmarks-and-targets)
8. [MTU Strategy](#8-mtu-strategy)

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

The CPU spends nearly zero time on encryption overhead when GSO is working.
The bottleneck shifts to memory bandwidth and PCIe.

### Threaded NAPI: Unlocking Multi-Core

Vanilla kernel WireGuard uses a single NAPI instance per interface, which
serializes all RX processing onto one CPU. At ~180 kpps this core saturates.

**Wirescale enables threaded NAPI on every `wg0` interface:**

```bash
echo 1 > /sys/class/net/wg0/threaded
```

This moves NAPI polling from the softirq context to a dedicated kthread
that the scheduler can migrate across cores.

**Impact:**
- 16 tunnels, 32 cores, standard NAPI: ~13 Gbps
- 16 tunnels, 32 cores, threaded NAPI: **~48 Gbps** (3.7x)

The wirescale-agent enables threaded NAPI automatically at boot.

### Multi-Tunnel Scaling

For clusters with many nodes, the mesh naturally creates multiple WireGuard
peers per node. Each peer's encryption worker is pinned to a different CPU
core by the kernel. With N peers, encryption work distributes across up to
N cores.

On a node with 16 peers (16 remote nodes) and 32 available cores:
- Each peer's TX encryption runs on a dedicated core
- RX decryption uses padata to fan out across all cores
- Aggregate throughput: **up to 48 Gbps** (threaded NAPI)

For single-peer scenarios (e.g., a two-node cluster), the single-core
encryption limit applies (~3-10 Gbps depending on CPU). The Netdev 0x18
"WireGuard Inline" research proposes future kernel patches to parallelize
single-peer encryption.

### Bypass Conntrack

If nf_conntrack is loaded, every packet traverses the conntrack hash table.
For WireGuard traffic that doesn't need NAT on the outer UDP:

```bash
# The wirescale-agent programs these nftables rules:
table inet wirescale_raw {
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;
        udp dport 51820 notrack
    }
    chain output {
        type filter hook output priority raw; policy accept;
        udp sport 51820 notrack
    }
}
```

This eliminates per-packet conntrack lookups for the outer WireGuard UDP
flow, saving ~100 ns per packet.

---

## 3. eBPF NAT64/CLAT Fast Path

### Why TC eBPF, Not XDP

XDP runs at the NIC driver level before sk_buff allocation -- it is the
fastest eBPF hook point. However, **XDP cannot be used for NAT64
translation on WireGuard interfaces** for three reasons:

1. WireGuard's `wg0` is a virtual L3 device with no Ethernet header. XDP
   programs that parse `struct ethhdr` will fault.
2. XDP on `wg0` can only run in `xdpgeneric` mode (software emulation),
   which is slower than TC.
3. IPv4-to-IPv6 translation grows the packet by 20 bytes.
   `bpf_xdp_adjust_head()` requires pre-allocated headroom that the
   WireGuard driver doesn't guarantee. TC's `bpf_skb_change_proto()`
   handles this correctly.

**TC eBPF (clsact qdisc) on `wg0` is the correct and optimal hook.**
It fires immediately after WireGuard decrypts the inner packet -- one
eBPF program call, one redirect, no additional kernel stack traversal.

### Where XDP IS Used

XDP runs on the **physical NIC** (`eth0`) for:
- Early drop of malformed/attack traffic (DDoS mitigation)
- RSS steering of WireGuard UDP flows across RX queues
- Pre-filtering before packets enter the WireGuard decrypt path

This protects the WireGuard crypto path from being overwhelmed by junk
traffic at up to 26 Mpps per core.

### NAT64 eBPF Program (TC on wg0 Ingress)

The NAT64 translation program attaches to `wg0`'s TC ingress hook. It
intercepts packets destined for `64:ff9b::/96` (the NAT64 prefix) after
WireGuard decrypts them:

```
wg0 receives decrypted IPv6 packet
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
nftables MASQUERADE -- replace 169.254.64.X with node's IPv4
  |
  v
Wire
```

**Performance:** The eBPF translation path is O(1) per packet -- one hash
map lookup for the address mapping, fixed-cost header rewrite, and a single
redirect. No conntrack in eBPF; stateful NAT is deferred to the kernel's
nftables MASQUERADE on the physical interface.

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
  - Deterministic mapping: 100.64.N.P -> fd00:ws:N::P
  - If dst is another pod: dst 100.64.M.Q -> fd00:ws:M::Q
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
  | src: fd00:ws:1::5, dst: 64:ff9b::5db8:d822
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
nftables MASQUERADE on eth0
  |
  v
Physical NIC TX (hardware checksum offload)
  |
  v
Wire (IPv4 packet, source = node's IPv4)
```

**Total eBPF programs in path: 2** (CLAT on veth + NAT64 on nat64 iface)
**Total kernel stack traversals: 1** (routing decision)
**Total copies: 0 extra** (all in-place sk_buff manipulation)

### Complete Fast Path (Pod-to-Pod Cross-Node, IPv6 Native)

```
Pod A: send to fd00:ws:2::7
  |
  v
eth0 -> veth -> host routing
  |
  | route: fd00:ws:2::/64 dev wg0
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
  100.64.1.5 -> fd00:ws:1::5 (src)
  100.64.2.7 -> fd00:ws:2::7 (dst)  [deterministic, no NAT64 prefix!]
  |
  v
Host routing: fd00:ws:2::/64 dev wg0
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
  | fd00:ws:1::5 -> 100.64.1.5 (src)
  | fd00:ws:2::7 -> 100.64.2.7 (dst)
  v
clat0 TUN -> Pod B app sees IPv4
```

**eBPF programs in path: 2** (CLAT at each end)
**NAT64 engine: not involved** (intra-mesh IPv4 maps directly to IPv6)
**Key insight:** The WireGuard tunnel always carries native IPv6. The CLAT
translation happens at the pod boundary, not at the tunnel boundary. The
mesh never sees IPv4 packets.

---

## 5. Kernel Tuning

The wirescale-agent applies these sysctls automatically on startup.

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
# eBPF JIT compilation -- mandatory for performance
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

For NICs with hardware RSS (Intel E810, Mellanox ConnectX), configure the
RSS hash to include the inner WireGuard flow where supported:

```bash
ethtool -N eth0 rx-flow-hash udp4 sdfn    # src/dst IP + src/dst port
ethtool -N eth0 rx-flow-hash udp6 sdfn
```

---

## 6. Hardware Acceleration

### Tier 1: Available Now

| Technology | Throughput | Availability |
|-----------|-----------|-------------|
| Kernel WireGuard + GRO/GSO | 10-15 Gbps/core | Linux >= 5.19 |
| + Big TCP GSO (512 KB) | +15% over 64KB GSO | Linux >= 6.13 |
| + Threaded NAPI | 48 Gbps (multi-tunnel) | Linux >= 5.17 |
| + AVX-512 ChaCha20-Poly1305 | ~10 Gbps/core | Intel Xeon, AMD Zen 4+ |
| eBPF JIT (TC NAT64) | 2-5 Mpps/core | Linux >= 5.0 |
| NIC hardware GRO/checksum | Frees CPU cycles | All modern NICs |

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
- AF_XDP for NAT64 I/O path if conntrack becomes a bottleneck

---

## 7. Benchmarks and Targets

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
| 10G  | 8.0+ Gbps | ~10% overhead (CLAT + NAT64 + MASQUERADE) |
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

---

## 8. MTU Strategy

MTU misconfiguration is the #1 cause of WireGuard underperformance.
Incorrect MTU causes either fragmentation (CPU-expensive) or path MTU
black holes (connections hang).

### Overhead Calculation

```
WireGuard outer header (over IPv6 underlay):
  IPv6 header:       40 bytes
  UDP header:         8 bytes
  WireGuard header:   4 bytes (type + reserved)
  WireGuard counter:  4 bytes
  Poly1305 tag:      16 bytes
  ─────────────────────────
  Total overhead:    72 bytes

Inner packet MTU = Physical MTU - 72
```

### Configuration

| Physical MTU | Inner MTU (wg0) | Pod MTU (eth0) | TCP MSS |
|-------------|----------------|---------------|---------|
| 1500 | 1428 | 1420 (safety margin) | 1380 (IPv6 TCP) / 1360 (IPv4 via CLAT) |
| 9000 (jumbo) | 8928 | 8920 | 8880 / 8860 |

The pod MTU is set 8 bytes below the WireGuard inner MTU as a safety
margin for IPv6 extension headers and CLAT overhead.

### MSS Clamping

The wirescale-agent programs MSS clamping to prevent TCP connections from
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

For clusters with jumbo frame support, **MTU 9000 is strongly
recommended.** The benefits compound:

1. Fewer packets per unit of data = less per-packet overhead
2. GRO/GSO can build larger superpackets = better amortization
3. Less CPU time in packet processing = more headroom for encryption
4. ~15-25% throughput improvement at 10G, more at higher speeds

The wirescale-agent auto-detects the physical MTU and configures wg0 and
pod MTUs accordingly.

---

## Appendix: Monitoring Performance

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
