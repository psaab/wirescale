# Wirescale: Outbound Internet Access Architecture

> NPTv6 egress translation, NAT64 for legacy IPv4, DNS-aware policy
> enforcement, URL/FQDN filtering, flow observability, and traffic
> containment — at line rate.

---

## Table of Contents

1. [Design Goals and Constraints](#1-design-goals-and-constraints)
2. [Egress Data Path Overview](#2-egress-data-path-overview)
3. [NPTv6: Stateless IPv6 Prefix Translation](#3-nptv6-stateless-ipv6-prefix-translation)
4. [SIIT-DC: Stateless IPv4 Internet Access](#4-siit-dc-stateless-ipv4-internet-access)
5. [DNS Interception and FQDN Resolution](#5-dns-interception-and-fqdn-resolution)
6. [Egress Policy Engine](#6-egress-policy-engine)
7. [URL and SNI Filtering](#7-url-and-sni-filtering)
8. [Traffic Containment and Rate Limiting](#8-traffic-containment-and-rate-limiting)
9. [Flow Observability](#9-flow-observability)
10. [Threat Detection and Response](#10-threat-detection-and-response)
11. [Performance Engineering](#11-performance-engineering)
12. [CRDs and Configuration](#12-crds-and-configuration)
13. [Packet Flow Walkthroughs](#13-packet-flow-walkthroughs)
14. [Interaction with Cilium](#14-interaction-with-cilium)

---

## 1. Design Goals and Constraints

### Goals

1. **Transparent internet access.** Pods reach the internet without
   configuration. IPv6 destinations are reachable natively via NPTv6;
   IPv4-only destinations are reachable via DNS64+NAT64. No proxy
   configuration, no CONNECT tunnels, no application changes.

2. **Complete flow observability.** Every outbound connection is logged
   with: source pod identity, destination IP, resolved FQDN, SNI (for
   TLS), port, protocol, bytes transferred, duration, and policy
   verdict. Operators see the full picture without sampling.

3. **FQDN-aware policy.** Egress rules reference domain names, not IPs.
   DNS resolution is tracked so that IP-level enforcement maps back to
   the FQDN the pod intended to reach. Wildcard patterns supported.

4. **Containment at speed.** When a workload goes rogue — crypto miners,
   data exfiltration, C2 callbacks — the operator can quarantine a pod,
   namespace, or entire cluster's egress within seconds. Rate limits
   cap bandwidth and connection rates per pod.

5. **Line-rate performance.** NPTv6 translation, verdict enforcement,
   and rate limiting happen in eBPF on the per-packet fast path. All
   intelligence (DNS parsing, SNI extraction, policy compilation,
   flow enrichment) runs in a userspace daemon that writes pre-computed
   verdicts to BPF maps. No userspace proxy in the data plane.

### Constraints

- Internal pod addresses use ULA (`fd00:1234:CCCC:HHHH::P`) in overlay
  mode or GUA (`3fff:1234:CCCC:HHHH::P`) in routable-prefix mode.
- ULA addresses are not routable on the public internet. NPTv6
  translates ULA → GUA at the egress boundary.
- GUA-mode clusters MAY skip NPTv6 (addresses are already routable) but
  SHOULD still use it for observability and policy enforcement at a
  defined egress chokepoint.
- IPv4 internet requires NAT64 (already designed in ARCHITECTURE.md §8).
- DNS is the control point: all FQDN resolution is observable and
  policy-enforced.

---

## 2. Egress Data Path Overview

Outbound internet traffic traverses a layered pipeline. eBPF handles
only the per-packet fast path (translation, verdict enforcement, rate
limiting). All intelligence — DNS parsing, SNI extraction, FQDN policy
compilation, flow enrichment, anomaly detection — runs in a userspace
daemon that writes pre-computed verdicts to BPF maps.

### 2.1 Data Path (eBPF — Per Packet)

```
Pod (ULA fd00:1234:0001:0042::5)
  │
  ├─ [1a] TC egress on pod veth ────────── Verdict enforcement
  │       • quarantine bit check (instant kill switch)
  │       • egress_ip_policy LPM lookup (pod_id + dest_ip → verdict)
  │       • DENY → drop; ALLOW → rate limit check → continue
  │       • emit flow record to ring buffer (5-tuple, verdict, pkt_len)
  │
  ├─ [1b] TC ingress on pod veth ────────── Packet mirror (async)
  │       • UDP src port 53 → copy DNS response to mirror ring buffer
  │       • TCP dst 443 + SYN → copy ClientHello to mirror ring buffer
  │       • TC_ACT_OK always (never blocks — mirror is advisory)
  │
  ├─ [2] Host routing table ────────────── Route selection
  │       • Mesh destination → wg0 (WireGuard, no NPTv6)
  │       • 64:ff9b::/96 → nat64 interface (IPv4 internet)
  │       • Default route → nptv6 interface (IPv6 internet)
  │
  ├─ [3a] TC on nptv6 interface ────────── NPTv6 translation (IPv6 internet)
  │       • ULA src fd00:1234:0001:0042::5
  │         → GUA src 3fff:1234:0001:0042::5
  │       • Stateless prefix rewrite + IID adjustment (RFC 6296)
  │       • Redirect to physical NIC
  │
  ├─ [3b] TC on nat64 interface ────────── SIIT-DC translation (IPv4 internet)
  │       • Extract IPv4 dest from 64:ff9b::C0A8:0101
  │       • IPv6 → IPv4 stateless header translation (RFC 7915)
  │       • Source IPv4 derived arithmetically: 100.64.H.P (EAM)
  │       • No state table — CGNAT address encodes pod identity
  │       • Redirect to physical NIC
  │
  └─ [4] Physical NIC egress ───────────── Wire
```

Return path is the reverse: physical NIC TC ingress → destination
CGNAT address `100.64.H.P` arithmetically maps back to pod IPv6
`fd00:1234:CCCC:HHHH::P` → SIIT-DC reverse IPv4→IPv6 → host routing
→ pod veth.

### 2.2 Control Path (Userspace Daemon)

The wirescale-agent runs a userspace egress daemon that owns all
intelligence. eBPF programs are thin verdict executors; the daemon
is the brain.

```
wirescale-agent userspace daemon
  │
  ├─ DNS mirror consumer ──────── Read mirrored DNS packets from ring buffer
  │                                Parse with real DNS library (compression,
  │                                EDNS0, CNAME chains, TCP DNS — all handled)
  │                                → Update IP→FQDN mapping (userspace table)
  │                                → Install per-IP verdicts in egress_ip_policy map
  │                                → Remove entries on TTL expiry
  │
  ├─ SNI mirror consumer ──────── Read mirrored ClientHellos from ring buffer
  │                                Extract SNI with real TLS parser
  │                                → Supplement IP→FQDN mapping
  │                                → Emit SNI metrics
  │
  ├─ Flow log consumer ────────── Drain flow record ring buffer
  │                                Enrich 5-tuple records with FQDN context
  │                                → Export to Hubble / IPFIX / JSON / OTEL
  │
  ├─ Policy compiler ──────────── Watch WirescaleEgressPolicy CRDs
  │                                Compile FQDN + CIDR rules to BPF maps
  │                                Recompile on DNS changes (new IPs for domain)
  │
  ├─ Threat intel loader ──────── Fetch feeds periodically
  │                                → Update threat_intel_ip BPF map
  │
  └─ Anomaly detector ─────────── Read flow stats + counters
                                   Detect fan-out, bandwidth spikes, retry storms
                                   → Set quarantine bits in BPF maps
```

### 2.3 Why This Split

| Concern | Where | Rationale |
|---------|-------|-----------|
| Packet translation (NPTv6, SIIT-DC) | eBPF | Pure arithmetic, ~15-25 instructions, no branching |
| Verdict enforcement | eBPF | Single map lookup, must be per-packet |
| Rate limiting | eBPF | Token bucket decrement, must be per-packet |
| Quarantine check | eBPF | Single bit check, must be instant |
| Flow record emit | eBPF | Per-packet, but only 5-tuple — no enrichment |
| DNS parsing | **Userspace** | DNS compression pointers, EDNS0, CNAME chains, TCP DNS — fragile in eBPF, trivial in userspace |
| SNI extraction | **Userspace** | TLS record fragmentation, QUIC CRYPTO frames, ECH — fragile in eBPF, trivial in userspace |
| FQDN→IP mapping | **Userspace** | Needs TTL tracking, wildcard matching, multi-IP domains |
| Policy compilation | **Userspace** | CRD watch, FQDN resolution, complex rule merging |
| Flow enrichment | **Userspace** | Join 5-tuple with FQDN context, format for export |
| Anomaly detection | **Userspace** | Statistical analysis, sliding windows, threshold tuning |
| Threat intel loading | **Userspace** | Feed fetching, parsing, deduplication |

**Result:** eBPF programs are trivially simple (~50 instructions for
enforcement, ~15-25 for translation). All complex parsing and logic
lives in a userspace daemon that is easy to test, debug, and update
without reloading eBPF programs. The packet mirror ring buffer is the
bridge — eBPF copies interesting packets at near-zero cost, userspace
processes them with real libraries.

---

## 3. NPTv6: Stateless IPv6 Prefix Translation

### 3.1 Why NPTv6

Pods in ULA overlay mode use `fd00:1234:CCCC:HHHH::P` addresses that
are not globally routable. Rather than NAT66 (stateful, breaks
end-to-end), NPTv6 (RFC 6296) performs **stateless, reversible, 1:1
prefix translation**:

| Property | NPTv6 | NAT66 |
|----------|-------|-------|
| State per flow | 0 | 1 state entry (conntrack or equivalent) |
| Throughput | Line rate (eBPF) | State-table-limited |
| Port sharing | No (1:1 mapping) | Yes |
| Reversibility | Fully reversible | Requires state table |
| End-to-end | Preserved (modulo prefix) | Broken |
| eBPF complexity | ~20 instructions | ~200+ instructions |

Each pod gets a deterministic, globally-unique external address. No
port exhaustion. No state table. No connection tracking.

### 3.2 Translation Rule

NPTv6 rewrites the prefix while preserving the Interface Identifier
(IID). Per RFC 6296, a checksum-neutral adjustment is applied to one
16-bit word in the IID so that the IPv6 pseudo-header checksum remains
valid for upper-layer protocols (TCP, UDP, ICMPv6).

```
Internal:  fd00:1234:CCCC:HHHH::P    (/32 prefix: fd00:1234)
External:  3fff:1234:CCCC:HHHH::P'   (/32 prefix: 3fff:1234)
                                       P' = P adjusted for checksum neutrality
```

The translation is configured per-cluster:

| Cluster | Internal Prefix | External Prefix | Translation |
|---------|----------------|-----------------|-------------|
| cluster-1 | `fd00:1234:0001::/48` | `3fff:1234:0001::/48` | `fd00:1234` ↔ `3fff:1234` |
| cluster-2 | `fd00:1234:0002::/48` | `3fff:1234:0002::/48` | Same /32 prefix swap |
| cluster-N | `fd00:1234:CCCC::/48` | `3fff:1234:CCCC::/48` | Same /32 prefix swap |

Because the ULA and GUA org prefixes share the same structure at /32
(only the first 32 bits differ), translation is a single 32-bit
rewrite plus a 16-bit checksum adjustment. Total: ~15 eBPF instructions.

### 3.3 eBPF Implementation

The NPTv6 translator runs as a TC eBPF program on a `nptv6` dummy
interface (same pattern as the existing `nat64` interface).

```c
/* TC egress on nptv6 interface — outbound ULA → GUA */
SEC("tc/nptv6_egress")
int nptv6_out(struct __sk_buff *skb) {
    struct ipv6hdr *ip6 = get_ipv6_hdr(skb);

    /* Verify source is internal ULA prefix */
    if ((ip6->saddr.s6_addr32[0] & PREFIX_MASK) != ULA_PREFIX_32)
        return TC_ACT_OK;  /* not ours, pass through */

    /* Compute RFC 6296 checksum-neutral adjustment */
    __u16 adjustment = compute_nptv6_adjustment(ULA_PREFIX_32, GUA_PREFIX_32);

    /* Rewrite /32 prefix: fd00:1234 → 3fff:1234 */
    bpf_skb_store_bytes(skb, IP6_SRC_OFF, &GUA_PREFIX_32, 4, 0);

    /* Apply checksum adjustment to IID word (octet 14-15 of src addr) */
    bpf_l4_csum_replace(skb, IP6_SRC_OFF + 14, 0, adjustment, 2);

    return bpf_redirect(PHYS_NIC_IFINDEX, 0);
}
```

Ingress (return traffic) performs the reverse: GUA → ULA on the
physical NIC's TC ingress, then routes to the pod via the host stack.

### 3.4 GUA-Mode Clusters

In routable-prefix mode, pod addresses are already GUA. NPTv6
translation is not required for reachability. However, operators
SHOULD still route egress traffic through the `nptv6` interface
(configured as a pass-through with no prefix rewrite) to maintain
a single enforcement and observability chokepoint. The `nptv6` TC
program skips translation but still executes the egress policy check
and connection logging.

### 3.5 Route Installation

The wirescale-agent installs the following routes on each node:

```
# Default IPv6 internet route via NPTv6 interface
default via fe80::1 dev nptv6 metric 200

# Mesh routes (higher priority, installed per-peer)
fd00:1234:0001:0042::/64 dev wg0 metric 100    # local cluster peer
fd00:1234:0002::/48 dev wg0 metric 100          # cross-cluster aggregate

# NAT64 (IPv4 internet via synthesized addresses)
64:ff9b::/96 dev nat64 metric 100

# The physical NIC's default route (metric 300, fallback only)
default via fe80::gw dev eth0 metric 300
```

Mesh routes are more specific than the default, so pod-to-pod traffic
never hits NPTv6. Only genuine internet-bound traffic reaches the
`nptv6` interface.

---

## 4. SIIT-DC: Stateless IPv4 Internet Access

Traditional NAT64 requires stateful connection tracking because many
pods share a single IPv4 address. Wirescale eliminates all state by
using **SIIT-DC (RFC 7755) with Explicit Address Mapping (EAM, RFC
7757)**, reusing the CGNAT address that CLAT already assigns to every
pod. The entire IPv4 egress path is stateless — zero conntrack, zero
state tables, pure prefix-derived header rewrite in eBPF.

### 4.1 Reusing the CLAT Address Space

ARCHITECTURE.md §8 already assigns each pod a deterministic CGNAT
address via CLAT: `100.64.N.P` where N = node index and P = pod index
within the node. The mapping is:

```
Pod IPv6:  fd00:1234:CCCC:HHHH::P   (ULA overlay address)
Pod IPv4:  100.64.H.P               (CGNAT, H = host index mod 256)
```

This mapping is bidirectional and computed from the address itself — no
lookup table. SIIT-DC at the egress boundary simply **reuses this same
mapping** as the EAM translation rule:

```
Outbound (IPv6 → IPv4):
  src: fd00:1234:0001:0042::5  →  100.64.66.5
  dst: 64:ff9b::5db8:d822     →  93.184.216.34

Return (IPv4 → IPv6):
  src: 93.184.216.34           →  64:ff9b::5db8:d822
  dst: 100.64.66.5             →  fd00:1234:0001:0042::5
```

Every field is derived from the packet itself. No state table. No port
rewriting. Each pod gets the **full 64K port space** — no connection
limits from shared port pools.

### 4.2 Address Space and Routing

`100.64.0.0/10` is CGNAT space (RFC 6598). It is not globally routable
on the public internet. Three deployment models handle this:

| Model | How it works | When to use |
|-------|-------------|-------------|
| **Internal egress** | CGNAT space routed within the organization's WAN. Upstream routers accept `100.64.0.0/10`. No further translation needed. | Private datacenters, enterprise WANs |
| **Gateway SNAT** | Dedicated egress gateway nodes perform stateful `100.64.x.x → public_ipv4` SNAT with a public IPv4 pool. Stateful NAT is isolated to a small number of gateway nodes. | Public cloud, internet-facing workloads |
| **Public EAM** | Egress gateways have a public IPv4 pool large enough for 1:1 EAM (one public IP per active pod). Fully stateless end-to-end. | High-connection workloads needing per-pod public identity |

**Internal egress (recommended for most deployments):** The
organization's border routers accept `100.64.0.0/10` as a routable
prefix within the WAN. Each pod's CGNAT address is unique across the
cluster (and across clusters if CGNAT ranges are scoped per-cluster,
e.g., cluster-1 uses `100.64.0.0/18`, cluster-2 uses `100.64.64.0/18`).
The entire path from pod to upstream NAT/firewall is stateless.

**Gateway SNAT:** For traffic that must exit to the public internet with
a routable source address, dedicated egress gateway nodes (see §12,
`WirescaleEgressGateway`) perform the final `100.64.x.x → public_ipv4`
SNAT using an eBPF or AF_XDP stateful translator with a public IPv4
pool. This concentrates stateful NAT at a small number of purpose-built
nodes (typically 2-4 per cluster for HA), keeping the rest of the mesh
entirely stateless.

### 4.3 eBPF Implementation

The `nat64` TC eBPF program performs pure header translation — the
source IPv4 is derived from the source IPv6 address, not looked up:

```c
SEC("tc/siit_dc_egress")
int siit_out(struct __sk_buff *skb) {
    struct ipv6hdr *ip6 = get_ipv6_hdr(skb);

    /* Verify destination is NAT64 prefix 64:ff9b::/96 */
    if (!is_nat64_prefix(&ip6->daddr))
        return TC_ACT_OK;

    /* Extract embedded IPv4 destination from low 32 bits */
    __be32 dst_v4 = ip6->daddr.s6_addr32[3];

    /* Derive source IPv4 from pod's ULA address (EAM rule):
       fd00:1234:CCCC:HHHH::P  →  100.64.H.P
       H = htons(ip6->saddr.s6_addr16[3])  (host index, low 8 bits)
       P = ip6->saddr.s6_addr32[3]          (pod index, low 8 bits) */
    __be32 src_v4 = htonl(0x64400000                           /* 100.64.0.0 */
                        | ((ntohs(ip6->saddr.s6_addr16[3]) & 0xFF) << 8)
                        | (ntohl(ip6->saddr.s6_addr32[3]) & 0xFF));

    /* Stateless IPv6 → IPv4 translation (RFC 7915) */
    bpf_skb_change_proto(skb, htons(ETH_P_IP), 0);
    write_ipv4_header(skb, src_v4, dst_v4, ip6->hop_limit);
    fix_l4_checksum_v6_to_v4(skb);

    return bpf_redirect(PHYS_NIC_IFINDEX, 0);
}
```

**Return path** (TC ingress on physical NIC):

```c
SEC("tc/siit_dc_ingress")
int siit_in(struct __sk_buff *skb) {
    struct iphdr *ip4 = get_ipv4_hdr(skb);

    /* Only process traffic to CGNAT range 100.64.0.0/10 */
    if ((ntohl(ip4->daddr) & 0xFFC00000) != 0x64400000)
        return TC_ACT_OK;

    /* Derive pod's ULA IPv6 from CGNAT address (reverse EAM):
       100.64.H.P  →  fd00:1234:CCCC:00H0::P
       where CCCC = local cluster index (compile-time constant) */
    __u8 host_idx = (ntohl(ip4->daddr) >> 8) & 0xFF;
    __u8 pod_idx  = ntohl(ip4->daddr) & 0xFF;
    struct in6_addr dst_v6 = ULA_PREFIX;   /* fd00:1234:CCCC:: */
    dst_v6.s6_addr16[3] = htons(host_idx); /* HHHH */
    dst_v6.s6_addr32[3] = htonl(pod_idx);  /* ::P */

    /* Reconstruct IPv6 source from embedded IPv4 */
    struct in6_addr src_v6 = NAT64_PREFIX;  /* 64:ff9b:: */
    src_v6.s6_addr32[3] = ip4->saddr;

    /* Stateless IPv4 → IPv6 translation */
    bpf_skb_change_proto(skb, htons(ETH_P_IPV6), 0);
    write_ipv6_header(skb, &src_v6, &dst_v6, ip4->ttl);
    fix_l4_checksum_v4_to_v6(skb);

    return TC_ACT_OK;  /* route to pod via host stack */
}
```

**Total eBPF instructions:** ~20 per direction. **Zero map lookups** —
both source and destination addresses are derived arithmetically from
the packet headers. No hash maps, no array lookups, no state of any
kind.

### 4.4 Policy Integration

SIIT-DC traffic passes through the same egress policy pipeline as NPTv6:

1. Pod sends to `64:ff9b::C0A8:0101` (synthesized AAAA for `192.168.1.1`).
2. TC egress on pod veth: egress policy check against pre-computed
   verdict in `egress_ip_policy` (installed by userspace from DNS
   resolution, see §5). If no ALLOW entry, drop.
3. Host routing: `64:ff9b::/96` routes to `nat64` interface.
4. TC on `nat64`: stateless SIIT-DC IPv6→IPv4 translation.

The key insight: **policy enforcement happens at the pod veth (step 2),
before translation (step 4).** The `nat64` interface is a pure
stateless translator with no policy logic.

### 4.5 IPv4 Source Identity Preservation

After SIIT-DC translation, each pod has a **unique CGNAT source
address** (`100.64.H.P`). Unlike traditional NAT64 where all pods
share one IPv4, SIIT-DC provides per-pod IPv4 identity:

- External observers see a unique `100.64.H.P` per pod (within the
  organization's WAN) or a unique `(public_ip, port)` (after gateway
  SNAT).
- The `connection_log` records the full mapping for audit: `(pod_id,
  pod_ipv6, cgnat_ipv4, dest, port, fqdn, timestamp)`.
- With internal egress (no gateway SNAT), per-pod IPv4 identity is
  fully preserved end-to-end.

### 4.6 Comparison: SIIT-DC/EAM vs Stateful NAT64

| Property | SIIT-DC/EAM (Wirescale) | Traditional NAT64 |
|----------|------------------------|--------------------|
| State per flow | **0** | 1 conntrack entry |
| eBPF instructions | **~20** | ~200+ |
| Map lookups | **0** (arithmetic) | 1+ hash lookups |
| Throughput | Line rate | Conntrack-limited |
| Ports per pod | **Full 64K** | 64K shared across all pods |
| Return-path demux | Address-derived (O(1) arithmetic) | Hash table lookup |
| Pod identification | Unique CGNAT per pod | Shared IP, requires log correlation |
| Failure mode | Stateless (survives restart) | State loss = connection reset |
| Connection limit | **Unlimited** (full port space) | Port exhaustion under load |

---

## 5. DNS Interception and FQDN Resolution

DNS is the linchpin. If you control DNS resolution, you control what
pods can reach — by name, not by chasing ephemeral IPs.

### 5.1 DNS Snooping Architecture

DNS response parsing runs **entirely in userspace**. The eBPF program
on pod veths is a trivial packet mirror — it copies DNS responses to
a ring buffer without attempting to parse them. The userspace daemon
parses responses with a real DNS library (handling compression pointers,
EDNS0, CNAME chains, TCP DNS segments, and malformed packets properly)
and writes pre-computed verdicts to BPF maps.

```
Pod queries "api.stripe.com" via CoreDNS
  → CoreDNS resolves: 52.204.1.100, 52.204.1.101
  → DNS response transits pod veth
  → TC ingress eBPF: UDP src port 53 → copy packet to mirror ring buffer
  → Userspace daemon reads ring buffer, parses DNS response:
      fqdn_table["api.stripe.com"] = {52.204.1.100, 52.204.1.101, TTL=300s}
      ip_table[52.204.1.100] = "api.stripe.com"
  → Userspace checks pod's egress policy for "api.stripe.com"
  → If allowed: install egress_ip_policy[pod_id, 52.204.1.100] = ALLOW
  → On TTL expiry: remove the entry
  → Subsequent packets to 52.204.1.100 hit the pre-computed ALLOW in eBPF
```

**IP→FQDN mapping** is a userspace hash table (not a BPF map):

```
Key:   destination IP address
Value: { fqdn, ttl_expiry, source_pod_id, query_timestamp }
Capacity: 65,536+ entries per node (limited only by daemon memory)
```

Because the mapping lives in userspace, it can handle arbitrary FQDN
lengths, multi-level CNAME chains, wildcard matching, and TTL-based
garbage collection without any eBPF verifier constraints.

### 5.2 eBPF Packet Mirror (TC Ingress on Pod Veth)

The eBPF program is deliberately minimal — it identifies interesting
packets and copies them to a ring buffer. No parsing.

```c
SEC("tc/pkt_mirror")
int mirror_interesting_packets(struct __sk_buff *skb) {
    /* Mirror DNS responses (UDP src port 53) */
    if (is_udp_sport_53(skb)) {
        bpf_perf_event_output(skb, &packet_mirror, BPF_F_CURRENT_CPU,
                              skb->data, MIN(skb->len, MAX_MIRROR_LEN));
    }

    /* Mirror TLS ClientHello (TCP dst 443, first packet) */
    if (is_tcp_dport_443(skb) && is_syn_or_first_data(skb)) {
        bpf_perf_event_output(skb, &packet_mirror, BPF_F_CURRENT_CPU,
                              skb->data, MIN(skb->len, MAX_MIRROR_LEN));
    }

    return TC_ACT_OK;  /* always pass — mirror is advisory */
}
```

**~15 eBPF instructions.** No DNS parsing. No TLS parsing. No map
updates. The mirror ring buffer is per-CPU to avoid contention. Packets
that don't match either check pass through with zero overhead.

### 5.3 Userspace DNS Processing

The daemon reads mirrored DNS packets and processes them with full
library support:

1. **Parse DNS response** — handles compression pointers (arbitrary
   depth), EDNS0 OPT records, CNAME/DNAME chains, TCP DNS segments
   that span multiple packets, and gracefully rejects malformed data.

2. **Update IP→FQDN table** — for each A/AAAA record, store the
   mapping with TTL. This table is the ground truth for FQDN
   attribution across the node.

3. **Install egress verdicts** — for each resolved IP, check all
   matching pods' egress policies. If pod P allows domain D and D
   resolves to IP X, install `egress_ip_policy[P, X] = ALLOW` in
   the BPF map. The eBPF enforcement path sees a pre-computed
   verdict — no FQDN logic in eBPF at all.

4. **TTL-driven cleanup** — when a DNS entry's TTL expires, the daemon
   removes the corresponding `egress_ip_policy` entries. If the domain
   resolves to new IPs, the old entries are replaced atomically.

**Latency:** DNS response processing completes in <1ms (parse + map
update). Since the application waits for the DNS response before
sending data, the verdict is in the BPF map before the first data
packet arrives. No race condition in practice.

### 5.4 DNS-over-HTTPS/TLS (DoH/DoT) Handling

Encrypted DNS bypasses the packet mirror (the eBPF program cannot
see inside TLS). Mitigations:

- **CoreDNS enforcement:** The cluster's CoreDNS SHOULD be the only
  permitted DNS resolver. Egress policy SHOULD deny UDP/TCP port 53
  to all destinations except CoreDNS, and deny HTTPS to known DoH
  providers (configurable blocklist).
- **Redirect policy:** The agent MAY install a DNAT rule redirecting
  all port-53 traffic to CoreDNS (transparent DNS proxy).
- **Unsnooped traffic:** Packets to IPs not in the userspace FQDN
  table are logged as `fqdn: <unknown>`. Policy can be configured to
  deny traffic to unknown FQDNs (strict mode) or allow-and-log
  (permissive mode). In strict mode, only IPs resolved through
  observable DNS and installed as verdicts in `egress_ip_policy`
  are allowed.

### 5.5 DNS Query Logging

The daemon logs all observed DNS queries and responses:

```
dns_log_entry:
  { timestamp, pod_id, namespace, query_name, query_type,
    response_code, resolved_ips[], ttl, latency_ns }
```

This provides a complete DNS audit trail independent of flow logs.
Operators can answer: "What domains did pod X query in the last hour?"

---

## 6. Egress Policy Engine

### 6.1 Policy Model

Egress policy operates at three levels, evaluated in order:

| Level | Scope | Effect | Use Case |
|-------|-------|--------|----------|
| **Cluster default** | All pods | Baseline allow/deny | Default-deny egress for the cluster |
| **Namespace policy** | All pods in namespace | Override cluster default | Team-level egress rules |
| **Pod policy** | Single pod or label selector | Override namespace | Workload-specific allowlists |

Policy evaluation: most-specific match wins. If no policy matches,
the cluster default applies. Recommended cluster default: **deny all
egress to internet; allow all egress to mesh.**

### 6.2 FQDN-Based Rules

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleEgressPolicy
metadata:
  name: payment-service-egress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payment-service
  rules:
    - action: allow
      to:
        fqdns:
          - "api.stripe.com"
          - "*.googleapis.com"
          - "hooks.slack.com"
      ports:
        - { port: 443, protocol: TCP }

    - action: allow
      to:
        fqdns:
          - "ntp.ubuntu.com"
      ports:
        - { port: 123, protocol: UDP }

    - action: deny
      to:
        cidrs:
          - "::/0"          # deny all other IPv6 internet
          - "0.0.0.0/0"     # deny all other IPv4 internet
      log: true              # log denied attempts
```

### 6.3 Compilation to BPF Maps (Userspace)

The daemon compiles all policy into a single BPF map:

**`egress_ip_policy`** (LPM trie, per-node):
```
Key:   { pod_identity, destination_ip_prefix }
Value: { action (allow/deny), ports_bitmap, rate_limit_id }
```

The daemon populates this map from two sources:

1. **Static CIDR rules** — installed directly from the CRD. Example:
   `deny pod_X ::/0` installs as a catch-all DENY entry.

2. **DNS-derived entries** — when the daemon's DNS parser resolves
   `api.stripe.com` to `52.204.1.100` and pod X allows that FQDN,
   the daemon installs `egress_ip_policy[pod_X, 52.204.1.100] = ALLOW`.
   When the DNS TTL expires, the daemon removes the entry.

This means:

- **FQDN changes propagate automatically.** If `api.stripe.com` changes
  IPs, the new DNS response updates the map.
- **Stale IPs are removed.** No risk of allowing traffic to a reused IP
  that previously belonged to an allowed domain.
- **No manual IP management.** Operators write domain names; the daemon
  handles the rest.
- **eBPF sees only IPs and verdicts.** No FQDN hashing, no string
  matching, no DNS logic in the kernel.

### 6.4 eBPF Enforcement (TC Egress on Pod Veth)

The enforcement program is deliberately simple — one map lookup for
the verdict, one for rate limiting, one ring buffer write. No FQDN
logic. No DNS map. No string operations. ~50 instructions total.

```c
SEC("tc/egress_policy")
int egress_check(struct __sk_buff *skb) {
    __u32 ifindex = skb->ifindex;
    struct pod_identity *pod = bpf_map_lookup_elem(&identity_cache, &ifindex);
    if (!pod)
        return TC_ACT_OK;       /* unknown veth — pass */

    /* 1. Quarantine check (instant kill switch — single bit) */
    struct rate_state *rl = bpf_map_lookup_elem(&egress_rate_limit, &pod->id);
    if (rl && rl->quarantine)
        return TC_ACT_SHOT;

    /* 2. Policy verdict (single LPM trie lookup — pre-computed by userspace) */
    struct ipv6hdr *ip6 = get_ipv6_hdr(skb);
    __u16 dport = get_l4_dport(skb);
    struct egress_key key = { .pod_id = pod->id, .addr = ip6->daddr };
    struct egress_value *v = bpf_map_lookup_elem(&egress_ip_policy, &key);

    if (v && v->action == ALLOW && port_matches(v->ports_bitmap, dport)) {
        /* 3. Rate limit check (token bucket decrement) */
        if (rl && !token_bucket_allow(rl, skb->len))
            return TC_ACT_SHOT;
        /* 4. Emit minimal flow record */
        emit_flow_record(skb, pod->id, ALLOW);
        return TC_ACT_OK;
    }

    /* 5. Default: deny */
    emit_flow_record(skb, pod->id, DENY);
    return TC_ACT_SHOT;
}
```

Compare with the previous design which had 5 map lookups (identity,
CIDR policy, dns_fqdn_map, FQDN policy hash, rate limit) and computed
FQDN hashes in eBPF. This version has 3 map lookups and zero string
operations.

### 6.5 Policy Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Strict** | Default deny. Only explicitly allowed FQDNs/CIDRs pass. Unknown destinations denied. | Production, compliance-sensitive |
| **Permissive** | Default allow. Denied FQDNs/CIDRs blocked. Unknown destinations allowed and logged. | Development, initial rollout |
| **Audit** | All traffic allowed. Policy violations logged but not enforced. | Shadow mode before enforcement |
| **Lockdown** | All internet egress denied. Mesh traffic only. | Incident response, quarantine |

---

## 7. URL and SNI Filtering

### 7.1 TLS SNI Inspection

SNI extraction runs **in userspace**, not eBPF. The packet mirror
(§5.2) already copies TLS ClientHello packets to the mirror ring
buffer. The daemon's SNI consumer parses them with a real TLS library.

**Flow:**

```
ClientHello arrives at pod veth
  → TC ingress eBPF: TCP dst 443 + SYN/first-data → copy to mirror ring buffer
  → Packet passes through to egress enforcement (not blocked by mirror)
  → Userspace daemon reads ClientHello from ring buffer
  → Parse TLS record layer → extract SNI extension
  → Supplement IP→FQDN table: ip_table[dest_ip] = sni_name
  → Emit wirescale_egress_sni_extractions_total metric
```

**Why userspace for SNI:**
- TLS ClientHello parsing in eBPF is fragile: record layer
  fragmentation, multiple extensions with variable-length fields,
  TLS 1.3 vs 1.2 format differences, QUIC CRYPTO frames.
- In userspace, a battle-tested TLS parser handles all edge cases.
- SNI is not on the blocking path for most traffic — DNS snooping
  is the primary enforcement mechanism. If the pod resolved the FQDN
  through DNS, the IP already has a pre-computed verdict in
  `egress_ip_policy`. SNI provides supplementary attribution for:
  - IPs that weren't resolved through observable DNS
  - Audit enrichment (confirm the SNI matches the DNS-resolved FQDN)
  - Detection of domain fronting (SNI doesn't match DNS)

**Latency:** The ClientHello mirror adds no latency to the connection —
the packet passes through to enforcement immediately. SNI processing
is async. If the IP was already authorized via DNS, the connection
proceeds at line rate. If the IP was not authorized (hardcoded IP,
bypassed DNS), it's already denied by policy before SNI processing
completes.

**Limitations:**
- Encrypted Client Hello (ECH) hides the SNI. Detection: the outer
  SNI is a cloudflare-ech.example.com stub. Policy can deny ECH
  connections or allow-and-flag.
- QUIC Initial packets carry SNI in the QUIC CRYPTO frame. The
  userspace parser handles both TLS-over-TCP and QUIC-over-UDP.
- Domain fronting: the daemon compares SNI against DNS-resolved FQDNs
  and flags mismatches.

### 7.2 URL-Level Filtering (L7 Proxy)

The eBPF+userspace pipeline operates at L3/L4 and can extract SNI, but
cannot inspect HTTP request paths, headers, or POST bodies. For
URL-level filtering (`/api/v1/transfer` vs `/api/v1/status`), a
dedicated L7 proxy is required.

**Architecture:**

```
Pod → TC egress (L3/L4 policy) → [if L7 inspection needed] → redirect to L7 proxy
  → L7 proxy (Envoy/wirescale-proxy) inspects HTTP/gRPC
  → L7 proxy → nptv6/nat64 → internet
```

**When to use L7 proxy:**

| Requirement | L3/L4 (eBPF + userspace) | L7 Proxy |
|-------------|--------------------------|----------|
| FQDN allowlist (domain level) | Yes (DNS+SNI) | Yes |
| Port/protocol filtering | Yes | Yes |
| URL path filtering | No | Yes |
| HTTP header inspection | No | Yes |
| Request/response body scanning | No | Yes |
| mTLS to external services | No | Yes |

**L7 proxy is optional.** Most workloads need only FQDN+port filtering
(handled by the eBPF+userspace pipeline at line rate). L7 proxy is
deployed only for workloads that require URL-level control. This avoids
imposing proxy overhead on all traffic.

**Selective redirection:**

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleEgressPolicy
metadata:
  name: api-l7-filter
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payment-service
  rules:
    - action: proxy     # redirect to L7 proxy for deep inspection
      to:
        fqdns: ["api.vendor.com"]
      ports:
        - { port: 443, protocol: TCP }
      l7Rules:
        http:
          - method: POST
            path: "/api/v1/transfer"
            action: allow
          - method: GET
            path: "/api/v1/.*"
            action: allow
          - path: ".*"
            action: deny
```

---

## 8. Traffic Containment and Rate Limiting

### 8.1 Per-Pod Rate Limiting

Every pod has a rate limit enforced in eBPF at the veth TC egress:

**BPF map: `egress_rate_limit`** (hash map, per-node):
```
Key:   pod_identity (32 bits)
Value: {
    bps_limit,          /* bytes per second (token bucket capacity) */
    pps_limit,          /* packets per second */
    conn_rate_limit,    /* new connections per second (SYN/Initial count) */
    tokens_bps,         /* current token count (bytes) */
    tokens_pps,         /* current token count (packets) */
    tokens_conn,        /* current token count (connections) */
    last_refill_ns,     /* timestamp of last refill */
}
```

**Three independent token buckets per pod:**

| Bucket | Default | Purpose |
|--------|---------|---------|
| Bandwidth (bps) | 1 Gbps | Prevent single pod from saturating uplink |
| Packet rate (pps) | 100K pps | Prevent packet floods (small-packet attacks) |
| Connection rate (conn/s) | 1000 conn/s | Prevent port scanning, C2 fan-out |

Defaults are generous (won't affect normal workloads). Operators
tighten per-namespace or per-pod via `WirescaleEgressPolicy`.

### 8.2 Namespace Quotas

Aggregate rate limits per namespace, enforced via a shared token bucket:

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleEgressQuota
metadata:
  name: egress-quota
  namespace: batch-jobs
spec:
  aggregateLimits:
    bandwidthMbps: 5000        # 5 Gbps total for namespace
    connectionsPerSecond: 5000 # cap fan-out
    dailyTransferGB: 500       # daily cap (reset at midnight UTC)
  burstMultiplier: 2.0         # allow 2x burst for 10 seconds
  onExceed: throttle           # "throttle" | "deny" | "alert-only"
```

### 8.3 Emergency Quarantine

When something goes wrong — crypto miner detected, data exfiltration
in progress, compromised namespace — operators need an instant kill
switch.

**`kubectl wirescale quarantine`:**

```bash
# Quarantine a single pod (all internet egress denied immediately)
kubectl wirescale quarantine pod payments/payment-service-abc123

# Quarantine entire namespace
kubectl wirescale quarantine namespace batch-jobs

# Quarantine with allow-list (only DNS and NTP permitted)
kubectl wirescale quarantine namespace batch-jobs \
    --allow "dns:53" --allow "ntp.ubuntu.com:123"

# Lift quarantine
kubectl wirescale quarantine lift namespace batch-jobs
```

**Implementation:** Quarantine sets a single bit in the pod's
`egress_rate_limit` map entry (`quarantine = 1`). The eBPF program
checks this bit first, before any policy evaluation. Setting one
map entry takes ~100ns. Quarantine is effective within one packet
processing cycle.

### 8.4 Automatic Containment (Circuit Breaker)

The userspace daemon monitors flow records and detects anomalous egress
patterns. All circuit breaker logic runs in userspace — when triggered,
it sets the quarantine bit in the BPF map (§8.3):

| Signal | Threshold | Action |
|--------|-----------|--------|
| Connection fan-out | > 500 unique dest IPs in 60s | Alert + optional auto-quarantine |
| DNS query burst | > 100 unique domains in 60s | Alert + optional auto-quarantine |
| Bandwidth spike | > 3x rolling average for 30s | Alert + throttle to baseline |
| Denied connection retry | > 50 denied attempts in 60s | Auto-quarantine pod |
| Known-bad FQDN hit | Any match | Immediate block + alert |

Circuit breaker thresholds are configurable per namespace. Automatic
quarantine MUST be opt-in (disabled by default) to avoid false
positives disrupting production.

---

## 9. Flow Observability

### 9.1 Connection Log

eBPF emits **minimal flow records** to a per-CPU ring buffer — just
the 5-tuple, verdict, and packet length. The userspace daemon enriches
these with FQDN context, SNI, pod metadata, and namespace before
export.

**eBPF flow record** (emitted per-packet, ~48 bytes):

```c
struct egress_flow_record {
    __u64 timestamp_ns;
    __u32 pod_identity;
    __u8  verdict;             /* allow, deny, quarantine */
    __u8  protocol;            /* TCP, UDP, SCTP */
    __be16 src_port, dst_port;
    struct in6_addr src_addr, dst_addr;
    __u32 pkt_len;
};
```

**Userspace enriched record** (exported to Hubble/IPFIX/JSON/OTEL):

```
{
    timestamp, pod_id, pod_name, namespace, service_account,
    verdict, protocol, src_addr, dst_addr, src_port, dst_port,
    fqdn,              /* from userspace IP→FQDN table */
    fqdn_source,       /* dns, sni, unknown */
    sni,               /* from SNI mirror consumer */
    bytes_out, bytes_in, duration_ns,
    threat_category     /* from threat intel lookup */
}
```

The split keeps the eBPF record tiny (no 256-byte FQDN/SNI strings)
and moves all enrichment to userspace where it's trivial.

### 9.2 Metrics (Prometheus)

The agent exposes egress-specific metrics at `:9090/metrics`:

```
# Per-pod egress traffic
wirescale_egress_bytes_total{pod, namespace, fqdn, dest_ip, protocol, verdict}
wirescale_egress_connections_total{pod, namespace, fqdn, protocol, verdict}
wirescale_egress_packets_total{pod, namespace, protocol, verdict}

# DNS
wirescale_dns_queries_total{pod, namespace, query_name, query_type, rcode}
wirescale_dns_fqdn_table_size{node}
wirescale_dns_mirror_drops_total{node}

# Rate limiting
wirescale_egress_rate_limited_total{pod, namespace, limit_type}
wirescale_egress_quarantine_active{pod, namespace}

# NPTv6
wirescale_nptv6_translations_total{direction, node}
wirescale_nptv6_errors_total{error_type, node}

# Policy
wirescale_egress_policy_evaluations_total{verdict, namespace}
wirescale_egress_unknown_dest_total{pod, namespace, dest_ip}
wirescale_egress_sni_extractions_total{pod, namespace, sni}
```

### 9.3 Flow Export

The agent exports flow records in multiple formats:

| Format | Destination | Use Case |
|--------|-------------|----------|
| **Hubble** (protobuf) | Hubble Relay → Hubble UI | Real-time flow visualization (Cilium-compatible) |
| **IPFIX/NetFlow v9** | Flow collector | Traditional network monitoring, SIEM integration |
| **JSON lines** | Loki, Elasticsearch, S3 | Log aggregation, long-term analytics |
| **OpenTelemetry** | OTEL collector | Traces with correlated network spans |

### 9.4 Real-Time Flow Watching

```bash
# Watch all egress flows from the payments namespace
kubectl wirescale flows --namespace payments --direction egress

# Filter by FQDN pattern
kubectl wirescale flows --fqdn "*.stripe.com" --direction egress

# Show denied flows only (detect policy misconfiguration or attacks)
kubectl wirescale flows --verdict deny --direction egress

# Show flows to unknown destinations (potential data exfiltration)
kubectl wirescale flows --fqdn "<unknown>" --direction egress

# Export to JSON for analysis
kubectl wirescale flows --direction egress --output json > flows.jsonl
```

### 9.5 Dashboards

Pre-built Grafana dashboards:

1. **Egress Overview:** Top destinations by bandwidth, top FQDNs by
   connection count, denied vs allowed ratio, rate limit events.
2. **Per-Namespace Egress:** Bandwidth over time, unique destinations,
   DNS queries, policy violations per namespace.
3. **DNS Analytics:** Query volume, NXDOMAIN rate (typosquatting
   indicator), resolution latency, top queried domains.
4. **Threat Detection:** Connections to unknown destinations, denied
   retry patterns, fan-out anomalies, known-bad FQDN hits.

---

## 10. Threat Detection and Response

### 10.1 Threat Intelligence Integration

The userspace daemon loads threat intelligence feeds into BPF maps for
real-time blocking:

**BPF map: `threat_intel_ip`** (LPM trie, per-node):
```
Key:   IP prefix (IPv4-mapped or IPv6)
Value: { category (C2, malware, phishing, tor_exit), feed_id, last_updated }
```

**BPF map: `threat_intel_fqdn`** (hash map, per-node):
```
Key:   FQDN hash
Value: { category, feed_id, last_updated }
```

Feed sources (configurable):
- Internal blocklists (operator-managed ConfigMap)
- Commercial feeds (CrowdStrike, Recorded Future, etc. via agent sidecar)
- Open-source feeds (abuse.ch, PhishTank, Emerging Threats)
- Directory-distributed federation-wide blocklist

### 10.2 Detection Signals

| Signal | Detection Method | Response |
|--------|-----------------|----------|
| Known C2 domain | DNS query matches `threat_intel_fqdn` | Block + alert + log |
| Known malicious IP | Egress packet matches `threat_intel_ip` | Block + alert + log |
| DGA detection | DNS query entropy scoring (agent userspace) | Flag + optional block |
| Data exfiltration | Sustained high-bandwidth egress to single dest | Alert + optional throttle |
| Port scanning | High connection fan-out, low bytes per conn | Alert + auto-quarantine |
| DNS tunneling | High query rate to single domain, large TXT responses | Block domain + alert |
| Crypto mining | Sustained CPU + outbound to known mining pools | Alert + quarantine |

### 10.3 Response Automation

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleThreatResponse
metadata:
  name: auto-contain
spec:
  rules:
    - signal: threat_intel_match
      category: [c2, malware]
      action: quarantine_pod
      notify: ["slack:#security-alerts", "pagerduty:egress-team"]

    - signal: connection_fanout
      threshold: 500
      window: 60s
      action: throttle_to_baseline
      notify: ["slack:#network-ops"]

    - signal: dns_query_burst
      threshold: 200
      window: 60s
      action: alert_only     # don't auto-contain, just flag
      notify: ["slack:#network-ops"]
```

---

## 11. Performance Engineering

### 11.1 eBPF Pipeline Cost Budget

Every egress packet traverses the eBPF enforcement path. With the
userspace split, the per-packet eBPF work is minimal:

| Stage | Cost | Notes |
|-------|------|-------|
| Quarantine check | ~5 ns | Hash map, single bit |
| Policy verdict (LPM) | ~30 ns | Single LPM trie lookup (pre-computed) |
| Port match | ~5 ns | Bitmap check |
| Rate limit check | ~10 ns | Per-CPU token bucket |
| Flow record emit | ~15 ns | Per-CPU ring buffer, 48-byte record |
| NPTv6 translation | ~15 ns | 32-bit rewrite + 16-bit checksum |
| SIIT-DC translation | ~20 ns | Stateless header swap (IPv4 path only) |
| **Total (fast path)** | **~80-85 ns** | **~11.8-12.5 Mpps single core** |

Compared to the previous design (~115-120ns with 5 map lookups and
FQDN hashing in eBPF), the userspace split reduces per-packet cost
by ~30% and eliminates the two most complex eBPF operations (DNS map
lookup and FQDN hash computation).

At 1KB average packet size, 10 Gbps = ~1.2 Mpps, well within a
single core's budget. At 64B packets (worst case), 12.5 Mpps per core
sustains ~6.4 Gbps — additional cores via RSS handle higher rates.

### 11.2 Packet Mirror Cost

The TC ingress mirror program runs on all pod veth traffic but does
useful work only for DNS responses and TLS ClientHellos — a tiny
fraction of total packets:

| Traffic type | Rate | Mirror cost | Notes |
|-------------|------|-------------|-------|
| DNS responses | ~10-100/sec/pod | ~200 ns each | `bpf_perf_event_output` copy |
| TLS ClientHellos | ~100-1K/sec/pod | ~300 ns each | Larger packet copy |
| All other traffic | ~100K+/sec/pod | ~5 ns each | Port check → skip |

Total mirror overhead: <0.01% of CPU. The mirror path never blocks —
if the ring buffer is full, the copy is silently dropped and the
packet passes through normally.

### 11.3 Userspace Processing Cost

DNS and SNI processing run in the userspace daemon, off the packet
hot path. Their cost is measured in wall-clock time, not per-packet
eBPF budget:

| Operation | Latency | Rate | CPU impact |
|-----------|---------|------|------------|
| DNS response parse + map update | ~50-200 µs | ~1K/sec/node | <1% core |
| SNI extraction | ~10-50 µs | ~10K/sec/node | <1% core |
| Flow record enrichment | ~5-10 µs | ~100K/sec/node | ~10% core |
| Policy recompilation (on DNS change) | ~1-5 ms | ~100/sec/node | <1% core |

The daemon processes these asynchronously using epoll on the ring
buffer file descriptors. Total daemon CPU usage: <0.5 cores at
moderate load.

### 11.4 GRO/GSO Amortization

NPTv6 translation and policy checks run on GRO superpackets (64-512KB)
before GSO segmentation. A single policy check + translation covers
~50-400 MTU-sized packets. Effective per-packet cost at bulk transfer:

```
115 ns / 300 packets per superpacket ≈ 0.38 ns per wire packet
```

### 11.5 Ring Buffer Sizing

The `egress_flow_log` ring buffer is per-CPU to avoid contention:

```
Per entry: ~600 bytes (with FQDN + SNI)
Target: buffer 100ms of flows at peak rate
At 100K connections/sec: 100K * 0.1s * 600B = 6 MB per CPU
8 CPUs: 48 MB total ring buffer

Configurable via WirescaleMesh CRD: spec.agent.egressLogBufferMB
```

The agent userspace daemon drains the ring buffer continuously. If the
daemon falls behind (overloaded), the ring buffer wraps and oldest
entries are lost. The metric `wirescale_egress_log_drops_total` tracks
this.

---

## 12. CRDs and Configuration

### WirescaleEgressPolicy (namespace-scoped)

Controls which destinations pods can reach.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleEgressPolicy
metadata:
  name: default-egress
  namespace: production
spec:
  podSelector: {}              # all pods in namespace
  mode: strict                 # strict | permissive | audit | lockdown
  defaultAction: deny

  rules:
    - action: allow
      to:
        fqdns: ["*.internal.company.com"]
      ports:
        - { port: 443, protocol: TCP }

    - action: allow
      to:
        fqdns: ["ntp.ubuntu.com", "time.google.com"]
      ports:
        - { port: 123, protocol: UDP }

    - action: allow
      to:
        cidrs: ["3fff:1234::/32"]     # allow all mesh traffic
      ports: []                        # any port

  rateLimits:
    perPod:
      bandwidthMbps: 500
      connectionsPerSecond: 500
      packetsPerSecond: 50000
```

### WirescaleEgressGateway (cluster-scoped)

Designates nodes as egress gateways with dedicated external IPs.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleEgressGateway
metadata:
  name: egress-gw-us-east
spec:
  nodeSelector:
    matchLabels:
      role: egress-gateway
      region: us-east
  nptv6:
    internalPrefix: "fd00:1234:0001::/48"
    externalPrefix: "3fff:1234:0001::/48"
  nat64:
    enabled: true
    ipv4Pool: ["198.51.100.0/28"]       # dedicated IPv4 pool (16 addrs)
    portRange: [1024, 65535]
  highAvailability:
    mode: active-active                  # active-active | active-standby
    healthCheck:
      intervalSeconds: 5
      failureThreshold: 3
```

### WirescaleThreatFeed (cluster-scoped)

Configures threat intelligence sources.

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleThreatFeed
metadata:
  name: abuse-ch-blocklist
spec:
  source:
    type: url
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv"
    format: csv
    refreshIntervalMinutes: 60
  targetMaps:
    - threat_intel_ip
  category: c2
  action: block
```

---

## 13. Packet Flow Walkthroughs

### Case 1: Pod Reaches api.stripe.com (IPv4-only, via DNS64+NAT64)

```
Pod (fd00:1234:0001:0042::5) runs: curl https://api.stripe.com/v1/charges

1. DNS resolution
   Pod → CoreDNS: "api.stripe.com AAAA?"
   CoreDNS → upstream: only A record exists (52.204.1.100)
   CoreDNS DNS64: synthesize AAAA → 64:ff9b::34cc:0164
   Response transits pod veth:
     TC ingress eBPF: copies DNS packet to mirror ring buffer
     Userspace daemon: parses response, resolves "api.stripe.com" → 64:ff9b::34cc:0164
     Daemon checks: pod 0x1234 allows "api.stripe.com" on port 443
     Daemon installs: egress_ip_policy[0x1234, 64:ff9b::34cc:0164] = ALLOW, port 443

2. TCP SYN to 64:ff9b::34cc:0164:443
   TC egress on pod veth:
     egress_ip_policy[0x1234, 64:ff9b::34cc:0164] → ALLOW, port 443
     rate_limit check → OK
     flow_record: {pod=0x1234, dest=64:ff9b::34cc:0164, port=443, verdict=ALLOW}
     → TC_ACT_OK

3. Host routing
   64:ff9b::/96 → dev nat64

4. SIIT-DC translation (stateless EAM)
   TC on nat64: IPv6 64:ff9b::34cc:0164 → IPv4 52.204.1.100
   Source: 100.64.66.5 (derived: H=0x42=66, P=5 from pod's ULA)
   No state table — pure arithmetic (~25 eBPF instructions)
   → Physical NIC → Internet

5. Return path (stateless EAM)
   Physical NIC TC ingress: dst 100.64.66.5
   → CGNAT 100.64.66.5 → H=66=0x42, P=5 → fd00:1234:0001:0042::5
   → SIIT-DC reverse: IPv4→IPv6 → host route → pod veth
```

### Case 2: Pod Reaches github.com (IPv6-native, via NPTv6)

```
Pod (fd00:1234:0001:0042::5) runs: git clone https://github.com/org/repo

1. DNS resolution
   Pod → CoreDNS: "github.com AAAA?"
   CoreDNS → upstream: AAAA 2606:50c0:8003::1
   Response transits pod veth:
     TC ingress eBPF: copies DNS packet to mirror ring buffer
     Userspace daemon: parses response, resolves "github.com" → 2606:50c0:8003::1
     Daemon checks: pod 0x5678 allows "github.com" on port 443
     Daemon installs: egress_ip_policy[0x5678, 2606:50c0:8003::1] = ALLOW, port 443

2. TCP SYN to 2606:50c0:8003::1:443
   TC egress on pod veth:
     egress_ip_policy[0x5678, 2606:50c0:8003::1] → ALLOW, port 443
     rate_limit check → OK
     flow_record: {pod=0x5678, dest=2606:50c0:8003::1, port=443, verdict=ALLOW}
     → TC_ACT_OK
   Mirror: copies ClientHello to ring buffer → userspace extracts SNI "github.com"
           (confirms DNS mapping, enriches flow log)

3. Host routing
   Default route → dev nptv6

4. NPTv6 translation
   TC on nptv6: src fd00:1234:0001:0042::5 → 3fff:1234:0001:0042::5'
   (checksum-neutral adjustment)
   → bpf_redirect to physical NIC → Internet

5. Return path
   Physical NIC → TC ingress: GUA dst 3fff:1234:0001:0042::5'
   NPTv6 reverse: → fd00:1234:0001:0042::5
   Host route → pod veth
```

### Case 3: Pod Denied (Strict Mode, Unknown Destination)

```
Pod (fd00:1234:0001:0042::5) runs: curl https://suspicious-domain.xyz

1. DNS resolution
   Pod → CoreDNS: "suspicious-domain.xyz AAAA?"
   Response: AAAA 2a01:dead::1
   Packet mirror → userspace daemon parses DNS response
   Daemon checks: pod 0x1234 has no policy allowing "suspicious-domain.xyz"
   Daemon does NOT install ALLOW entry in egress_ip_policy

2. TCP SYN to 2a01:dead::1:443
   TC egress on pod veth:
     egress_ip_policy[0x1234, 2a01:dead::1] → NOT FOUND
     No match → DENY (default deny)
     flow_record: {pod=0x1234, dest=2a01:dead::1, port=443, verdict=DENY}
     → TC_ACT_SHOT
   Userspace enriches flow log: fqdn="suspicious-domain.xyz"

   Pod receives: connection refused / timeout
```

### Case 4: Automatic Quarantine (Connection Fan-Out)

```
Compromised pod (fd00:1234:0001:0042::9) begins port scanning

1. Pod sends TCP SYNs to 500+ unique destinations in 60 seconds

2. Flow record ring buffer captures each connection attempt:
   flow_record: {pod=0x9999, dest=..., verdict=ALLOW/DENY}

3. Userspace daemon aggregates flow records, counts unique dests:
   Detects: 500+ unique dests in 60s window → threshold exceeded

4. Agent sets quarantine bit:
   egress_rate_limit[pod=0x9999].quarantine = 1
   (Single BPF map update, ~100ns)

5. Next packet from pod:
   TC egress: quarantine bit set → TC_ACT_SHOT
   connection_log: {pod=0x9999, verdict=QUARANTINE}

6. Agent sends alert:
   → Slack #security-alerts
   → PagerDuty egress-team
   → Audit log: "Auto-quarantine pod ci/compromised-job-abc, reason: connection_fanout"
```

---

## 14. Interaction with Cilium

When Cilium is the intra-cluster CNI, the egress pipeline integrates
cleanly via ownership boundaries.

### 14.1 Ownership Split

| Concern | Cilium | Wirescale |
|---------|--------|-----------|
| Intra-cluster pod-to-pod policy | CiliumNetworkPolicy | Defers to Cilium |
| Intra-cluster encryption | Cilium WireGuard (cilium_wg0) | Not involved |
| Cross-cluster connectivity | Not involved | Wirescale WireGuard (wg0) |
| **Egress to internet** | **CiliumNetworkPolicy egress rules (optional)** | **WirescaleEgressPolicy (primary)** |
| DNS snooping | Cilium DNS proxy (L7) | Wirescale packet mirror → userspace |
| NPTv6 translation | Not involved | Wirescale nptv6 interface |
| NAT64 translation | Not involved | Wirescale nat64 interface |
| Egress gateway | CiliumEgressGateway (if used) | WirescaleEgressGateway |

### 14.2 Coexistence Strategy

**Option A: Wirescale-only egress (recommended)**

Cilium handles intra-cluster L3/L4 policy. Wirescale handles all
internet-bound egress via its own policy engine, NPTv6, NAT64, and
observability. CiliumNetworkPolicy egress rules are not used for
internet traffic.

Rationale: Wirescale's FQDN resolution integrates with DNS snooping
and the threat intelligence pipeline. Running two independent egress
policy engines creates confusing ordering and potential conflicts.

**Option B: Layered egress**

Both Cilium and Wirescale enforce egress policy. Cilium's
CiliumNetworkPolicy applies first (TC on pod veth, Cilium-owned).
Wirescale's WirescaleEgressPolicy applies second (TC on nptv6/nat64
interfaces). This provides defense-in-depth but increases operational
complexity.

### 14.3 Hubble Integration

Wirescale flow logs are exported in Hubble-compatible protobuf format.
Hubble Relay aggregates flows from both Cilium (intra-cluster) and
Wirescale (cross-cluster + egress) into a unified flow stream. Hubble
UI shows end-to-end flow visibility without distinguishing the
enforcement source.

---

## Appendix A: BPF Map Summary

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `identity_cache` | Hash | ifindex (u32) | pod identity | 256 | Map veth to pod identity |
| `egress_ip_policy` | LPM trie | pod_id + IP prefix | action + ports_bitmap | 65,536 | Pre-computed verdicts (CIDR + DNS-derived) |
| `egress_rate_limit` | Hash | pod_id | token buckets + quarantine | 16,384 | Per-pod rate limiting and quarantine |
| `egress_flow_log` | Per-CPU ring | — | flow record (48B) | 4 MB/CPU | Minimal 5-tuple flow logging |
| `packet_mirror` | Per-CPU ring | — | raw packet bytes | 2 MB/CPU | DNS response + TLS ClientHello mirror to userspace |
| `threat_intel_ip` | LPM trie | IP prefix | category + feed_id | 1,000,000 | Threat intelligence IP blocklist |

**Removed from eBPF** (now userspace-only):

| Data | Where it lives | Why |
|------|---------------|-----|
| IP→FQDN mapping | Userspace hash table | DNS parsing too complex for eBPF |
| FQDN policy rules | Userspace (compiled to `egress_ip_policy` via DNS) | Wildcard matching, TTL tracking |
| SNI→FQDN mapping | Userspace hash table | TLS parsing too complex for eBPF |
| FQDN threat intel | Userspace hash table | String matching + feed management |
| Fan-out counters | Userspace counters | Anomaly detection logic is userspace |

Total BPF map memory per-node: ~70 MB (dominated by threat_intel_ip
at 1M entries × 64B ≈ 64MB). The flow log and packet mirror ring
buffers add ~6 MB/CPU. No conntrack or NAT state table. SIIT-DC
translation is fully stateless — pod identity is derived arithmetically
from the CGNAT address (zero map lookups).

---

## Appendix B: Implementation Phases

| Phase | Scope | Deliverables |
|-------|-------|-------------|
| **1** | NPTv6 + basic egress | `nptv6` interface, ULA↔GUA translation, default route, basic CIDR egress policy |
| **2** | DNS snooping + FQDN policy | Packet mirror ring buffer, userspace DNS parser, `WirescaleEgressPolicy` with FQDN rules |
| **3** | Rate limiting + quarantine | Token buckets, `kubectl wirescale quarantine`, `WirescaleEgressQuota` |
| **4** | SNI extraction + observability | Userspace TLS ClientHello parser, flow export (Hubble, IPFIX, JSON), Grafana dashboards |
| **5** | Threat intelligence + auto-response | Threat feed ingestion, `threat_intel_*` maps, `WirescaleThreatResponse` CRD |
| **6** | L7 proxy (optional) | Envoy sidecar integration, URL-level filtering, `proxy` action in policy |
