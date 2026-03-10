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

5. **Line-rate performance.** NPTv6 translation, policy lookup, and
   flow logging all happen in eBPF on the egress fast path. No
   userspace proxy in the data plane for L3/L4 traffic.

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

Outbound internet traffic traverses a layered pipeline. Each layer is
an eBPF program or a kernel fast-path operation.

```
Pod (ULA fd00:1234:0001:0042::5)
  │
  ├─ [1] TC egress on pod veth ─────────── Egress policy check
  │       • identity_cache lookup (source pod)
  │       • egress_policy_map lookup (dest IP → FQDN → verdict)
  │       • DENY → drop + log; ALLOW → continue
  │       • connection_log ring buffer entry (5-tuple + FQDN + verdict)
  │       • rate_limit_map check (per-pod token bucket)
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
2. TC egress on pod veth: egress policy check against the **original
   FQDN** (looked up from `dns_fqdn_map`, see §5). If denied, drop.
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

Every DNS response transiting a pod's veth is parsed by an eBPF program
to build a real-time mapping of IP addresses to FQDNs:

```
Pod queries "api.stripe.com" via CoreDNS
  → CoreDNS resolves: 52.204.1.100, 52.204.1.101
  → DNS response transits pod veth
  → TC ingress eBPF on veth parses DNS response:
      dns_fqdn_map.update(52.204.1.100 → "api.stripe.com", TTL=300s)
      dns_fqdn_map.update(52.204.1.101 → "api.stripe.com", TTL=300s)
  → Subsequent packets to 52.204.1.100 can be attributed to "api.stripe.com"
```

**BPF map: `dns_fqdn_map`** (LRU hash, per-node)

```
Key:   destination IPv6 address (16 bytes) or IPv4-mapped (16 bytes)
Value: { fqdn[256], ttl_expiry, source_pod_id, query_timestamp }
Max entries: 65,536 (configurable)
```

### 5.2 DNS Response Parsing in eBPF

The TC ingress program on each pod veth inspects UDP port 53 responses:

```c
SEC("tc/dns_snoop")
int dns_response_snoop(struct __sk_buff *skb) {
    /* Only inspect UDP src port 53 (DNS responses) */
    if (!is_udp_sport_53(skb))
        return TC_ACT_OK;

    struct dns_header *dns = get_dns_header(skb);
    if (dns->qr != 1)          /* Not a response */
        return TC_ACT_OK;
    if (dns->ancount == 0)      /* No answers */
        return TC_ACT_OK;

    /* Parse question section to extract FQDN */
    char fqdn[256];
    int off = parse_dns_question(skb, fqdn, sizeof(fqdn));

    /* Walk answer RRs, extract A/AAAA records */
    for (int i = 0; i < MIN(dns->ancount, MAX_RR_PARSE); i++) {
        struct dns_rr rr;
        off = parse_dns_rr(skb, off, &rr);
        if (rr.type == DNS_TYPE_AAAA || rr.type == DNS_TYPE_A) {
            struct fqdn_entry entry = {
                .ttl_expiry = bpf_ktime_get_ns() + rr.ttl * 1e9,
                .source_pod = get_pod_identity(skb),
            };
            __builtin_memcpy(entry.fqdn, fqdn, sizeof(fqdn));
            bpf_map_update_elem(&dns_fqdn_map, &rr.rdata, &entry, BPF_ANY);
        }
    }
    return TC_ACT_OK;
}
```

**Verifier constraints:** DNS parsing is bounded (max 8 RRs parsed,
max 256-byte name, max 512-byte UDP or 4096-byte TCP). Compression
pointers are followed up to 4 hops. Malformed responses are passed
through without map updates.

### 5.3 DNS-over-HTTPS/TLS (DoH/DoT) Handling

eBPF cannot inspect encrypted DNS. Pods using DoH/DoT bypass the DNS
snooping layer. Mitigations:

- **CoreDNS enforcement:** The cluster's CoreDNS SHOULD be the only
  permitted DNS resolver. Egress policy SHOULD deny UDP/TCP port 53
  to all destinations except CoreDNS, and deny HTTPS to known DoH
  providers (configurable blocklist).
- **Redirect policy:** The agent MAY install a DNAT rule redirecting
  all port-53 traffic to CoreDNS (transparent DNS proxy).
- **Unsnooped traffic:** Packets to IPs not in `dns_fqdn_map` are
  flagged as `fqdn: <unknown>` in logs. Policy can be configured to
  deny traffic to unknown FQDNs (strict mode) or allow-and-log
  (permissive mode).

### 5.4 DNS Query Logging

In addition to response snooping, the agent logs DNS queries:

```
dns_query_log ring buffer entry:
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

### 6.3 Compilation to eBPF Maps

The wirescale-agent compiles FQDN rules into two BPF maps:

**`egress_fqdn_policy`** (hash map, per-node):
```
Key:   { pod_identity, fqdn_hash }
Value: { action (allow/deny/log), ports_bitmap, rate_limit_id }
```

**`egress_ip_policy`** (LPM trie, per-node):
```
Key:   { pod_identity, destination_ip_prefix }
Value: { action, ports_bitmap, fqdn_hash (for attribution), rate_limit_id }
```

When DNS snooping populates `dns_fqdn_map` with resolved IPs, the
agent installs corresponding entries in `egress_ip_policy` with the
FQDN hash for attribution. When the DNS TTL expires, the agent removes
the IP entries. This means:

- **FQDN changes propagate automatically.** If `api.stripe.com` changes
  IPs, the new DNS response updates the maps.
- **Stale IPs are removed.** No risk of allowing traffic to a reused IP
  that previously belonged to an allowed domain.
- **No manual IP management.** Operators write domain names; the system
  handles the rest.

### 6.4 eBPF Enforcement (TC Egress on Pod Veth)

```c
SEC("tc/egress_policy")
int egress_check(struct __sk_buff *skb) {
    struct pod_identity *pod = lookup_identity(skb->ifindex);
    struct ipv6hdr *ip6 = get_ipv6_hdr(skb);
    __u16 dport = get_l4_dport(skb);

    /* 1. Check CIDR policy (LPM trie — catches broad deny rules) */
    struct egress_ip_key key = { .pod_id = pod->id, .addr = ip6->daddr };
    struct egress_ip_value *cidr_v = bpf_map_lookup_elem(&egress_ip_policy, &key);

    if (cidr_v) {
        if (cidr_v->action == DENY) {
            log_egress_decision(skb, pod, DENY, cidr_v->fqdn_hash);
            return TC_ACT_SHOT;
        }
        if (cidr_v->action == ALLOW && port_matches(cidr_v->ports_bitmap, dport)) {
            log_egress_decision(skb, pod, ALLOW, cidr_v->fqdn_hash);
            check_rate_limit(skb, pod, cidr_v->rate_limit_id);
            return TC_ACT_OK;
        }
    }

    /* 2. Lookup FQDN from dns_fqdn_map */
    struct fqdn_entry *fqdn = bpf_map_lookup_elem(&dns_fqdn_map, &ip6->daddr);

    /* 3. If destination has no FQDN mapping — policy decision */
    if (!fqdn) {
        /* Unknown destination: apply unknown-dest policy */
        return apply_unknown_dest_policy(skb, pod);
    }

    /* 4. Check FQDN policy */
    struct egress_fqdn_key fkey = { .pod_id = pod->id, .fqdn_hash = hash(fqdn->fqdn) };
    struct egress_fqdn_value *fv = bpf_map_lookup_elem(&egress_fqdn_policy, &fkey);

    if (fv && fv->action == ALLOW && port_matches(fv->ports_bitmap, dport)) {
        log_egress_decision(skb, pod, ALLOW, fkey.fqdn_hash);
        check_rate_limit(skb, pod, fv->rate_limit_id);
        return TC_ACT_OK;
    }

    /* 5. Default: deny */
    log_egress_decision(skb, pod, DENY, fkey.fqdn_hash);
    return TC_ACT_SHOT;
}
```

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

For HTTPS traffic (port 443), the eBPF program inspects the TLS
ClientHello to extract the Server Name Indication (SNI) field. This
provides FQDN-level visibility even when DNS snooping missed the
resolution (DoH, cached, hardcoded IP).

```c
SEC("tc/sni_inspect")
int sni_extract(struct __sk_buff *skb) {
    /* Only inspect TCP SYN or first data packet on port 443 */
    if (!is_tcp_dport_443(skb) || !is_client_hello(skb))
        return TC_ACT_OK;

    char sni[256];
    int sni_len = parse_tls_client_hello_sni(skb, sni, sizeof(sni));
    if (sni_len <= 0)
        return TC_ACT_OK;

    /* Update dns_fqdn_map with SNI (supplements DNS snooping) */
    struct fqdn_entry entry = {
        .ttl_expiry = bpf_ktime_get_ns() + SNI_TTL_NS,
        .source_pod = get_pod_identity(skb),
        .source = FQDN_SOURCE_SNI,
    };
    __builtin_memcpy(entry.fqdn, sni, sizeof(sni));
    bpf_map_update_elem(&dns_fqdn_map, &dest_addr, &entry, BPF_NOEXIST);

    /* Enforce FQDN policy against SNI */
    return enforce_fqdn_policy(skb, sni);
}
```

**Limitations:**
- Encrypted Client Hello (ECH) hides the SNI. Detection: the outer
  SNI is a cloudflare-ech.example.com stub. Policy can deny ECH
  connections or allow-and-flag.
- QUIC Initial packets carry SNI in the QUIC CRYPTO frame. The parser
  MUST handle both TLS-over-TCP and QUIC-over-UDP ClientHellos.
- SNI parsing adds ~100-200ns per connection setup (first packet only).

### 7.2 URL-Level Filtering (L7 Proxy)

eBPF operates at L3/L4 and can extract SNI, but cannot inspect HTTP
request paths, headers, or POST bodies. For URL-level filtering
(`/api/v1/transfer` vs `/api/v1/status`), a userspace L7 proxy is
required.

**Architecture:**

```
Pod → TC egress (L3/L4 policy) → [if L7 inspection needed] → redirect to L7 proxy
  → L7 proxy (Envoy/wirescale-proxy) inspects HTTP/gRPC
  → L7 proxy → nptv6/nat64 → internet
```

**When to use L7 proxy:**

| Requirement | L3/L4 eBPF | L7 Proxy |
|-------------|-----------|----------|
| FQDN allowlist (domain level) | Yes (DNS+SNI) | Yes |
| Port/protocol filtering | Yes | Yes |
| URL path filtering | No | Yes |
| HTTP header inspection | No | Yes |
| Request/response body scanning | No | Yes |
| mTLS to external services | No | Yes |

**L7 proxy is optional.** Most workloads need only FQDN+port filtering
(handled entirely in eBPF at line rate). L7 proxy is deployed only for
workloads that require URL-level control. This avoids imposing proxy
overhead on all traffic.

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

The agent can detect anomalous egress patterns and auto-quarantine:

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

Every egress connection is logged to a per-CPU ring buffer consumed
by the wirescale-agent userspace daemon:

```
struct egress_flow_log {
    __u64 timestamp_ns;
    __u32 pod_identity;
    __u8  direction;           /* egress */
    __u8  verdict;             /* allow, deny, throttle, quarantine */
    __u8  protocol;            /* TCP, UDP, SCTP */
    __u8  ip_version;          /* 4, 6 */
    __u8  fqdn[256];           /* resolved FQDN or "<unknown>" */
    __u8  fqdn_source;         /* dns_snoop, sni, manual, unknown */
    union {
        __be32 ipv4;
        struct in6_addr ipv6;
    } src_addr, dst_addr;
    __be16 src_port, dst_port;
    __u64 bytes_out;           /* (updated on connection close) */
    __u64 bytes_in;
    __u64 duration_ns;
    __u32 rate_limit_id;
    __u16 sni_len;
    __u8  sni[256];            /* TLS SNI if extracted */
};
```

### 9.2 Metrics (Prometheus)

The agent exposes egress-specific metrics at `:9090/metrics`:

```
# Per-pod egress traffic
wirescale_egress_bytes_total{pod, namespace, fqdn, dest_ip, protocol, verdict}
wirescale_egress_connections_total{pod, namespace, fqdn, protocol, verdict}
wirescale_egress_packets_total{pod, namespace, protocol, verdict}

# DNS
wirescale_dns_queries_total{pod, namespace, query_name, query_type, rcode}
wirescale_dns_fqdn_map_size{node}
wirescale_dns_fqdn_map_evictions_total{node}

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

The agent loads threat intelligence feeds into eBPF maps for real-time
blocking:

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

Every egress packet traverses the pipeline. The budget at 10 Gbps
(~14.8 Mpps at 64B, ~1.2 Mpps at 1KB typical):

| Stage | Cost | Notes |
|-------|------|-------|
| Identity lookup | ~10 ns | Hash map, O(1) |
| Egress CIDR policy (LPM) | ~30 ns | LPM trie, O(prefix_len) |
| FQDN map lookup | ~15 ns | Hash map, O(1) |
| FQDN policy lookup | ~15 ns | Hash map, O(1) |
| Rate limit check | ~10 ns | Per-CPU token bucket |
| Connection log write | ~20 ns | Per-CPU ring buffer, non-blocking |
| NPTv6 translation | ~15 ns | 32-bit rewrite + 16-bit checksum |
| SIIT-DC translation | ~20 ns | Stateless header swap, no state table (IPv4 path) |
| **Total (fast path)** | **~115-120 ns** | **~8.3-8.7 Mpps single core** |

At 1KB average packet size, 10 Gbps = ~1.2 Mpps, well within a
single core's budget. At 64B packets (worst case), 8.7 Mpps per core
sustains ~4.5 Gbps — additional cores via RSS handle higher rates.

### 11.2 DNS Snooping Cost

DNS snooping runs on the ingress path only for UDP port 53 responses.
DNS response rate is orders of magnitude lower than data packet rate
(~10-100 DNS responses/sec per pod vs ~100K+ data packets/sec). The
cost of DNS parsing (~500ns per response) is negligible.

### 11.3 SNI Extraction Cost

TLS ClientHello parsing runs only on the **first packet** of each TLS
connection (TCP SYN+data or standalone ClientHello). At ~100-200ns per
extraction and ~1000 new connections/sec per pod, total cost is ~0.1-0.2
ms/sec — invisible.

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
     TC ingress eBPF: dns_fqdn_map[64:ff9b::34cc:0164] = "api.stripe.com"

2. TCP SYN to 64:ff9b::34cc:0164:443
   TC egress on pod veth:
     identity_cache: pod = payments/payment-service (identity 0x1234)
     dns_fqdn_map[64:ff9b::34cc:0164] → "api.stripe.com"
     egress_fqdn_policy[0x1234, hash("api.stripe.com")] → ALLOW, port 443
     rate_limit check → OK
     connection_log: {pod=0x1234, fqdn="api.stripe.com", dest=64:ff9b::34cc:0164,
                      port=443, verdict=ALLOW}
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
     TC ingress eBPF: dns_fqdn_map[2606:50c0:8003::1] = "github.com"

2. TCP SYN to 2606:50c0:8003::1:443
   TC egress on pod veth:
     identity_cache: pod = ci/builder (identity 0x5678)
     dns_fqdn_map[2606:50c0:8003::1] → "github.com"
     egress_fqdn_policy[0x5678, hash("github.com")] → ALLOW, port 443
     SNI extraction: "github.com" (confirms DNS mapping)
     rate_limit check → OK
     connection_log: {pod=0x5678, fqdn="github.com", sni="github.com",
                      dest=2606:50c0:8003::1, port=443, verdict=ALLOW}
     → TC_ACT_OK

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
   dns_fqdn_map[2a01:dead::1] = "suspicious-domain.xyz"

2. TCP SYN to 2a01:dead::1:443
   TC egress on pod veth:
     identity_cache: pod = payments/payment-service (identity 0x1234)
     egress_ip_policy: no CIDR match
     dns_fqdn_map[2a01:dead::1] → "suspicious-domain.xyz"
     egress_fqdn_policy[0x1234, hash("suspicious-domain.xyz")] → NOT FOUND
     Strict mode: no explicit allow → DENY
     connection_log: {pod=0x1234, fqdn="suspicious-domain.xyz",
                      dest=2a01:dead::1, port=443, verdict=DENY}
     → TC_ACT_SHOT

   Pod receives: connection refused / timeout
```

### Case 4: Automatic Quarantine (Connection Fan-Out)

```
Compromised pod (fd00:1234:0001:0042::9) begins port scanning

1. Pod sends TCP SYNs to 500+ unique destinations in 60 seconds

2. TC egress counts unique destinations per pod:
   egress_fanout_counter[pod=0x9999] increments per unique dest IP

3. Agent userspace reads fanout counter every 10 seconds:
   Detects: 500+ unique dests in window → threshold exceeded

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
| DNS snooping | Cilium DNS proxy (L7) | Wirescale eBPF (L3/L4) |
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
| `dns_fqdn_map` | LRU hash | dest IP (16B) | fqdn + metadata | 65,536 | IP→FQDN mapping from DNS snooping |
| `egress_fqdn_policy` | Hash | pod_id + fqdn_hash | action + ports | 32,768 | Compiled FQDN allowlist |
| `egress_ip_policy` | LPM trie | pod_id + IP prefix | action + fqdn_hash | 65,536 | Compiled CIDR rules + DNS-derived entries |
| `egress_rate_limit` | Hash | pod_id | token buckets + quarantine | 16,384 | Per-pod rate limiting and quarantine |
| `egress_flow_log` | Per-CPU ring | — | flow record | 6 MB/CPU | Connection logging |
| `threat_intel_ip` | LPM trie | IP prefix | category + feed_id | 1,000,000 | Threat intelligence IP blocklist |
| `threat_intel_fqdn` | Hash | fqdn_hash | category + feed_id | 100,000 | Threat intelligence FQDN blocklist |
| `egress_fanout_counter` | Per-CPU hash | pod_id | unique_dest_count | 16,384 | Anomaly detection (connection fan-out) |

Total per-node memory: ~85 MB (dominated by threat_intel_ip at 1M entries × 64B ≈ 64MB).
Note: no conntrack or NAT state table. SIIT-DC translation is fully stateless —
pod identity is derived arithmetically from the CGNAT address (zero map lookups).

---

## Appendix B: Implementation Phases

| Phase | Scope | Deliverables |
|-------|-------|-------------|
| **1** | NPTv6 + basic egress | `nptv6` interface, ULA↔GUA translation, default route, basic CIDR egress policy |
| **2** | DNS snooping + FQDN policy | `dns_fqdn_map`, DNS response parser, `WirescaleEgressPolicy` with FQDN rules |
| **3** | Rate limiting + quarantine | Token buckets, `kubectl wirescale quarantine`, `WirescaleEgressQuota` |
| **4** | SNI extraction + observability | TLS ClientHello parser, flow export (Hubble, IPFIX, JSON), Grafana dashboards |
| **5** | Threat intelligence + auto-response | Threat feed ingestion, `threat_intel_*` maps, `WirescaleThreatResponse` CRD |
| **6** | L7 proxy (optional) | Envoy sidecar integration, URL-level filtering, `proxy` action in policy |
