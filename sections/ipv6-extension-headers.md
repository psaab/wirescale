### IPv6 Extension Header Parsing in eBPF Programs

> Extends: SECURITY.md Section 7 (Enforcement Engine), PERFORMANCE.md
> Section 3 (eBPF NAT64/CLAT Fast Path)

The enforcement pseudocode in Section 7 and the NAT64 translation logic in
PERFORMANCE.md Section 3 parse the fixed 40-byte IPv6 header to extract
`nexthdr`, source/destination addresses, and transport-layer fields. In
production traffic, IPv6 packets MAY carry an extension header chain
between the fixed header and the upper-layer payload. Extension header
types include Hop-by-Hop Options (0), Routing (43), Fragment (44),
Destination Options (60), Authentication Header (51), and ESP (50).

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
per-packet enforcement budget of ~50-80 ns documented in Section 7.

The NAT64 translation path (PERFORMANCE.md Section 3) MUST perform the
same extension header walk before extracting transport-layer checksums.
The GRO/GSO amortization described in Section 3 applies identically:
the extension header parse cost is paid once per superpacket, not per
MTU-segment.

#### Monitoring

The agent SHOULD expose a per-node metric
`wirescale_ext_header_depth_exceeded_total` counting packets that hit
the maximum chain depth. A sustained non-zero rate MAY indicate evasion
attempts or misconfigured middleboxes injecting extension headers.
