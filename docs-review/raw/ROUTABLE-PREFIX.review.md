**Scope Coverage Summary**

| Section | Lines | Claims reviewed |
|---|---:|---:|
| Table of Contents | 9-23 | 0 (index only) |
| 1. /64-per-Host Model | 27-64 | 14 |
| 2. Changes from Base Architecture | 67-106 | 13 |
| 3. Address Architecture | 110-241 | 19 |
| 4. Routing: Fabric-Managed BGP | 244-341 | 11 |
| 5. WireGuard Encryption-Only | 345-433 | 9 |
| 6. Selective Encryption Modes | 436-518 | 4 |
| 7. IPv4 Compatibility | 521-587 | 8 |
| 8. Security | 591-728 | 10 |
| 9. Multi-Site/Hybrid | 731-805 | 7 |
| 10. CNI Changes | 808-859 | 9 |
| 11. Packet Flows | 863-997 | 8 |
| 12. Deployment Topologies | 1001-1041 | 6 |
| 13. Comparison/Guidance | 1045-1081 | 11 |
| **Total** | **9-1081** | **129** |

Evidence codes used below are in the Sources section.

---

**Claim Inventory Table**

| claim_id | lines | claim | status | evidence |
|---|---:|---|---|---|
| C001 | 31-33 | Each host gets a dedicated /64 from GUA space. | Needs Qualification | Valid design pattern, not protocol requirement. |
| C002 | 32 | GUA is `2000::/3`. | Supported | IANA-UNI, R4291 |
| C003 | 33 | Every pod gets address from host /64. | Needs Qualification | Design assumption only. |
| C004 | 34 | Pod addresses are internet-routable without NAT/tunnels/overlays. | Needs Qualification | True only if routes/ACLs advertise/permit. |
| C005 | 37 | /48 contains 65,536 /64s. | Supported | IPv6 prefix math |
| C006 | 47 | SLAAC mandates /64. | Partially Supported | R4862 + R7421 (true for standard 64-bit IID SLAAC links). |
| C007 | 47-48 | NDP assumes /64. | Unsupported | R4861 does not require /64 for ND operation. |
| C008 | 48 | Switch ASICs optimize for /64. | Needs Qualification | R7421 cites reports, not universal rule. |
| C009 | 48-49 | /64 has 2^64 addresses. | Supported | IPv6 prefix math |
| C010 | 54-55 | No overlay needed for reachability. | Needs Qualification | Conditional on routed fabric design. |
| C011 | 56-57 | No SNAT outbound; source preserved. | Needs Qualification | True for IPv6 egress if upstream routes exist. |
| C012 | 58-59 | Direct inbound from internet possible. | Needs Qualification | Depends on routing + perimeter policy. |
| C013 | 60-61 | WireGuard optional for reachability. | Needs Qualification | True in native-routed mode only. |
| C014 | 62-63 | No encapsulation overhead for unencrypted same-site traffic. | Supported | Native forwarding path avoids WG encapsulation. |
| C015 | 69-70 | Base architecture uses ULA + WireGuard overlay for reachability+encryption. | Supported | ARCH |
| C016 | 75 | Address model shifts ULA->GUA. | Supported | ARCH + document context |
| C017 | 76 | Inter-node reachability shifts WG->native BGP routing. | Partially Supported | Valid target design; not implementation-verified. |
| C018 | 77 | Encryption becomes selective. | Needs Qualification | Policy/model claim only. |
| C019 | 78 | Base internet reachability is via NAT64 gateway. | Unsupported | ARCH distinguishes IPv6 egress vs NAT64 for IPv4. |
| C020 | 79 | Base inbound internet not possible without proxy. | Needs Qualification | Generally true for ULA, but edge translation/proxy exceptions. |
| C021 | 80 | New routing protocol is fabric BGP, not Wirescale. | Partially Supported | Design statement; no impl artifacts. |
| C022 | 81 | Base outbound SNAT is MASQUERADE at NAT64. | Partially Supported | True for IPv4 NAT64 path, not all egress. |
| C023 | 82 | IPv4 path CLAT->NAT64 unchanged. | Supported | ARCH, R6877/R6146 model |
| C024 | 83 | Performance ceiling becomes line-rate native forwarding. | Needs Qualification | Hardware/path dependent. |
| C025 | 90 | WG routing overlay removed for same-site traffic. | Needs Qualification | Design mode statement. |
| C026 | 95 | Ingress firewall added because pods are internet-exposed. | Needs Qualification | Depends on deployment exposure model. |
| C027 | 99-105 | Controller/agent/CNI/CRDs/DNS/IPv4 model unchanged. | Partially Supported | Mostly consistent internally, but architecture semantics changed materially. |
| C028 | 115 | `3fff::/32` is provider RIR/LIR allocation. | Outdated | IANA-SP + RFC9637: `3fff::/20` is documentation prefix. |
| C029 | 116 | Site /48 has 65,536 /64s. | Supported | Prefix math |
| C030 | 117 | /56 gives 256 /64s. | Supported | Prefix math |
| C031 | 121 | /52 gives 4,096 /64s. | Supported | Prefix math |
| C032 | 121-126 | Example pod /64s are inside stated /52 block. | Unsupported | Prefix placement is inconsistent (hextet boundary error). |
| C033 | 134 | Host has two IPv6 addresses from two /64s. | Needs Qualification | Common pattern, not mandatory. |
| C034 | 136-141 | Rack address as /128 on rack /64 for identity/WG/BGP next-hop. | Needs Qualification | Possible, but /128-onlink behavior must be explicit. |
| C035 | 143-145 | Dedicated pod /64 is routed to host. | Supported | Standard routed-subnet design. |
| C036 | 179-182 | Rack /64 NDP works naturally, no proxy NDP needed. | Partially Supported | True for shared L2 rack segment. |
| C037 | 184-188 | Routing pod /64 avoids pod NDP flooding on rack. | Supported | R4861 + routed-host model reasoning. |
| C038 | 190-192 | Host failure withdraws pod /64 route automatically. | Needs Qualification | Depends on BGP timers/BFD/fabric automation. |
| C039 | 196-202 | WG endpoint uses rack address; wg0 has no IP. | Supported | WG-MAN/WGQ-MAN allow no Address in `wg`; valid design. |
| C040 | 205-207 | Rack/pod address spaces never overlap. | Unsupported | Conflicts with incorrect prefix hierarchy examples. |
| C041 | 211 | CNI assigns directly (no SLAAC/DHCPv6). | Supported | Valid CNI behavior model. |
| C042 | 217 | `::0` is subnet-router anycast. | Supported | R4291 |
| C043 | 220 | Available addresses are `2^64 - 10`. | Supported | Math |
| C044 | 223-227 | DAD is disabled because IPAM authoritative/no shared link. | Needs Qualification | KERN: `accept_dad` is configurable; disabling is optional optimization. |
| C045 | 232-236 | Pod IPv4 uses CGNAT `100.64/10` scheme. | Supported | R6598 + design |
| C046 | 239-240 | CLAT mechanism unchanged/stateless at pod veth. | Partially Supported | R6877 defines CLAT function; implementation specifics not shown. |
| C047 | 248-250 | Fabric-managed BGP for rack/pod prefixes is “standard” modern DC model. | Needs Qualification | Common but not universal. |
| C048 | 252-254 | Rack /64 is directly connected L2; ToR learns hosts via NDP. | Supported | R4861 behavior |
| C049 | 256-259 | Pod /64 routed to host via eBGP/static. | Supported | Plausible and standard routing pattern. |
| C050 | 261 | Wirescale does not include BGP speaker. | Partially Supported | Doc claim; no code evidence in repo. |
| C051 | 290-293 | Hosts advertise pod /64; ToR aggregates upstream. | Needs Qualification | Topology-specific, not mandatory. |
| C052 | 299-304 | Fabric must provide rack L2 and pod /64 routes site-wide. | Supported | Architectural prerequisites. |
| C053 | 306-307 | Default IPv6 route via RA or BGP. | Supported | R4861 + operational practice |
| C054 | 309-311 | `WirescaleNode` stores addressing; does not program BGP. | Partially Supported | Documentation-only evidence. |
| C055 | 330-333 | `accept_ra=2` required with forwarding to keep RA processing. | Supported | KERN |
| C056 | 337-340 | Proxy NDP is not needed. | Needs Qualification | True for routed pod prefix model; not universally. |
| C057 | 334-335 | Host forwarding sysctls must be enabled. | Supported | Linux router behavior |
| C058 | 349-352 | WG shifts from overlay+routing to encryption-only. | Needs Qualification | Architectural mode claim. |
| C059 | 354-355 | Cilium and Calico already do this in native mode. | Partially Supported | CIL-WG/CIL-RT/CAL-WG show native routing + WG support, details differ. |
| C060 | 365-367 | Unencrypted same-site path is pure native IPv6 at line rate/zero overhead. | Needs Qualification | No WG overhead yes; line rate not guaranteed. |
| C061 | 368-371 | Encrypted path uses eBPF redirect->wg0 only when policy requires. | Partially Supported | Valid mechanism; implementation not evidenced. |
| C062 | 376-377 | Encryption decision is per-packet at pod veth egress. | Partially Supported | Design assertion only. |
| C063 | 406-407 | Same-site unencrypted, remote-site encrypted by default. | Needs Qualification | Policy choice, not standards fact. |
| C064 | 408 | External `::/0` unencrypted because TLS already covers it/no benefit. | Unsupported | Overbroad security claim; transport encryption still may add value. |
| C065 | 413-420 | WG config is simpler with no Address on wg0. | Supported | WG-MAN/WGQ-MAN |
| C066 | 428-432 | Redirected traffic enters wg0, exits as UDP 51820, returns decrypted and routed. | Supported | WG data path model |
| C067 | 447-460 | Encryption modes `always/cross-site/never/policy` exist as CRD schema. | Partially Supported | Design schema shown, no CRD validation artifacts here. |
| C068 | 469-472 | `cross-site` is recommended default for multi-site trusted fabric/MACsec. | Needs Qualification | Recommendation, threat-model dependent. |
| C069 | 474-476 | `never` mode suitable in trusted or mTLS-only environments. | Needs Qualification | Security-policy dependent. |
| C070 | 512-517 | Throughput/CPU table including “~10G/core WG limit”. | Needs Qualification | Hardware/kernel dependent; no external benchmark citation here. |
| C071 | 527-529 | CLAT per-pod model unchanged in GUA mode. | Partially Supported | R6877 conceptually; implementation not shown. |
| C072 | 531 | Deterministic mapping formula `100.64.N.P <-> 3fff:0a:N::P`. | Needs Qualification | Local addressing convention only. |
| C073 | 540-548 | DNS64 synthesizes AAAA and NAT64 translates to IPv4 egress. | Supported | R6147 + R6146 + R6052 |
| C074 | 555-557 | ULA outbound IPv6 required SNAT. | Supported | ULA non-global routability (R4291 scope semantics). |
| C075 | 560-565 | GUA outbound IPv6 needs no SNAT/NAT64/translation. | Needs Qualification | True if routes/policy permit return reachability. |
| C076 | 567-568 | “Zero overhead” is the primary GUA performance benefit. | Needs Qualification | Qualitative benefit valid; “zero overhead” absolute is too strong. |
| C077 | 572-583 | Inbound IPv4->pod is done by NAT64 ingress gateway. | Unsupported | R6146 NAT64 is IPv6-client to IPv4-server direction. |
| C078 | 578-580 | NAT64 ingress embeds client IPv4 in `64:ff9b::` source to pod. | Unsupported | R6052 WKP constraints + translator model mismatch. |
| C079 | 596-597 | Every GUA pod is reachable from internet unless firewalled. | Needs Qualification | Also depends on advertised routes/upstream ACL/SG/NACL. |
| C080 | 602-603 | Controller auto-installs mandatory default-deny ingress policy. | Unsupported | No implementation evidence; K8S-NP defaults are allow unless policies applied. |
| C081 | 623-624 | Pod-to-pod traffic blocked until explicit allow. | Unsupported | Only true if default-deny actually present cluster-wide. |
| C082 | 625-626 | Inbound default deny, outbound default allow. | Partially Supported | Matches NP semantics only when deny policy exists. |
| C083 | 630-632 | Agent installs XDP NIC firewall for external->pod filtering. | Partially Supported | Design claim; no code in repo. |
| C084 | 666-667 | XDP runs at 14-26 Mpps/core. | Needs Qualification | Benchmark-specific; no authoritative universal value. |
| C085 | 671-693 | External ingress should be explicitly allowed via policy. | Supported | Sound policy model (K8S-NP principle). |
| C086 | 689 | `64:ff9b::/96` should be allowed for NAT64’d IPv4 clients. | Needs Qualification | Depends on translator architecture; not generic default. |
| C087 | 695-696 | Controller compiles ingress policy into XDP maps. | Partially Supported | Design-only claim. |
| C088 | 700-727 | XDP LRU_HASH rate limiter keyed by source /64 at line rate. | Needs Qualification | Implementation/perf assumptions unverified. |
| C089 | 735-737 | Multi-site: /48 per site, native intra-site, WG inter-site. | Needs Qualification | Deployment pattern, not protocol requirement. |
| C090 | 754 | 2-3 gateways per site for HA. | Needs Qualification | Heuristic, environment-dependent. |
| C091 | 756-758 | Gateways advertise remote /48 and transit cross-site traffic. | Partially Supported | Plausible routing design. |
| C092 | 760-777 | Gateway WG endpoints use rack IPs; AllowedIPs remote /48. | Supported | Valid WireGuard configuration style. |
| C093 | 779-781 | Worker nodes need no WG in `cross-site` mode. | Unsupported | Contradicted by Section 5/11 worker `wg0` flow. |
| C094 | 785-798 | Hybrid GUA site + ULA site can coexist via WG gateway. | Supported | Feasible with policy/routing translation gateways. |
| C095 | 802-804 | External peers connect via gateway regardless of internal GUA/ULA. | Partially Supported | Design claim only. |
| C096 | 812-813 | CNI changes are minimal. | Needs Qualification | Scope estimate, not verifiable fact. |
| C097 | 817-823 | CNI sequence (allocate, veth, gateway, MTU, CLAT IPv4). | Partially Supported | Plausible; no implementation evidence. |
| C098 | 822 | Always-encrypt MTU = physical MTU - 80. | Needs Qualification | 80-byte overhead valid for IPv6 outer; not universal. |
| C099 | 825-828 | Host carries rack and pod addresses on distinct interfaces. | Supported | Standard host-router pattern. |
| C100 | 833-835 | Same-site can use full physical MTU in `cross-site`/`never`. | Needs Qualification | Works only if traffic class/path segmentation is consistent. |
| C101 | 840 | `cross-site` MTU split (1500 same-site / 1420 cross-site). | Needs Qualification | Requires robust PMTUD behavior and ICMP delivery. |
| C102 | 843-846 | PMTUD with ICMPv6 PTB handles cross-site MTU delta. | Partially Supported | R8201 supports mechanism; operational caveats remain. |
| C103 | 850-855 | Host installs /128 route per pod. | Supported | Standard per-veth route pattern. |
| C104 | 857-859 | Fabric advertises /64 only; /128 routes stay local. | Supported | Common route summarization practice. |
| C105 | 874 | Same-node path has no WG/eBPF translation; pure kernel forwarding. | Needs Qualification | Policy eBPF may still apply depending hooking strategy. |
| C106 | 875 | Same-node latency 2-5us and throughput 40+ Gbps. | Unsupported | No benchmark context/hardware specification. |
| C107 | 885-894 | Same-rack, different-node path is single L2 hop, no WG, line rate. | Needs Qualification | Topology and NIC/switch dependent. |
| C108 | 905-914 | Different-rack same-site path is standard L3 fabric, no WG, line rate. | Needs Qualification | “Line rate” unsourced absolute. |
| C109 | 923-937 | Cross-site flow uses worker eBPF redirect to worker wg0 then gateway transit. | Unsupported | Inconsistent with C093 gateway-only worker claim. |
| C110 | 950-953 | IPv6 internet flow has no SNAT/NAT64/WG; pod source preserved. | Needs Qualification | Requires global routing and perimeter allowance. |
| C111 | 963-975 | IPv4 internet flow is CLAT->NAT64->MASQUERADE. | Supported | R6877 + R6146 pattern (for architecture intent). |
| C112 | 987-997 | Internet ingress is BGP-routed to host then XDP-allowed then unsNAT return. | Partially Supported | Plausible, but policy implementation unverified. |
| C113 | 1006-1013 | Bare metal + fabric BGP + cross-site encryption is recommended for prod. | Needs Qualification | Recommendation statement. |
| C114 | 1012 | Requires /48 per site. | Needs Qualification | Not strictly required; larger/smaller allocations possible. |
| C115 | 1020-1022 | Cloud routing model: AWS prefix delegation, GCP /96, or cloud routes. | Partially Supported | AWS-PFX + GCP-VM, but generalized wording. |
| C116 | 1024 | Cloud MTU 1500 or 8996 in AWS. | Outdated | AWS-MTU says ENI supports up to 9001; pod MTU is stack-dependent. |
| C117 | 1026-1028 | Not all clouds support /64-per-host; AWS /80 ENI and GCP /96 NIC. | Supported | AWS-PFX, GCP-VM/GCP-SUB |
| C118 | 1035-1040 | Single-rack/lab is simplest; pods via L2/single router hop. | Needs Qualification | Usually true; still environment-specific. |
| C119 | 1049 | ULA+WG same-site throughput 3-10 Gbps/core vs native line rate. | Needs Qualification | Performance depends on kernel/NIC/CPU/workload. |
| C120 | 1050 | Cross-site pod-to-pod is WG encrypted in both models. | Partially Supported | Depends on policy mode and topology. |
| C121 | 1051 | ULA pod->IPv6 internet needs SNAT; GUA direct. | Supported | ULA routability semantics. |
| C122 | 1052 | IPv4 internet path is CLAT+NAT64 in both models. | Supported | Consistent with ARCH + Section 7 model. |
| C123 | 1053 | Internet->pod not possible in ULA without proxy. | Needs Qualification | Edge NAT46/SIIT/proxy designs can provide ingress. |
| C124 | 1055 | GUA mode requires routable IPv6 + BGP fabric. | Needs Qualification | BGP can be static/IGP alternatives. |
| C125 | 1056 | GUA security posture is “mandatory explicit firewall”. | Needs Qualification | Strong guidance, not protocol requirement. |
| C126 | 1057-1059 | Native path has 0 MTU/latency/CPU overhead vs WG. | Needs Qualification | Better phrased as “no encryption encapsulation overhead”; not literal zero. |
| C127 | 1065-1070 | ULA should be used on shared infra/no fabric control/no GUA. | Supported | Reasonable decision guidance. |
| C128 | 1071-1077 | GUA should be used on dedicated infra with BGP/perf/direct ingress goals. | Supported | Reasonable decision guidance. |
| C129 | 1078-1081 | Hybrid use (intra-site native + inter-site WG) for migration/compliance. | Supported | Plausible and internally coherent strategy. |

---

**Findings by Severity (with rewrites)**

**Critical**
1. Prefix plan is mathematically inconsistent and uses a non-routable documentation block as “provider allocation.”  
Refs: [ROUTABLE-PREFIX.md:115](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:115), [ROUTABLE-PREFIX.md:116](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:116), [ROUTABLE-PREFIX.md:121](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:121), [ROUTABLE-PREFIX.md:122](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:122).  
Rewrite: use a placeholder production block (`<GUA_SITE>/48`) and fix hextet alignment, e.g. `2001:db8:0a00::/48` with host subnets `2001:db8:0a00:0001::/64` etc. Add note: “`2001:db8::/32` (or `3fff::/20`) examples are documentation-only, not routable production space.”

2. Inbound IPv4 section mislabels/overstates NAT64 capabilities.  
Refs: [ROUTABLE-PREFIX.md:572](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:572), [ROUTABLE-PREFIX.md:578](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:578).  
Rewrite: replace “NAT64 ingress gateway” with “IPv4/IPv6 edge translation (NAT46/SIIT-DC/reverse proxy)”. Avoid asserting generic `64:ff9b::/96` source embedding for inbound clients.

3. Cross-site encryption architecture is internally contradictory.  
Refs: [ROUTABLE-PREFIX.md:369](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:369), [ROUTABLE-PREFIX.md:779](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:779), [ROUTABLE-PREFIX.md:923](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:923).  
Rewrite: split into two explicit modes: `distributed-wg` (worker wg0) and `gateway-transit-wg` (workers no wg0). Keep packet-flow examples consistent with one mode per section.

**High**
1. Security defaults are stated as guaranteed implementation behavior without evidence and conflict with Kubernetes baseline semantics.  
Refs: [ROUTABLE-PREFIX.md:602](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:602), [ROUTABLE-PREFIX.md:623](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:623).  
Rewrite: “When `defaultDenyIngress=true`, Wirescale installs cluster-wide deny; otherwise Kubernetes default is allow if no policy selects pod.”

2. `/64` claims are over-absolute (“SLAAC mandates it; NDP assumes it”).  
Refs: [ROUTABLE-PREFIX.md:47](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:47).  
Rewrite: “SLAAC on standard Ethernet-style links expects 64-bit IID, so /64 is the default operational choice. NDP itself is not /64-exclusive.”

3. “External `::/0` no encryption because TLS/no benefit” is a risky and incorrect blanket claim.  
Ref: [ROUTABLE-PREFIX.md:408](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:408).  
Rewrite: “External encryption policy is workload/risk dependent; TLS may cover payload, but transport-layer encryption can still be required.”

4. Hard performance numbers are uncited and presented as universal.  
Refs: [ROUTABLE-PREFIX.md:666](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:666), [ROUTABLE-PREFIX.md:875](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:875), [ROUTABLE-PREFIX.md:1049](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:1049).  
Rewrite: add benchmark context (`CPU/NIC/kernel/frame size`), or convert to relative statements.

**Medium**
1. Cloud MTU value (`8996`) is stale/ambiguous.  
Ref: [ROUTABLE-PREFIX.md:1024](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:1024).  
Rewrite: “AWS ENI MTU supports up to 9001; effective pod MTU depends on encapsulation/underlay (compute dynamically).”

2. Internet reachability wording is too absolute for GUA pods.  
Refs: [ROUTABLE-PREFIX.md:34](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:34), [ROUTABLE-PREFIX.md:596](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:596).  
Rewrite: add dependencies on route advertisement, border ACLs, and firewall policy.

3. “0 overhead / 0 CPU” language should be softened.  
Refs: [ROUTABLE-PREFIX.md:955](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:955), [ROUTABLE-PREFIX.md:1059](/Users/bill/src/wirescale/ROUTABLE-PREFIX.md:1059).  
Rewrite: “no WireGuard encapsulation/crypto overhead in native path.”

---

**Cross-Claim Consistency Issues**

1. Worker WireGuard role conflict: encryption decision/packet flow assumes worker `wg0`, but multi-site section says workers do not need WireGuard (`C061/C109` vs `C093`).
2. Connectivity default conflict: early sections imply native pod reachability by default, while security section says pod-to-pod is blocked until explicit allow (`C010` vs `C081`).
3. Address hierarchy conflict: declared site/rack/pod supernets do not contain many shown example prefixes (`C029-C032`, `C040`).
4. Base architecture comparison mismatch: table says internet via NAT64 in base, but ARCH text separates IPv6 native behavior from NAT64 IPv4 translation (`C019`).
5. Inbound IPv4 model conflict with security policy source matching on `64:ff9b::/96`; this assumes a specific translator behavior not established elsewhere (`C077/C078` vs `C086`).

---

**Top-Priority Remediation Plan (ordered)**

1. Fix all IPv6 example prefixes and hierarchy math first (site/rack/pod containment), and explicitly mark doc-only prefixes as non-production.
2. Choose one cross-site encryption architecture (`distributed-wg` vs `gateway-transit-wg`) and rewrite Sections 5/9/11 to match it end-to-end.
3. Replace inbound IPv4 “NAT64 ingress” with a correct edge pattern (NAT46/SIIT-DC/reverse proxy) and adjust policy examples accordingly.
4. Rewrite security defaults to separate “protocol facts” from “Wirescale policy defaults,” with explicit feature flags/conditions.
5. Remove or qualify universal performance numbers; add benchmark appendix if exact numbers are required.
6. Normalize wording from absolutes (“always,” “zero,” “mandatory”) to conditional statements where deployment-dependent.
7. Refresh cloud section with current AWS/GCP limits and dynamic MTU guidance.
8. Add citation footnotes inline for every external-standard assertion.

---

**Sources**

- R4291: https://datatracker.ietf.org/doc/html/rfc4291  
- R4862: https://datatracker.ietf.org/doc/html/rfc4862  
- R7421: https://datatracker.ietf.org/doc/html/rfc7421  
- R6052: https://datatracker.ietf.org/doc/html/rfc6052  
- R6146: https://datatracker.ietf.org/doc/html/rfc6146  
- R6147: https://datatracker.ietf.org/doc/html/rfc6147  
- R6877: https://datatracker.ietf.org/doc/html/rfc6877  
- R6598: https://datatracker.ietf.org/doc/html/rfc6598  
- R8201: https://datatracker.ietf.org/doc/html/rfc8201  
- RFC9637 (documentation prefix): https://datatracker.ietf.org/doc/rfc9637/  
- KERN: https://docs.kernel.org/networking/ip-sysctl.html  
- IANA-SP: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml  
- IANA-UNI: https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml  
- AWS-PFX: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html  
- AWS-MTU: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html  
- GCP-SUB: https://cloud.google.com/vpc/docs/subnets  
- GCP-VM: https://cloud.google.com/compute/docs/ip-addresses/configure-ipv6-address  
- K8S-NP: https://v1-33.docs.kubernetes.io/docs/concepts/services-networking/network-policies/  
- CIL-WG: https://docs.cilium.io/en/stable/security/network/encryption-wireguard/  
- CIL-RT: https://docs.cilium.io/en/stable/network/concepts/routing/  
- CAL-WG: https://docs.tigera.io/calico/latest/network-policy/encrypt-cluster-pod-traffic  
- WG-MAN: https://man7.org/linux/man-pages/man8/wg.8.html  
- WGQ-MAN: https://man7.org/linux/man-pages/man8/wg-quick.8.html
