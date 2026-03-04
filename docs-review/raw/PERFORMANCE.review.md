**Scope Coverage Summary**
Reviewed the full [`PERFORMANCE.md`](/Users/bill/src/wirescale/PERFORMANCE.md) (lines 1-667), with no skipped sections:

| Section | Lines | Claims inventoried |
|---|---:|---:|
| 1. Performance Budget | 21-50 | 5 |
| 2. WireGuard at Line Rate | 54-158 | 22 |
| 3. eBPF NAT64/CLAT Fast Path | 162-273 | 21 |
| 4. Packet Pipeline Architecture | 277-375 | 11 |
| 5. Kernel Tuning | 379-454 | 11 |
| 6. Hardware Acceleration | 458-507 | 6 |
| 7. Benchmarks and Targets | 510-555 | 7 |
| 8. MTU Strategy | 559-615 | 9 |
| Appendix | 619-667 | 4 |
| **Total** |  | **96 atomic claims** |

**Evidence Key (authoritative sources)**
- **S1** https://www.wireguard.com/install/
- **S2** https://www.wireguard.com/protocol/
- **S3** https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash
- **S4** https://www.rfc-editor.org/rfc/rfc6052#section-2.1
- **S5** https://www.rfc-editor.org/rfc/rfc6146
- **S6** https://www.rfc-editor.org/rfc/rfc6877
- **S7** https://docs.kernel.org/networking/napi.html
- **S8** https://docs.kernel.org/networking/af_xdp.html
- **S9** https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
- **S10** https://docs.ebpf.io/linux/helper-function/bpf_skb_change_proto/
- **S11** https://docs.kernel.org/networking/scaling.html
- **S12** https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html
- **S13** https://docs.kernel.org/networking/ip-sysctl.html
- **S14** https://man7.org/linux/man-pages/man8/ip-link.8.html
- **S15** https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation
- **S16** https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers
- **S17** https://www.spinics.net/lists/netdev/msg1036260.html
- **S18** https://www.spinics.net/lists/netdev/msg1118848.html
- **S19** Repo evidence: this repo is docs-only (`PERFORMANCE.md`, `ARCHITECTURE.md`, `ROUTABLE-PREFIX.md`, `SECURITY.md`), no implementation artifacts to verify “agent does X”.
- **S20** https://man7.org/linux/man-pages/man8/ethtool.8.html
- **S21** https://github.com/WireGuard/wireguard-go
- **S22** https://netdevconf.info/0x18/sessions/wireguard-inline-optimizations-for-networking-stack-bypassing.html
- **S23** https://lore.kernel.org/netdev/20190809021355.17431-1-Jason@zx2c4.com/
- **S24** https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/tuning-the-network-performance_monitoring-and-managing-system-status-and-performance

## Claim Inventory

| claim_id | lines | claim | status | evidence |
|---|---:|---|---|---|
| C001 | 23-25 | Up to 3 processing stages per packet. | Supported | Internal architecture description; consistent with C050/C057. |
| C002 | 29-34 | 1500B packet-rate/time-budget table values. | Needs Qualification | Numbers match on-wire framing assumptions, not pure 1500B payload math. |
| C003 | 40-44 | Per-stage nanosecond costs and throughput/core table. | Unsupported | No benchmark method/citation. |
| C004 | 46 | GRO/GSO amortization is key to line rate. | Partially Supported | Concept supported broadly (S23, S17), but absolute phrasing. |
| C005 | 47-50 | 812k pps -> ~13k superpackets (~50 pkt each). | Needs Qualification | Internal arithmetic mismatch (13k implies ~62:1, not ~50:1). |
| C006 | 58-59 | Wirescale uses in-kernel WG, not wireguard-go. | Unsupported | No implementation evidence in repo (S19). |
| C007 | 58 | In-kernel WG is Linux >=5.6. | Supported | S1. |
| C008 | 63 | 0 syscalls/packet kernel WG vs 2+ wireguard-go. | Unsupported | No primary benchmark/citation. |
| C009 | 64 | 0 extra copies kernel vs 2+ userspace. | Needs Qualification | Directionally true for userspace tunnel overhead (S21), but oversimplified. |
| C010 | 65 | wireguard-go needs Linux >=6.2 TUN GSO/GRO. | Partially Supported | Community notes exist; no strong primary citation in doc set. |
| C011 | 66 | Kernel WG multi-core decrypt uses padata. | Unsupported | No primary source found for current WG using padata. |
| C012 | 67 | Max single-peer throughput table (~10 vs ~7 Gbps). | Unsupported | No cited benchmark methodology. |
| C013 | 74-77 | Linux 5.19 was initial WG GRO offload. | Outdated | Earlier WG upstream work already referenced GRO/GSO (S23). |
| C014 | 79-80 | Linux 6.2 added TUN UDP GSO/GRO. | Partially Supported | Plausible, but needs stronger primary release citation. |
| C015 | 82-85 | Linux 6.13 WG Big TCP GSO 512KB, +15%. | Partially Supported | Patch evidence supports 512KB/+15% (S17), version mapping should be qualified. |
| C016 | 88-96 | CPU-time math examples with/without GRO/Big TCP. | Partially Supported | Arithmetic internally coherent; assumptions not validated. |
| C017 | 98-99 | Encryption overhead becomes near-zero; bottleneck shifts to memory/PCIe. | Needs Qualification | Plausible at high batching, but too absolute. |
| C018 | 103-105 | Vanilla WG has single NAPI per interface, saturates ~180kpps. | Outdated | Newer WG NAPI threading/per-peer work changed behavior (S18). |
| C019 | 106-113 | `threaded` sysfs enables threaded NAPI and kthread scheduling. | Supported | S7. |
| C020 | 116-118 | 13 -> 48 Gbps (3.7x) threaded NAPI impact. | Unsupported | No reproducible benchmark details. |
| C021 | 119 | agent auto-enables threaded NAPI at boot. | Unsupported | No implementation evidence (S19). |
| C022 | 123-126 | Per-peer workers pinned/distributed across cores. | Needs Qualification | Kernel scheduling behavior is nuanced; “pinned” is too strong. |
| C023 | 128-131 | 16 peers/32 cores -> up to 48 Gbps and padata RX fanout. | Unsupported | No verified benchmark + padata issue (C011). |
| C024 | 133-136 | Single-peer limit 3-10 Gbps; WireGuard Inline is future work. | Partially Supported | Research exists (S22); numeric limits uncited. |
| C025 | 140-142 | If conntrack loaded, every packet hits conntrack hash. | Needs Qualification | Depends on hooks/rules; overbroad (S15). |
| C026 | 144-154 | agent programs shown nft `notrack` rules. | Unsupported | No implementation evidence (S19). |
| C027 | 157-158 | `notrack` saves ~100ns/packet. | Unsupported | No benchmark citation. |
| C028 | 166-168 | XDP fastest hook, but cannot be used for NAT64 on wg0. | Needs Qualification | “Cannot” is too absolute; design tradeoff statement should be scoped (S8). |
| C029 | 170-171 | XDP ethhdr parse on wg0 will fault. | Unsupported | Depends on program parser; not universally true. |
| C030 | 172-173 | wg0 XDP only generic mode and slower than TC. | Needs Qualification | Generic-mode part plausible (S8), perf comparison needs data. |
| C031 | 174-177 | `bpf_xdp_adjust_head` headroom limits make TC proto-change correct path. | Needs Qualification | Helper behavior is complex; statement is too categorical. |
| C032 | 179-181 | TC on wg0 is “correct and optimal”, one call/redirect/no extra traversal. | Needs Qualification | Absolute “optimal” unsupported. |
| C033 | 185-188 | XDP used on NIC for drop/RSS steering/prefilter. | Unsupported | No code evidence (S19). |
| C034 | 190-191 | XDP protects at up to 26 Mpps/core. | Unsupported | No benchmark citation. |
| C035 | 195-197 | NAT64 TC program is on wg0 ingress. | Unsupported | Conflicts with Section 4 nat64-interface path (C049). |
| C036 | 208-209 | IPv6->IPv4 proto swap shrinks L3 header 40->20 bytes. | Supported | RFC header sizes + helper semantics (S9, S25). |
| C037 | 211-214 | Source mapping `169.254.64.X` statelessly derived from pod IPv6. | Unsupported | No implementation evidence. |
| C038 | 216-217 | L3/L4 checksum helper fixups are used. | Supported | Helpers documented (S9). |
| C039 | 219 | Redirect out physical NIC via `bpf_redirect`. | Supported | Helper behavior documented (S9). |
| C040 | 222-223 | nft MASQUERADE rewrites source to node IPv4. | Partially Supported | Stateful NAT behavior aligns with NAT64/NAT (S5). |
| C041 | 228-231 | Path is O(1), one map lookup, fixed rewrite, no conntrack in eBPF. | Needs Qualification | Hash lookup average-case only; runtime depends on load/map behavior. |
| C042 | 235-237 | CLAT on veth avoids extra host routing hop. | Unsupported | No implementation/path proof. |
| C043 | 243-250 | Deterministic CLAT mapping and external mapping to `64:ff9b::/96`. | Unsupported | No code evidence; standards allow multiple designs (S6). |
| C044 | 253-254 | Reverse path runs on same-veth ingress TC. | Unsupported | No code evidence. |
| C045 | 256-260 | Intra-mesh IPv4 bypasses NAT64 entirely; stateless/symmetric. | Partially Supported | Architecturally plausible, but not validated in implementation. |
| C046 | 264-266 | `bpf_skb_change_proto` marks skb `SKB_GSO_DODGY`. | Supported | S10. |
| C047 | 268-270 | NAT64 translates superpacket header once before re-segmentation. | Partially Supported | Directionally consistent with GSO workflow (S10), needs proof for this path. |
| C048 | 272-273 | Translation cost amortized across superpacket. | Partially Supported | Plausible with batching; no measured evidence. |
| C049 | 282-307 | Pod->external path uses CLAT + nat64 iface TC + MASQUERADE. | Partially Supported | Internally coherent path; conflicts with C035 hookpoint. |
| C050 | 310 | Exactly 2 eBPF programs in pod->external path. | Partially Supported | True if C049 path is authoritative; currently ambiguous. |
| C051 | 311 | Exactly 1 kernel stack traversal. | Unsupported | No kernel-trace evidence. |
| C052 | 312 | 0 extra copies end-to-end. | Needs Qualification | “0 copies” claim is too absolute for full path. |
| C053 | 317-338 | Pod->pod IPv6 path includes hardware GRO and padata decrypt fanout. | Needs Qualification | GRO/hardware wording + padata claim need correction (C011). |
| C054 | 340 | eBPF programs in pure IPv6 pod->pod path: 0. | Supported | Internal path logic. |
| C055 | 341 | This is the fastest possible path. | Needs Qualification | Absolute, workload/hardware dependent. |
| C056 | 346-369 | Pod->pod IPv4 via CLAT mapping path exactly as diagrammed. | Unsupported | No implementation proof. |
| C057 | 371 | eBPF programs in pod->pod IPv4 path: 2. | Partially Supported | Depends on actual attach points. |
| C058 | 372 | NAT64 engine not involved intra-mesh IPv4. | Supported | Consistent with described CLAT-only intra-mesh model. |
| C059 | 373-375 | Tunnel always carries native IPv6; mesh never sees IPv4. | Needs Qualification | True only in this mode/design; should be scoped. |
| C060 | 381 | agent applies listed sysctls automatically on startup. | Unsupported | No implementation evidence (S19). |
| C061 | 386-392 | UDP buffer values are critical above 1 Gbps. | Needs Qualification | Tuning is workload/NIC dependent; “critical” too strong (S12). |
| C062 | 393-395 | TCP buffer values specifically for GRO superpackets. | Needs Qualification | Needs performance evidence and scope. |
| C063 | 401-405 | netdev budget/backlog values and defaults shown. | Needs Qualification | Defaults vary by kernel/distribution (S24). |
| C064 | 410-413 | `fq` + BBR reduces bufferbloat through WG tunnels. | Needs Qualification | Generally plausible, but environment-dependent. |
| C065 | 418-420 | IPv4/IPv6 forwarding must be enabled. | Supported | S13. |
| C066 | 426-427 | BPF JIT is mandatory for performance. | Needs Qualification | Strongly advisable, “mandatory” is too absolute (S12). |
| C067 | 432-433 | agent configures RPS across all cores. | Unsupported | No implementation evidence (S19). |
| C068 | 436-445 | RPS/RFS script values (`ffffffff`, 32768, 4096). | Partially Supported | Kernel docs discuss RPS/RFS and 32768 example (S11); full values should be host-specific. |
| C069 | 448-449 | RSS hash can include inner WG flow with shown approach. | Unsupported | `ethtool -N ... udp4/udp6 sdfn` hashes outer tuple, not “inner WG flow” generally (S20). |
| C070 | 452-453 | `ethtool -N ... rx-flow-hash udp4/udp6 sdfn` is valid config. | Supported | S20. |
| C071 | 464-469 | Tier-1 throughput/availability matrix. | Needs Qualification | Mixed factual + uncited performance numbers. |
| C072 | 475-477 | Tier-2 QAT/VPP/AF_XDP performance figures. | Unsupported | No primary benchmark references provided. |
| C073 | 483-487 | Tier-3 “future/research” status statements. | Partially Supported | WireGuard Inline is research (S22). |
| C074 | 491-493 | 10G recommendations and single-core sufficiency. | Needs Qualification | Hardware/workload dependent. |
| C075 | 496-500 | 25G recommendations and 2-4 crypto cores. | Needs Qualification | Needs measured basis. |
| C076 | 502-507 | 40-100G recommendations; threaded NAPI mandatory. | Needs Qualification | “Mandatory” too strong; kernel behavior evolving (S18). |
| C077 | 516-517 | Unencrypted baseline iperf ceilings table. | Unsupported | No test conditions/methodology. |
| C078 | 523-525 | Encrypted pod->pod target table. | Unsupported | No benchmark traceability. |
| C079 | 531-532 | IPv4 via CLAT target table. | Unsupported | No benchmark traceability. |
| C080 | 538-539 | IPv4 via NAT64 target table. | Unsupported | No benchmark traceability. |
| C081 | 543-545 | Single-peer TX encryption worker pinned to one core. | Needs Qualification | WG scheduling details need precise kernel-version scope. |
| C082 | 549-553 | CPU-specific single-peer max throughput table. | Unsupported | No source data. |
| C083 | 554-555 | Limitation is architectural; Netdev 0x18 not upstreamed. | Partially Supported | Research exists and is not upstreamed (S22). |
| C084 | 561-563 | MTU misconfig is #1 performance cause; causes frag/black holes. | Needs Qualification | Frag/PMTU risk true; “#1 cause” uncited. |
| C085 | 568-575 | WG-over-IPv6 overhead is 72 bytes with 4-byte counter. | Unsupported | Protocol defines 8-byte counter; overhead is 80 bytes (S2). |
| C086 | 577 | Inner MTU = Physical MTU - 72. | Unsupported | For IPv6 underlay, wg-quick logic and packet format indicate -80 (S2, S3). |
| C087 | 584-585 | MTU/MSS table based on 1428/8928 inner MTU. | Unsupported | Derived from incorrect overhead assumption (C085/C086). |
| C088 | 587-588 | Pod MTU is 8 bytes below wg MTU for ext headers/CLAT overhead. | Needs Qualification | Possible policy choice, but currently tied to wrong base MTU math. |
| C089 | 592-593 | agent programs MSS clamping. | Unsupported | No implementation evidence (S19). |
| C090 | 595-601 | nft MSS clamp rule syntax/effect (`set rt mtu`). | Supported | S16. |
| C091 | 606-613 | Jumbo gives 15-25% throughput improvement. | Unsupported | No benchmark data. |
| C092 | 614-615 | agent auto-detects physical MTU and configures wg0/pods. | Unsupported | No implementation evidence (S19). |
| C093 | 625-628 | `wg show`/`wg show dump` provide peer/transfer/handshake stats. | Supported | WG tooling behavior (S1/S2 ecosystem). |
| C094 | 635-640 | `bpftool`/`tc -s` commands provide eBPF/TC stats. | Supported | Standard tool behavior. |
| C095 | 647-653 | perf/softirq/mpstat commands help find CPU bottlenecks. | Supported | Standard observability practice. |
| C096 | 659-666 | iperf command patterns can validate the 3 throughput scenarios. | Supported | Valid test commands. |

## Findings by Severity (with line refs and rewrites)

1. **Critical: Incorrect WireGuard-over-IPv6 overhead and MTU derivation**
- Lines: [PERFORMANCE.md:568](/Users/bill/src/wirescale/PERFORMANCE.md:568), [PERFORMANCE.md:577](/Users/bill/src/wirescale/PERFORMANCE.md:577), [PERFORMANCE.md:584](/Users/bill/src/wirescale/PERFORMANCE.md:584)
- Issue: Uses 72-byte overhead and 4-byte counter. WireGuard data packet has 8-byte counter; IPv6+UDP+WG data+tag totals 80 bytes (S2). `wg-quick` logic also subtracts 80 for IPv6 underlay (S3).
- Rewrite:
```md
WireGuard outer overhead (IPv6 underlay):
  IPv6 header:        40 bytes
  UDP header:          8 bytes
  WireGuard data hdr: 16 bytes (type/reserved + receiver index + counter)
  Poly1305 tag:       16 bytes
  -----------------------------
  Total overhead:     80 bytes

Inner MTU = Physical MTU - 80
```
And update MTU table accordingly.

2. **High: NAT64 hookpoint contradiction (wg0 ingress vs nat64 interface)**
- Lines: [PERFORMANCE.md:195](/Users/bill/src/wirescale/PERFORMANCE.md:195), [PERFORMANCE.md:293](/Users/bill/src/wirescale/PERFORMANCE.md:293), [PERFORMANCE.md:297](/Users/bill/src/wirescale/PERFORMANCE.md:297)
- Issue: Section 3 says NAT64 TC attaches to `wg0` ingress; Section 4 says route to `nat64` interface and run NAT64 TC there.
- Rewrite:
```md
Choose one canonical attach point and apply consistently:
- Option A: TC ingress on wg0 (post-decrypt), no nat64 dummy hop.
- Option B: Route 64:ff9b::/96 to nat64 interface and attach TC there.
```
Then align diagrams, counters, and command examples to that single model.

3. **High: Outdated/incorrect WireGuard NAPI architecture claim**
- Lines: [PERFORMANCE.md:103](/Users/bill/src/wirescale/PERFORMANCE.md:103), [PERFORMANCE.md:104](/Users/bill/src/wirescale/PERFORMANCE.md:104)
- Issue: “Single NAPI instance per interface” is stale vs newer WireGuard NAPI/threading work (S18).
- Rewrite:
```md
On older kernels, WireGuard RX can bottleneck in a single poll context.
On newer kernels, WireGuard NAPI/threading behavior has improved; verify per-kernel behavior before applying tuning assumptions.
```

4. **High: Performance-number heavy sections lack reproducible evidence**
- Lines: [PERFORMANCE.md:40](/Users/bill/src/wirescale/PERFORMANCE.md:40), [PERFORMANCE.md:116](/Users/bill/src/wirescale/PERFORMANCE.md:116), [PERFORMANCE.md:464](/Users/bill/src/wirescale/PERFORMANCE.md:464), [PERFORMANCE.md:516](/Users/bill/src/wirescale/PERFORMANCE.md:516)
- Issue: ns/packet, Gbps/core, Mpps/core, targets all presented as facts without methodology.
- Rewrite:
```md
Replace absolute figures with:
- "Measured in lab X on kernel Y.Z, NIC A, CPU B"
- link to benchmark scripts/raw runs
- confidence/variance and packet-size distribution
```

5. **High: Absolute XDP prohibition on wg0 is overstated**
- Lines: [PERFORMANCE.md:167](/Users/bill/src/wirescale/PERFORMANCE.md:167), [PERFORMANCE.md:179](/Users/bill/src/wirescale/PERFORMANCE.md:179)
- Issue: “Cannot be used” and “correct and optimal” are too categorical.
- Rewrite:
```md
For this design, TC eBPF is preferred for translation on tunnel/virtual paths.
XDP is used on physical NIC ingress for early filtering and steering.
```

6. **Medium: Packet-rate table label mismatch**
- Lines: [PERFORMANCE.md:29](/Users/bill/src/wirescale/PERFORMANCE.md:29), [PERFORMANCE.md:31](/Users/bill/src/wirescale/PERFORMANCE.md:31)
- Issue: Label says “1500B”, but numbers appear to assume on-wire framing overhead.
- Rewrite:
```md
| Link Speed | Packet Rate (1500B payload, L2 on-wire) | Time Budget |
```
Or recompute for pure L3 payload.

7. **Medium: “Inner WireGuard flow” RSS claim is misleading**
- Lines: [PERFORMANCE.md:448](/Users/bill/src/wirescale/PERFORMANCE.md:448), [PERFORMANCE.md:452](/Users/bill/src/wirescale/PERFORMANCE.md:452)
- Issue: Provided `ethtool -N ... udp4/udp6 sdfn` config targets UDP tuple hashing, not generic inner-flow hashing.
- Rewrite:
```md
Configure RSS for outer UDP 4-tuple by default.
If NIC supports tunnel inner-hash features, document vendor-specific commands separately.
```

8. **Medium: MTU section conflicts with project docs**
- Lines: [PERFORMANCE.md:568](/Users/bill/src/wirescale/PERFORMANCE.md:568) vs [`ARCHITECTURE.md:367`](/Users/bill/src/wirescale/ARCHITECTURE.md:367)
- Issue: `PERFORMANCE.md` says 72-byte overhead while `ARCHITECTURE.md` acknowledges 80 bytes for IPv6 outer.
- Rewrite: unify all docs on one MTU model (`-80` for IPv6 underlay).

9. **Medium: “agent does X automatically” repeated without implementation evidence**
- Lines: [PERFORMANCE.md:119](/Users/bill/src/wirescale/PERFORMANCE.md:119), [PERFORMANCE.md:381](/Users/bill/src/wirescale/PERFORMANCE.md:381), [PERFORMANCE.md:592](/Users/bill/src/wirescale/PERFORMANCE.md:592), [PERFORMANCE.md:614](/Users/bill/src/wirescale/PERFORMANCE.md:614)
- Issue: Repo has no code to substantiate these automation claims (S19).
- Rewrite:
```md
If implementation exists elsewhere, link to exact module/release.
Otherwise mark as "planned behavior" or remove.
```

10. **Medium: Conntrack and BPF statements are too absolute**
- Lines: [PERFORMANCE.md:140](/Users/bill/src/wirescale/PERFORMANCE.md:140), [PERFORMANCE.md:426](/Users/bill/src/wirescale/PERFORMANCE.md:426)
- Issue: “every packet traverses conntrack” and “BPF JIT mandatory” should be scoped.
- Rewrite:
```md
When packets hit conntrack hooks, lookup cost may become significant; raw/notrack can reduce that path for selected flows.
Enable BPF JIT for production datapaths; interpret-only mode is generally unsuitable at high PPS.
```

## Cross-Claim Consistency Issues

1. **NAT64 attach-point conflict**
- C035 (`wg0` ingress) conflicts with C049 (nat64 interface).

2. **MTU model conflict**
- C085/C086/C087 (72-byte model) conflicts with protocol math and `ARCHITECTURE.md`’s 80-byte IPv6 model.

3. **NAPI model conflict**
- C018 (“single NAPI per interface”) conflicts with newer kernel direction and your own scaling narrative (C022/C023).

4. **Packet-coalescing arithmetic inconsistency**
- C005 ratio/superpacket count does not match its own numbers.

5. **RSS/RPS guidance tension**
- C067/C068 “RPS all cores” and C069 “inner-flow RSS” are presented without deciding a primary steering strategy per NIC/kernel capability.

## Top-Priority Remediation Plan (ordered)

1. **Fix MTU/overhead section first**
- Correct WG packet overhead to 80 bytes on IPv6 underlay, recompute all derived MTU/MSS values, and align with `ARCHITECTURE.md`.

2. **Resolve NAT64 path architecture**
- Choose canonical hookpoint (`wg0` vs `nat64` interface), then update all diagrams/text/commands to match.

3. **Version-gate kernel behavior claims**
- Replace hard version assertions with “tested on kernel X.Y” and include caveats for newer kernels (NAPI/Big TCP behavior).

4. **Demote uncited numbers to targets/hypotheses**
- For ns/Gbps/Mpps figures, either add reproducible benchmark references or mark as “lab target/estimate”.

5. **Replace absolute language with scoped statements**
- Especially XDP “cannot”, BPF JIT “mandatory”, conntrack “every packet”, and “fastest possible”.

6. **Back automation claims with code links**
- If agent behavior exists in another repo, link it; otherwise rewrite as roadmap statements.
