**Scope Coverage Summary**
Reviewed full [`SECURITY.md`](/Users/bill/src/wirescale/SECURITY.md) end-to-end, including all sections and embedded claim-bearing artifacts:

1. `1. Security Philosophy` (26-71)  
2. `2. Identity Model` (75-147)  
3. `3. Cryptographic Trust Chain` (150-192)  
4. `4. Dynamic Access Control Architecture` (196-283)  
5. `5. Policy Language and CRDs` (286-526)  
6. `6. Enforcement Engine` (529-659)  
7. `7. Node Admission and Revocation` (663-744)  
8. `8. Mutual Authentication` (748-808)  
9. `9. Key Lifecycle Management` (812-874)  
10. `10. Audit and Observability` (877-967)  
11. `11. Threat Model and Mitigations` (971-1019)  
12. `12. Implementation Details` (1023-1124)

Validation basis:
- Internal consistency across this file (plus phase/roadmap state inside section 12).
- External correctness against WireGuard, Kubernetes, RFCs, and Linux kernel docs.

External sources used:
- WireGuard protocol: https://www.wireguard.com/protocol/
- WireGuard overview/cryptokey routing: https://www.wireguard.com/
- WireGuard userspace interface semantics: https://www.wireguard.com/xplatform/
- WireGuard kernel timing constants: https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/messages.h
- RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
- RFC 7748 (Curve25519/X25519): https://www.rfc-editor.org/rfc/rfc7748
- RFC 6052 (64:ff9b::/96): https://www.rfc-editor.org/rfc/rfc6052
- RFC 6146 (Stateful NAT64): https://www.rfc-editor.org/rfc/rfc6146
- RFC 6877 (464XLAT/CLAT): https://www.rfc-editor.org/rfc/rfc6877
- RFC 7915 (SIIT): https://www.rfc-editor.org/rfc/rfc7915
- Kubernetes NetworkPolicy: https://v1-32.docs.kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Kubernetes admission controllers: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- Kubernetes cluster networking/CNI roles: https://kubernetes.io/docs/concepts/cluster-administration/networking/
- Kubernetes API type `NetworkPolicyPeer`: https://pkg.go.dev/k8s.io/api/networking/v1
- Linux BPF ring buffer: https://www.kernel.org/doc/html/next/bpf/ringbuf.html
- Linux BPF hash maps (atomic replacement semantics): https://docs.kernel.org/bpf/map_hash.html
- Linux BPF LPM trie: https://docs.kernel.org/bpf/map_lpm_trie.html

**Claim Inventory**

| claim_id | lines | claim | status | evidence |
|---|---:|---|---|---|
| C001 | 33-35 | All inter-node packets are encrypted by WireGuard (ChaCha20-Poly1305). | Partially Supported | WireGuard primitives are correct; implementation pending per 1031-1061. |
| C002 | 36-39 | Pod identity is cryptographic (SA/ns/labels bound to node WG key). | Unsupported | No implementation artifacts; roadmap unchecked 1031-1061. |
| C003 | 40-41 | Policy posture is deny-by-default with full isolation. | Outdated | Asserted as current state, but enforcement work unchecked 1031-1036. |
| C004 | 42-43 | Enforcement is distributed per-node via eBPF only. | Outdated | eBPF enforcement listed as pending 1031-1036. |
| C005 | 44-47 | API/control-plane compromise cannot decrypt dataplane traffic. | Needs Qualification | True only if keys truly never leave node memory and hosts not compromised; implementation not present. |
| C006 | 52-55 | Cryptokey routing allows known peers only; unknown sources dropped. | Supported | WireGuard docs explicitly describe allowed IP checks and drops. |
| C007 | 57-60 | L3/L4 filtering at pod veth is active. | Outdated | TC eBPF program is planned, unchecked 1032. |
| C008 | 67-70 | Audit layer provides non-repudiation. | Needs Qualification | Logging alone is not non-repudiation unless signed/immutable; no mechanism specified. |
| C009 | 79-83 | Identity tuple is `(namespace, serviceAccount, labels, node)`. | Unsupported | Project-defined model only; no schema/controller implementation shown. |
| C010 | 86-90 | Namespace/SA/labels/node mapping semantics are active. | Unsupported | No runtime artifacts in repo; only design text. |
| C011 | 93-113 | Identity resolution chain (WG peer -> IP -> identity cache -> eBPF) is implemented. | Unsupported | Depends on multiple pending components 1031-1036. |
| C012 | 116-118 | Pod identities propagate to all nodes within milliseconds. | Unsupported | No benchmarks or implementation. |
| C013 | 125 | Agent sees pods via kubelet watch. | Needs Qualification | Typical identity controllers watch API server; wording is imprecise. |
| C014 | 127-130 | Controller distributes per-node policy via ConfigMaps and agents update BPF maps. | Unsupported | Planned only (1034-1036). |
| C015 | 132 | Pod creation to enforcement latency is `<2s`. | Unsupported | No measurement evidence. |
| C016 | 140-141 | IP-based policies break under pod churn/rolling deploys. | Supported | Consistent with Kubernetes pod-IP ephemerality. |
| C017 | 142 | CLAT adds a second IPv4 address per pod. | Partially Supported | CLAT model is valid (RFC6877); implementation absent. |
| C018 | 143 | NAT64 makes external IPv4 appear as IPv6. | Supported | RFC6052/RFC6146 semantics. |
| C019 | 145-146 | Real-time reverse IP->identity map exists in enforcement engine. | Unsupported | Map/enforcer implementation pending 1031-1036. |
| C020 | 155-157 | Node keypair is boot-generated, memory-only, never persisted. | Unsupported | No agent implementation present. |
| C021 | 159-162 | RBAC ensures only authenticated agents can create/update node CRDs. | Partially Supported | RBAC can gate identity, but current YAML is overbroad (1073-1075). |
| C022 | 162 | Agents can only write their own node CRD. | Unsupported | Contradicted by RBAC snippet: create/update on all `wirescalenodes` (1073-1075); RBAC doc says create cannot be resourceName-scoped. |
| C023 | 163-164 | Controller validates and rejects suspicious key updates by source IP. | Unsupported | No webhook/controller logic implemented. |
| C024 | 171-174 | Identity chain scheduler->kubelet->CNI->agent binding is active. | Partially Supported | Role split is conceptually valid (K8s networking doc), but feature pending. |
| C025 | 177 | Only kubelet can create pods with node CIDR IPs. | Unsupported | Pod IP allocation is CNI/runtime function, not solely kubelet. |
| C026 | 178-179 | WireGuard guarantees packets from node CIDR come from node. | Needs Qualification | True only with strict non-overlapping AllowedIPs and peer config correctness. |
| C027 | 185-192 | API server is policy source of truth and chain to packet decisions is active. | Partially Supported | Valid architecture concept; unimplemented path. |
| C028 | 200-203 | Dynamic recomputation in real-time is operational. | Unsupported | Reconciler/compiler pending 1035. |
| C029 | 213-224 | Controller recompiles all policies on any watched object change. | Unsupported | Design only. |
| C030 | 234-240 | Agents atomically apply updates and immediately enforce new rules. | Unsupported | Agent map updater pending 1034/1036. |
| C031 | 254-255 | ConfigMaps provide version history for policy diff/audit. | Needs Qualification | ConfigMaps have `resourceVersion`; history/audit requires external mechanism. |
| C032 | 261-267 | Trigger latency targets (`<2s/<5s/<10s`) are achieved. | Unsupported | No test data. |
| C033 | 271-276 | During propagation, old policy remains secure and never leaves pods unprotected. | Unsupported | Kubernetes docs state affected pods may start unprotected before policy handling completes. |
| C034 | 277-279 | Generation counters detect stale agents in practice. | Unsupported | No implementation evidence. |
| C035 | 280-283 | Atomic shadow-map swap guarantees no half-updated rules. | Needs Qualification | Pattern is plausible; correctness depends on concrete implementation. |
| C036 | 290-292 | Wirescale fully implements native NetworkPolicy with no modifications required. | Outdated | Contradicted by section 12 unchecked implementation list. |
| C037 | 317-318 | `WirescalePolicy` extensions are implemented. | Unsupported | CRD definition/validation marked TODO 1039. |
| C038 | 345-352 | `serviceAccountSelector` is supported in policy engine. | Unsupported | No API/controller evidence; also not part of standard `NetworkPolicyPeer`. |
| C039 | 354-357 | `externalPeer` selectors are supported. | Unsupported | Marked TODO 1041. |
| C040 | 379-384 | Time-bounded recurring schedule support exists. | Unsupported | Marked TODO 1043. |
| C041 | 395-430 | FQDN-based egress control exists. | Unsupported | Marked TODO 1042; name-based targeting not in standard NetworkPolicy API. |
| C042 | 435 | Default-deny policy is “applied first”. | Needs Qualification | NetworkPolicy semantics are additive; ordering does not determine result. |
| C043 | 446 | No rules means deny all ingress/egress for selected pods. | Supported | Matches Kubernetes default-deny pattern when podSelector+policyTypes are set. |
| C044 | 469-518 | `WirescaleAccessGrant` CRD and status workflow are implemented. | Unsupported | CRD/workflow/CLI all TODO 1046-1049. |
| C045 | 520-525 | Access grants auto-expire and status changes are automated. | Unsupported | Auto-expiry marked TODO 1048. |
| C046 | 533-574 | BPF map architecture described is present in code. | Unsupported | BPF map architecture marked TODO 1031. |
| C047 | 536-538 | Identity LPM trie map used for CIDR matching. | Partially Supported | LPM trie mechanism is valid in kernel docs; feature unimplemented here. |
| C048 | 550-563 | Policy hash map with key/value schema is active. | Unsupported | No implementation artifacts. |
| C049 | 565-571 | Dual-map selector mechanism is implemented for atomic cutover. | Unsupported | Atomic swap itself TODO 1036. |
| C050 | 572-573 | Ring buffer audit map is implemented. | Unsupported | Ring buffer logging TODO 1052. |
| C051 | 578-580 | TC eBPF attached on every host-side pod veth ingress+egress. | Unsupported | TC program TODO 1032. |
| C052 | 599 | Unknown source traffic is dropped by running policy program. | Unsupported | Program itself not implemented. |
| C053 | 606-607 | Pseudocode uses `bpf_map_lookup_elem` result as scalar selector directly. | Unsupported | This is technically inaccurate pseudocode (helper returns pointer). |
| C054 | 635-646 | Single write to selector array makes update globally atomic. | Needs Qualification | Element replacement can be atomic; whole-system race safety still implementation-dependent. |
| C055 | 652-655 | Nanosecond-level lookup overhead and 1ms/10k swap numbers. | Unsupported | No benchmark evidence in repo. |
| C056 | 657-659 | Policy cost is negligible and does not affect line-rate. | Unsupported | Unverified, especially without implementation/benchmarks. |
| C057 | 667-691 | Node admission flow executes as documented. | Unsupported | Admission controller/agent/controller all pending. |
| C058 | 675 | Hostname<->CRD-name enforcement webhook exists. | Unsupported | Hardened webhook is TODO 1058. |
| C059 | 678-683 | Controller validates real node membership/IP expectations. | Unsupported | No implemented validator evidence. |
| C060 | 684 | Controller allocates pod CIDRs. | Unsupported | No implementation in repository. |
| C061 | 700 | Node deletion cascades to WirescaleNode CRD via ownerReference. | Needs Qualification | Possible pattern, but no CRD/controller code proving behavior. |
| C062 | 706 | Emergency revocation propagates “within seconds”. | Unsupported | No measured system. |
| C063 | 708 | Cached sessions timeout after 2 minutes. | Needs Qualification | WireGuard rekey/reject timers are 120/180s; “2 min timeout” is oversimplified/inaccurate. |
| C064 | 714 | Old key becomes immediately invalid at rotation. | Unsupported | Contradicted by later stated 5-minute grace window (837-843). |
| C065 | 740-744 | Admission webhook can enforce attestation/rate-limit/key-age policies. | Partially Supported | Webhooks can enforce validation in Kubernetes; this specific webhook is not implemented. |
| C066 | 752 | Every WireGuard handshake is mutually authenticated. | Supported | WireGuard Noise_IK handshake design. |
| C067 | 757-758 | Initiator sends encrypted static key in first handshake message. | Supported | Matches `encrypted_static` in protocol first message. |
| C068 | 760-761 | Responder sends encrypted static pubkey in second message. | Unsupported | Protocol second message includes `unencrypted_ephemeral` and `encrypted_nothing`, not responder static key. |
| C069 | 763-766 | Both peers prove private-key possession and derive session keys. | Supported | Protocol properties + key derivation. |
| C070 | 769-770 | No certs/CAs/CRLs; CRD deletion equals revocation. | Needs Qualification | WireGuard part is true; CRD registry/revocation is project-specific and unimplemented. |
| C071 | 774-790 | Pod-level auth is provided by transitive node->kubelet->identity chain. | Needs Qualification | Viable model, but relies on strong host trust and implemented anti-spoof checks. |
| C072 | 796-808 | External peer auth/approval flow is implemented and active. | Unsupported | CRD/controller/CLI pieces are TODO in section 12 scope. |
| C073 | 818-821 | Key generation method and key handling are implemented as described. | Unsupported | No implementation code present. |
| C074 | 824-827 | Agent restart always regenerates keys and causes brief interruption. | Unsupported | No running system evidence. |
| C075 | 832 | Default automatic key rotation interval is 24h. | Unsupported | No config/code reference. |
| C076 | 837-843 | Dual-key grace via `previousKeys` for 5 minutes works. | Unsupported | No implementation; also WireGuard AllowedIPs behavior complicates dual active peers for same ranges. |
| C077 | 845-850 | T+2/T+5/T+300 timeline is achieved. | Unsupported | Unverified target numbers. |
| C078 | 861-863 | Revoked key cannot handshake and sessions timeout in 2 minutes. | Needs Qualification | Handshake rejection true after config update; timeout number imprecise vs WireGuard timer model. |
| C079 | 868-873 | No key escrow/no master key/PFS guarantee. | Partially Supported | WireGuard PFS property holds; project key handling unimplemented. |
| C080 | 881-883 | Ringbuf-based audit emission and structured identity logs are implemented. | Unsupported | Audit/logging TODO 1052-1054. |
| C081 | 914-923 | Logging defaults table reflects runtime behavior. | Unsupported | No implementation. |
| C082 | 926-950 | Metrics endpoint and metric set are implemented. | Unsupported | Metrics exporter TODO 1054. |
| C083 | 956 | Hubble-compatible flow format is available. | Unsupported | No parser/exporter evidence. |
| C084 | 959-967 | `kubectl wirescale flows` exists and works. | Unsupported | CLI TODO 1055. |
| C085 | 977 | T1 mitigation (WG encryption for eavesdropping) is correct. | Supported | WireGuard protocol and primitives. |
| C086 | 978 | T2 mitigation (rogue node prevented by RBAC+webhook) is sufficient. | Needs Qualification | Webhook optional; RBAC shown is not self-node-scoped. |
| C087 | 979 | T3 blast radius strictly limited to compromised node’s pods. | Needs Qualification | Overstated; compromised node can abuse allowed identity/routing semantics. |
| C088 | 980 | T4: API compromise cannot passively decrypt traffic. | Partially Supported | True if private keys remain off-API and uncompromised on nodes. |
| C089 | 981 | T5: agents validate CRD consistency + anomaly alerts exist. | Unsupported | Anomaly detection is TODO 1060. |
| C090 | 983 | T7 DNS poisoning mitigated via signed MagicDNS + DNSSEC + hardcoded NAT64. | Unsupported | No signed DNS implementation evidence; claim is speculative. |
| C091 | 984 | T8 DDoS mitigation includes WG cookie and XDP early drop. | Partially Supported | WG cookie mechanism exists; XDP path unimplemented here. |
| C092 | 986 | T10 replay protection via monotonic counters is correct. | Supported | WireGuard anti-replay window/counter behavior documented. |
| C093 | 987 | T11 spoofing mitigation via cryptokey routing is correct. | Partially Supported | WireGuard AllowedIPs source check true; project IPAM aspect unproven. |
| C094 | 988 | T12 deny-by-default + grants currently constrain lateral movement. | Outdated | Deny-default/grants implementation still TODO. |
| C095 | 995-998 | IPv6-only underlay removes IPv4 attack surface. | Needs Qualification | NAT64/dual-stack paths still introduce IPv4-facing components. |
| C096 | 1016-1018 | Every denied connection and every policy change are logged. | Outdated | Logging stack and CLI/exporters are TODO (1052-1055). |
| C097 | 1027-1029 | Document scope is phase 3/4 design. | Supported | Explicitly stated in text. |
| C098 | 1031-1061 | Core security features are not yet implemented (all checklist items unchecked). | Supported | Internal explicit state marker. |
| C099 | 1073-1075 | Agent RBAC grants create/update on all `wirescalenodes`. | Supported | YAML shows broad verbs/resources. |
| C100 | 1088 | `resourceNames: ["wirescale-policy-*"]` constrains ConfigMap access by wildcard prefix. | Unsupported | RBAC docs do not define wildcard semantics for `resourceNames`; list/watch also requires exact `metadata.name` selector when constrained. |
| C101 | 1098-1100 | Controller has full wildcard CRD access (`resources:*`, `verbs:*`). | Supported | YAML explicitly grants this; least-privilege risk. |
| C102 | 1117-1124 | Resource overhead table is factual current-state measurement. | Unsupported | No benchmark methodology/data and no implementation. |

**Findings by Severity (with rewrites)**

**Critical**
1. Present-tense security guarantees describe unimplemented features.  
Lines: 33-47, 57-70, 116-133, 200-283, 290-526, 529-967 vs 1031-1061.  
Rewrite: Prefix each operational claim with design intent until implementation lands.  
Suggested replacement header text at line 1-5:
```md
# Wirescale Security Architecture (Design Draft)

> This document describes intended security architecture and planned controls.
> Current implementation status is tracked in Section 12.
```

2. RBAC least-privilege claim is false.  
Lines: 159-163 claim vs 1073-1075 YAML.  
Rewrite line 162:
```md
- RBAC policy: agents currently have cluster-wide create/update on `wirescalenodes`; admission checks must enforce node ownership until RBAC is tightened.
```

3. Incorrect WireGuard handshake description (responder static key in message 2).  
Lines: 760-761.  
Rewrite:
```md
2. B sends its ephemeral public key and encrypted key-confirmation payload.
   B's static key is not sent in message 2; identity is proven via Noise_IK transcript.
```

4. Unsafe propagation guarantee (“At no point is a pod unprotected”).  
Lines: 276 and 271-276.  
Rewrite:
```md
- During propagation there can be short windows of policy skew. Pods may be temporarily over-permissive or over-restrictive depending on plugin timing; design should minimize and monitor this window.
```

**High**
5. NetworkPolicy ordering statement conflicts with Kubernetes semantics.  
Lines: 435 (`applied first`).  
Rewrite:
```md
# Namespace default-deny baseline (order-independent with additive policy semantics)
```

6. Key lifecycle contradiction: “old key immediately invalid” vs “5-minute grace period.”  
Lines: 714 vs 837-843.  
Rewrite either to strict cutover or grace mode, not both.  
Example:
```md
4. Old key retained for a 5-minute overlap window to avoid in-flight disruption.
5. After overlap, old key is removed and rejected.
```

7. ResourceNames wildcard usage is misleading.  
Lines: 1088.  
Rewrite:
```yaml
# Prefer label/namespace scoping and dedicated per-node ConfigMap names;
# do not rely on wildcard-like resourceNames.
resourceNames:
  - wirescale-policy-worker-1
```

8. Threat model overclaims unsupported mitigations (MagicDNS signing, anomaly detection, Hubble compatibility).  
Lines: 981, 983, 956.  
Rewrite each as planned controls with status tags, e.g.:
```md
- [Planned] Anomaly detection alerts on mass policy changes.
- [Planned] DNS response integrity checks for internal resolver.
```

**Medium**
9. Performance numbers presented as facts without benchmark context.  
Lines: 650-659, 1117-1124.  
Rewrite:
```md
| Operation | Target (Design) | Validation Status |
| ...       | ...             | Not yet benchmarked |
```

10. Non-repudiation claim lacks cryptographic log integrity model.  
Line: 67.  
Rewrite:
```md
Layer 4: Audit Trail (attribution and forensics)
```

**Cross-Claim Consistency Issues**

1. Implementation-state contradiction: sections 1-11 use present tense, section 12 shows all major security items unchecked (1031-1061).  
2. RBAC contradiction: “agents can only write their own CRD” (162) conflicts with granted verbs/resources (1073-1075).  
3. Key validity contradiction: immediate invalidation (714) vs overlap grace (837-843).  
4. Policy safety contradiction: “no pod unprotected” (276) conflicts with Kubernetes policy-application timing caveat.  
5. NetworkPolicy compatibility contradiction: “fully implements standard API” (290-292) while using non-standard selectors/FQDN features and no implementation.  
6. Logging contradiction: “always logged” assertions (916-923, 1016-1018) vs logging pipeline TODOs (1052-1055).  
7. Threat model assumes controls (anomaly detection, admission hardening) that are explicitly planned but not built.

**Top-Priority Remediation Plan (ordered)**

1. Reframe document as `design + status` immediately. Convert all operational present-tense claims to “planned” unless implemented.  
2. Fix factual protocol errors first (handshake message 2 text, timer wording).  
3. Resolve RBAC model/document mismatch: either tighten YAML or explicitly document current broad permissions + compensating controls.  
4. Remove absolute safety guarantees (`no pod unprotected`, `always logged`, `line-rate unaffected`) unless backed by tests.  
5. Split standard NetworkPolicy support from custom extensions; explicitly mark non-standard fields and compatibility caveats.  
6. Add per-claim status tags (`Implemented`, `Planned`, `Validated`, `Target`) to sections 1-11.  
7. Add benchmark appendix for latency/overhead claims with method, environment, and date.  
8. Add a compact “security assumptions” section (host trust, CNI behavior, webhook availability, key custody model) and link each threat mitigation to implementation status.
