**Scope coverage summary**
Reviewed all sections of [ARCHITECTURE.md](/Users/bill/src/wirescale/ARCHITECTURE.md) end-to-end (lines 1-1058), with no skipped headings:

- Front matter + TOC: lines 1-33
- Sections 1-14: lines 36-1027
- Appendices A-C: lines 1031-1058

Total inventoried atomic claims: **96**

**Evidence key (authoritative sources)**
- `R1` NRO IPv4 free-pool depletion: https://www.nro.net/ipv4-free-pool-depleted/
- `R2` AWS public IPv4 pricing ($0.005/hour): https://aws.amazon.com/blogs/aws/new-aws-public-ipv4-address-charge-public-ip-insights/
- `R3` Kubernetes dual-stack/single-stack docs: https://kubernetes.io/docs/concepts/services-networking/dual-stack/
- `R4` Kubernetes network plugin model: https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/
- `R5` CNI spec (`ADD`/`DEL` lifecycle): https://github.com/containernetworking/cni/blob/main/SPEC.md
- `R6` WireGuard protocol/crypto (Curve25519): https://www.wireguard.com/protocol/
- `R7` `wg(8)` (`AllowedIPs`, listen-port semantics): https://man7.org/linux/man-pages/man8/wg.8.html
- `R8` Linux capabilities (`NET_ADMIN`, `NET_RAW`, `SYS_MODULE`): https://man7.org/linux/man-pages/man7/capabilities.7.html
- `R9` RFC 6052 (well-known NAT64 prefix `64:ff9b::/96`): https://datatracker.ietf.org/doc/html/rfc6052
- `R10` RFC 6598 (`100.64.0.0/10` shared space): https://datatracker.ietf.org/doc/html/rfc6598
- `R11` RFC 8215 (local-use NAT64 prefix `64:ff9b:1::/48`): https://datatracker.ietf.org/doc/html/rfc8215
- `R12` RFC 6147 (DNS64 behavior): https://datatracker.ietf.org/doc/html/rfc6147
- `R13` CoreDNS `dns64` plugin (`translate_all` behavior): https://coredns.io/plugins/dns64/
- `R14` RFC 6146 (stateful NAT64): https://datatracker.ietf.org/doc/html/rfc6146
- `R15` RFC 6877 (464XLAT/CLAT context): https://datatracker.ietf.org/doc/html/rfc6877
- `R16` RFC 7915 (SIIT translation): https://datatracker.ietf.org/doc/html/rfc7915
- `R17` RFC 6762 (`.local` special-use for mDNS): https://datatracker.ietf.org/doc/html/rfc6762
- `R18` Tailscale Kubernetes operator docs: https://tailscale.com/docs/features/kubernetes-operator/
- `R19` Cilium WireGuard + routing docs (current): https://docs.cilium.io/en/stable/security/network/encryption-wireguard.html and https://docs.cilium.io/en/stable/network/concepts/routing/
- `R20` Calico IPv6 support docs: https://docs.tigera.io/calico/latest/networking/ipam/ipv6
- `R21` Calico WireGuard encryption docs: https://docs.tigera.io/calico/latest/security/encrypt-cluster-pod-traffic
- `R22` Kilo docs/introduction: https://kilo.squat.ai/docs/introduction/
- `R23` Kubernetes API authn/authz control: https://kubernetes.io/docs/concepts/security/controlling-access/
- `R24` Kubernetes NetworkPolicy behavior: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- `I1` Internal repo evidence: only markdown docs present (`ARCHITECTURE.md`, `SECURITY.md`, `PERFORMANCE.md`, `ROUTABLE-PREFIX.md`), no manifests/code/CRDs detected.

## Claim inventory

| claim_id | lines | claim | status | evidence |
|---|---:|---|---|---|
| C01 | 3-5 | Wirescale is a WireGuard Kubernetes operator giving seamless IPv4/IPv6 in IPv6-only clusters. | Needs Qualification | Design intent only; no implementation artifacts (`I1`). |
| C02 | 8-13 | Performance/Security/Routable-prefix docs exist and define adjacent architecture behavior. | Supported | Files present (`I1`). |
| C03 | 40-41 | Public IPv4 is exhausted/scarce and expensive. | Supported | `R1`, `R2`. |
| C04 | 41 | AWS cost is about $43/year per public IPv4. | Supported | `R2` ($0.005/h ≈ $43.8/year). |
| C05 | 42 | “The path forward is IPv6-only infrastructure.” | Needs Qualification | Strategic assertion, not universal requirement (`R3`). |
| C06 | 44 | Many external services are still IPv4-only. | Partially Supported | Industry reality; not universally quantified (`R12`,`R15` context). |
| C07 | 45 | Legacy apps often depend on IPv4-only behavior/APIs. | Supported | Common migration driver (464XLAT problem space, `R15`). |
| C08 | 46 | Kubernetes tooling mostly assumes dual-stack or IPv4-primary. | Needs Qualification | Kubernetes supports single-stack IPv6 (`R3`). |
| C09 | 56-57 | All inter-node pod traffic is encrypted by WireGuard. | Needs Qualification | Conflicts with location-aware “no WG intra-zone” later (315-316). |
| C10 | 58-61 | Tailscale-like control/data split can also cover external peers. | Needs Qualification | Conceptual design; no repo implementation (`I1`). |
| C11 | 69 | Underlay is IPv6-only; IPv4 is translation service. | Needs Qualification | Valid model, but implementation absent (`I1`). |
| C12 | 70 | Control/data separation means control-plane failure won’t break existing connections. | Partially Supported | True for preconfigured WG state; depends on restart/state handling (`R7`). |
| C13 | 71 | Key-per-node matches WireGuard and avoids key-per-pod scaling; same-node traffic unencrypted. | Partially Supported | WG peer model supports node keys (`R7`); “sufficient isolation” is threat-model-dependent. |
| C14 | 72 | All mesh state lives in CRDs; API server is coordination DB. | Unsupported | No CRDs/manifests in repo (`I1`). |
| C15 | 73 | Can run standalone CNI or overlay on existing CNI. | Partially Supported | Technically possible with chaining (`R4`,`R5`), not implemented (`I1`). |
| C16 | 74 | No external dependencies (no etcd/Consul). | Needs Qualification | Kubernetes itself depends on etcd; should say no *additional* coordinator. |
| C17 | 75 | Graceful degradation: existing mesh persists while controller is down. | Partially Supported | Plausible with local WG state (`R7`), but not evidenced (`I1`). |
| C18 | 86-94 | Controller performs IPAM/topology/key/policy/health roles. | Unsupported | No controller code/manifests (`I1`). |
| C19 | 103-116 | Agent has WG manager, route manager, policy enforcer, NAT64+CLAT engines. | Unsupported | No agent implementation (`I1`). |
| C20 | 120-125 | CNI assigns IPv6 primary + IPv4 via CLAT and injects routes. | Unsupported | No CNI binary/config in repo (`I1`). |
| C21 | 136 | CoreDNS `dns64` plugin is patched/configured component. | Partially Supported | Plugin exists (`R13`), deployment/config not present (`I1`). |
| C22 | 133-135 | Component roles/placement table reflects current architecture. | Unsupported | No deployable artifacts (`I1`). |
| C23 | 144-146 | Controller uses controller-runtime and leader election. | Unsupported | No code/go module/manifests (`I1`). |
| C24 | 149-152 | Per-node allocations are /64 IPv6 and /24 IPv4 with reclamation. | Partially Supported | Size choices align with common K8s defaults (`R3`), but no implementation (`I1`). |
| C25 | 155-158 | Location-aware mode: same-zone direct routing, cross-zone WireGuard. | Needs Qualification | Design possible (`R22` inspiration) but conflicts with “always encrypted”. |
| C26 | 160-164 | Policy reconciler compiles NetworkPolicy + WirescalePolicy into ConfigMaps. | Unsupported | No controller/policy compiler artifacts (`I1`). |
| C27 | 166-169 | External peer reconciler distributes keys/routes to nodes. | Unsupported | No implementation (`I1`). |
| C28 | 172-174 | Agent requires NET_ADMIN, NET_RAW, SYS_MODULE. | Needs Qualification | NET_ADMIN/NET_RAW plausible; SYS_MODULE conditional (`R8`). |
| C29 | 176-183 | Private key memory-only and never persisted; CRD registration at startup. | Needs Qualification | Security claim plausible but unverified (`I1`); impacts restart behavior. |
| C30 | 182-187 | Agent creates wg0, routes, nat64 iface, CLAT engine on startup. | Unsupported | No implementation evidence (`I1`). |
| C31 | 191-203 | Reconciliation loop commands are operationally valid for peer lifecycle. | Partially Supported | Command semantics align with `wg/ip` model (`R7`). |
| C32 | 210-212 | CNI is short-lived/stateless per pod invocation. | Supported | CNI lifecycle model (`R5`). |
| C33 | 217-229 | CNI ADD sequence (incl MTU host-80) is universally correct. | Needs Qualification | MTU delta depends on outer header/path; conditional needed (`R7`,`R19`,`R21`). |
| C34 | 238-242 | Addressing block (`fd00:ws::/48` etc.) is valid concrete CIDR notation. | Unsupported | `fd00:ws` / `svc` are invalid hex hextets; examples not syntactically valid IPs. |
| C35 | 244-246 | All pod/service/external traffic is native IPv6; WG endpoints on physical IPv6. | Needs Qualification | Depends on topology mode and node underlay reality. |
| C36 | 253-256 | IPv4 pod space uses `100.64.0.0/10` with per-node `/24`, per-pod `/32`. | Supported | `100.64/10` is shared address space (`R10`). |
| C37 | 258-266 | Deterministic IPv4↔IPv6 mapping enables stateless translation in mesh. | Partially Supported | SIIT-style deterministic mapping is valid (`R16`), implementation unspecified (`I1`). |
| C38 | 271-275 | `64:ff9b::/96` is well-known NAT64 prefix and embeds IPv4 in low 32 bits. | Supported | `R9`. |
| C39 | 283-288 | DNS resolver IPv4 `100.100.100.100` is compatibility baseline. | Needs Qualification | Tailscale-specific convention; not protocol standard. |
| C40 | 284 | Optional service IPv4 block `100.64.255.0/24` is safe by default. | Needs Qualification | Must prove non-overlap/reservation rules within `100.64/10`. |
| C41 | 297-300 | Full mesh default threshold `<100 nodes`; key distribution O(N). | Needs Qualification | Big-O statement fine; threshold is unsourced design heuristic. |
| C42 | 301-319 | Zone-leader topology behavior mirrors Kilo-like approach. | Partially Supported | Kilo supports location-aware interconnect concepts (`R22`), but details are custom. |
| C43 | 324-327 | WireGuard keypair is Ed25519. | Unsupported | WireGuard uses Curve25519/X25519 (`R6`). |
| C44 | 329-334 | Rotation causes ~1-2 RTT interruption. | Needs Qualification | Runtime-dependent; no source or implementation (`I1`). |
| C45 | 336-337 | PSK optional for defense-in-depth. | Supported | WG supports optional preshared key (`R7`). |
| C46 | 359-361 | `AllowedIPs` covering v4+v6 lets one tunnel carry both families. | Supported | `R7`. |
| C47 | 366-370 | MTU overhead math is correct as written. | Partially Supported | 80-byte IPv6-over-IPv6 case is fine; “20 IPv6” is incorrect label. |
| C48 | 373-374 | nftables MSS clamping on `wg0` prevents fragmentation issues. | Needs Qualification | Technique valid; effectiveness depends on path/header variance. |
| C49 | 385-387 | Per-pod `clat0` gives apps transparent IPv4 sockets. | Needs Qualification | Concept valid (`R15`), operational complexity/overhead unstated. |
| C50 | 406-409 | CLAT mapping references RFC 7915 SIIT behavior. | Partially Supported | SIIT exists (`R16`); 464XLAT context is `R15`. |
| C51 | 413-414 | Route `64:ff9b::/96` to `wg0` for mesh destinations. | Unsupported | Contradicts section 7.5 + RFC6052 global-address constraints (`R9`,`R11`). |
| C52 | 417-419 | Reverse CLAT is deterministic due 1:1 map. | Partially Supported | True if deterministic map is enforced (`R16`). |
| C53 | 423-425 | Per-node NAT64 handles external IPv4 egress. | Partially Supported | NAT64 architecture valid (`R14`), implementation absent (`I1`). |
| C54 | 443-445 | NAT64 is stateless eBPF + conntrack MASQUERADE. | Needs Qualification | Mixes SIIT and stateful NAT behavior; terminology should be tightened (`R14`,`R16`). |
| C55 | 449-462 | CoreDNS `dns64` config (prefix + `translate_all`) is valid. | Supported | `R13`. |
| C56 | 471-477 | If AAAA exists, it is returned directly (no synthesis). | Partially Supported | True by default (`R12`), but not when `translate_all` is enabled (`R13`). |
| C57 | 482-500 | End-to-end external IPv4 flow via CLAT+DNS64+NAT64 is coherent. | Partially Supported | Concept aligns with 464XLAT/NAT64 model (`R12`,`R14`,`R15`). |
| C58 | 505-526 | In-mesh IPv4 bypasses NAT64 and maps to IPv6 over WG. | Partially Supported | Consistent with deterministic SIIT-style mapping (`R16`). |
| C59 | 534-540 | `*.ws.local` as mesh DNS domain is appropriate. | Needs Qualification | `.local` is special-use mDNS namespace (`R17`). |
| C60 | 542-547 | Agent DNS sidecar serves `ws.local` and forwards others to CoreDNS. | Unsupported | No DNS sidecar implementation/config (`I1`). |
| C61 | 548-550 | Push-based updates remove need for TTL-based caching concerns. | Needs Qualification | DNS client caching semantics still TTL-driven by protocol behavior. |
| C62 | 553-567 | `ws.local` query path via CoreDNS forwarding is implemented. | Unsupported | No CoreDNS/forward config artifacts (`I1`). |
| C63 | 571-580 | External names are handled by CoreDNS+dns64 synthesis when needed. | Supported | `R12`,`R13`. |
| C64 | 588-590 | External peers join through `WirescaleExternalPeer` CRD. | Unsupported | CRD not present (`I1`). |
| C65 | 607-609 | `wirescale-join` agent exists and handles key exchange/routes. | Unsupported | No CLI/agent artifacts (`I1`). |
| C66 | 613-629 | Subnet-router mode works like Tailscale route advertisement. | Partially Supported | Model valid in principle (`R18`), unimplemented here (`I1`). |
| C67 | 633-649 | Exit-node mode routes non-mesh traffic through selected node. | Partially Supported | Pattern is valid (`R18`), implementation absent (`I1`). |
| C68 | 652-670 | Multi-cluster gateway peering + seamless DNS is supported. | Partially Supported | Feasible concept (`R22`), no implementation evidence (`I1`). |
| C69 | 678-681 | Encryption/control-plane/key-handling summary is current behavior. | Partially Supported | Crypto primitives accurate (`R6`), memory-only claim unverified (`I1`). |
| C70 | 685-687 | Node auth is WG-key ownership + kubeconfig gate. | Needs Qualification | Kube auth/RBAC exists (`R23`), node attestation details unspecified. |
| C71 | 689-693 | External peer auth token + approval workflow is implemented. | Unsupported | No workflow artifacts in repo (`I1`). |
| C72 | 698-701 | WireGuard `AllowedIPs` drops non-matching sources. | Supported | `R7`. |
| C73 | 702-706 | L3/L4 policy via eBPF/nftables from NP + WirescalePolicy. | Partially Supported | NP framework exists (`R24`), Wirescale enforcement unimplemented (`I1`). |
| C74 | 735-739 | Deleting CRD or rotating key revokes peers immediately. | Needs Qualification | Eventual propagation/watch timing not “immediate” by guarantee. |
| C75 | 738 | Control-plane compromise can’t decrypt existing data-plane traffic. | Partially Supported | True if private keys stay off control plane; implementation not evidenced (`I1`). |
| C76 | 745-777 | `WirescaleMesh` CRD schema/status shown as concrete API. | Unsupported | No CRD definitions present (`I1`). |
| C77 | 779-812 | `WirescaleNode` CRD/status fields (incl NAT type) are concrete API. | Unsupported | No CRD/controller code (`I1`). |
| C78 | 814-837 | `WirescaleExternalPeer` schema/auth fields are concrete API. | Unsupported | No CRD/validation/controller evidence (`I1`). |
| C79 | 839-872 | `WirescalePolicy` schema is concrete API extension. | Unsupported | No CRD artifacts (`I1`). |
| C80 | 756-763,797-798 | CRD CIDR examples are valid literals. | Unsupported | `fd00:ws...` examples are invalid IPv6 syntax. |
| C81 | 881-884 | Same-node pod path avoids WG and translation. | Supported | Consistent with node-local veth path model (`R4`). |
| C82 | 889-901 | Cross-node IPv6 flow via wg0 + AllowedIPs validation is correct. | Supported | `R7`. |
| C83 | 906-916 | Cross-node IPv4 flow via CLAT→IPv6→WG→reverse CLAT is coherent. | Partially Supported | Model plausible (`R15`,`R16`), unimplemented (`I1`). |
| C84 | 921-934 | External IPv4 flow uses DNS64 then NAT64 on node. | Partially Supported | Aligns with RFC model (`R12`,`R14`). |
| C85 | 939-946 | External peer to pod path over WG is valid. | Partially Supported | WG peer model valid (`R7`), CRD/agent path absent (`I1`). |
| C86 | 952-963 | Comparison matrix is technically current for all listed projects. | Needs Qualification | Multiple rows are stale or oversimplified (`R18`,`R19`,`R20`,`R21`,`R22`). |
| C87 | 956 | Cilium/Calico/Kilo are “dual-stack only.” | Outdated | Cilium/Calico document IPv6 modes (`R19`,`R20`); Kilo docs do not state dual-stack-only (`R22`). |
| C88 | 960-961 | External peer support matrix (yes/no) is fully accurate. | Partially Supported | High-level mostly right; terminology differs by project docs (`R18`,`R22`). |
| C89 | 966-970 | Tailscale operator is not a CNI and uses proxy connector patterns; no in-cluster pod-to-pod encryption. | Supported | `R18`. |
| C90 | 969-970 | Tailscale requires account or headscale-like coordinator. | Partially Supported | Coordination dependency true in principle; wording should mention enterprise/self-host options explicitly (`R18`). |
| C91 | 982-1025 | Phase checklist indicates features are planned/not complete. | Supported | All checklist items unchecked; repo lacks code (`I1`). |
| C92 | 988,998,1007,1017,1027 | “Result” statements are future outcomes, not current implemented state. | Needs Qualification | Should be explicitly labeled “target outcome”. |
| C93 | 1023 | NAT traversal/DERP-like relay is future work. | Needs Qualification | Valid roadmap item; scope/dependency unspecified. |
| C94 | 1035-1042 | Appendix tech stack reflects implementation choices. | Needs Qualification | Proposed stack only; no implementation (`I1`). |
| C95 | 1048-1050 | Port requirements (`51820`, API `443`) are universally correct. | Needs Qualification | WG listen-port configurable/random if unset (`R7`); API port/env can vary (`R23`). |
| C96 | 1054-1058 | Kernel/sysctl/eBPF/TUN requirements are baseline prerequisites. | Partially Supported | Requirements are directionally correct for this design (`R19`,`R21`,`R5`). |

## Findings by severity (with rewrites)

### Critical

1. **Incorrect WireGuard key type**  
   Ref: [ARCHITECTURE.md:324](/Users/bill/src/wirescale/ARCHITECTURE.md:324)  
   Issue: Says “Ed25519 keypair (WireGuard)”; WireGuard uses Curve25519/X25519 (`R6`).  
   Rewrite:
   ```md
   1. Generate Curve25519 (X25519) WireGuard keypair
   ```

2. **Invalid IPv6 examples used as literal CIDRs**  
   Refs: [ARCHITECTURE.md:238](/Users/bill/src/wirescale/ARCHITECTURE.md:238), [ARCHITECTURE.md:756](/Users/bill/src/wirescale/ARCHITECTURE.md:756)  
   Issue: `fd00:ws::/48`, `fd00:ws:svc::/108` are not syntactically valid IPv6.  
   Rewrite:
   ```md
   Cluster pod CIDR:     fd12:3456:7800::/48
   Per-node allocation:  fd12:3456:7800:N::/64
   Service CIDR:         fd12:3456:78ff::/108
   ```

3. **NAT64 well-known prefix route conflicts and RFC risk**  
   Ref: [ARCHITECTURE.md:413](/Users/bill/src/wirescale/ARCHITECTURE.md:413)  
   Issue: Routing `64:ff9b::/96` “to wg0 if dest in mesh” conflicts with section 7.5 and RFC6052 constraints for non-global mappings (`R9`,`R11`).  
   Rewrite:
   ```md
   host routing:
   - mesh IPv4-compat traffic -> deterministic IPv4↔IPv6 pod mapping (no WKP NAT64 prefix)
   - external global IPv4 destinations -> 64:ff9b::/96 via nat64 interface
   ```

### High

4. **Encryption guarantee contradiction**  
   Refs: [ARCHITECTURE.md:56](/Users/bill/src/wirescale/ARCHITECTURE.md:56), [ARCHITECTURE.md:315](/Users/bill/src/wirescale/ARCHITECTURE.md:315), [ARCHITECTURE.md:678](/Users/bill/src/wirescale/ARCHITECTURE.md:678)  
   Issue: “All inter-node traffic encrypted” conflicts with “intra-zone direct routing (no WireGuard).”  
   Rewrite:
   ```md
   In full-mesh mode, all inter-node pod traffic is WireGuard-encrypted.
   In location-aware mode, inter-zone traffic is encrypted; intra-zone traffic can be native-routed unless policy requires encryption.
   ```

5. **DNS64 behavior internally inconsistent with `translate_all`**  
   Refs: [ARCHITECTURE.md:461](/Users/bill/src/wirescale/ARCHITECTURE.md:461), [ARCHITECTURE.md:477](/Users/bill/src/wirescale/ARCHITECTURE.md:477)  
   Issue: Claims AAAA is returned directly while config enables optional `translate_all` (`R13`).  
   Rewrite:
   ```md
   If `translate_all` is disabled (default), existing AAAA answers are returned unchanged.
   If enabled, DNS64 may synthesize AAAA even when AAAA exists.
   ```

6. **Comparison table has stale vendor claims**  
   Ref: [ARCHITECTURE.md:956](/Users/bill/src/wirescale/ARCHITECTURE.md:956)  
   Issue: “Dual-stack only” for Cilium/Calico/Kilo is outdated/inaccurate (`R19`,`R20`,`R22`).  
   Rewrite:
   ```md
   IPv6-only cluster support: project-dependent and version/mode-specific; verify per current vendor docs.
   ```

7. **`ws.local` domain choice risks mDNS collision**  
   Ref: [ARCHITECTURE.md:537](/Users/bill/src/wirescale/ARCHITECTURE.md:537)  
   Issue: `.local` is special-use for mDNS (`R17`).  
   Rewrite:
   ```md
   Use a non-.local internal domain, e.g. `ws.cluster.internal`.
   ```

### Medium

8. **“No external dependencies” wording is misleading**  
   Ref: [ARCHITECTURE.md:74](/Users/bill/src/wirescale/ARCHITECTURE.md:74)  
   Rewrite:
   ```md
   No additional external coordinator beyond Kubernetes control-plane components.
   ```

9. **Capabilities over-specified (`SYS_MODULE`)**  
   Ref: [ARCHITECTURE.md:173](/Users/bill/src/wirescale/ARCHITECTURE.md:173)  
   Rewrite:
   ```md
   Requires NET_ADMIN and NET_RAW; SYS_MODULE only if loading kernel modules at runtime.
   ```

10. **Immediate revocation claims are too absolute**  
    Ref: [ARCHITECTURE.md:737](/Users/bill/src/wirescale/ARCHITECTURE.md:737)  
    Rewrite:
    ```md
    Revocation propagates via CRD watch updates; effective cutoff is near-real-time but not instantaneous.
    ```

11. **MTU overhead line has protocol-label error**  
    Ref: [ARCHITECTURE.md:367](/Users/bill/src/wirescale/ARCHITECTURE.md:367)  
    Rewrite:
    ```md
    WireGuard overhead: 60 bytes (20 IPv4 + 8 UDP + 32 WG), 80 bytes on IPv6 underlay.
    ```

12. **API server port hardcoded to 443**  
    Ref: [ARCHITECTURE.md:1050](/Users/bill/src/wirescale/ARCHITECTURE.md:1050)  
    Rewrite:
    ```md
    Agent-to-API: Kubernetes API endpoint port (commonly 443 via service, often 6443 on control-plane endpoint).
    ```

## Cross-claim consistency issues

1. **Encryption scope conflict**: C09/C69 vs C25/C42 (always encrypted vs intra-zone no WG).  
2. **Addressing conflict**: C51 vs C58/C37 (using `64:ff9b::/96` for mesh paths vs direct deterministic mesh mapping).  
3. **DNS64 logic conflict**: C55 vs C56 (`translate_all` enabled but text describes default non-translate behavior).  
4. **Dependency wording conflict**: C16 (“no etcd needed”) vs Kubernetes architecture reality (API server persistence).  
5. **Example validity conflict**: C34/C80 examples are shown as real YAML/CIDRs but are syntactically invalid.  
6. **Maturity signaling conflict**: C18-C30/C76-C79 present concrete architecture/API; C91 shows all roadmap tasks unchecked.

## Top-priority remediation plan (ordered)

1. **Fix protocol correctness errors first**: key type (Curve25519), NAT64/WKP semantics, MTU label error.  
2. **Normalize all address examples to valid literals** across sections and CRD YAML.  
3. **Resolve encryption-mode contradictions** by explicitly defining `full-mesh` vs `location-aware` guarantees.  
4. **Refresh competitor comparison table with versioned citations** (Cilium/Calico/Kilo/Tailscale).  
5. **Fix DNS section semantics**: `translate_all` conditional text + replace `.ws.local` with non-`.local` domain.  
6. **Reword absolutes into operationally accurate guarantees** (`immediate`, `always`, `no dependencies`).  
7. **Separate “design target” from “implemented behavior”** with a clear banner and per-section status tags (Planned/Implemented/Experimental).
