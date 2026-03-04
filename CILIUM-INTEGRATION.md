# Wirescale: Architecture with Cilium as CNI

> How the Wirescale architecture changes when Cilium is the CNI, what
> Cilium absorbs, what Wirescale still provides, and where the two
> designs diverge.
>
> Status: design comparison document. Unless explicitly linked to
> implementation artifacts, behavior described here should be treated
> as target architecture.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are
> to be interpreted as described in RFC 2119 and RFC 8174 when shown
> in all caps.

**Companion documents:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Base Wirescale architecture (ULA overlay, standalone CNI)
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
- [SECURITY.md](SECURITY.md) -- Security and dynamic access control
- [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) -- Globally routable /64-per-host design

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Component Ownership: Cilium vs Wirescale](#2-component-ownership-cilium-vs-wirescale)
3. [Address Architecture (Unchanged)](#3-address-architecture-unchanged)
4. [Routing and Data Plane](#4-routing-and-data-plane)
5. [WireGuard Encryption](#5-wireguard-encryption)
6. [IPv4 Compatibility: The Critical Gap](#6-ipv4-compatibility-the-critical-gap)
7. [Policy Enforcement](#7-policy-enforcement)
8. [Identity Model](#8-identity-model)
9. [Ingress Security for Internet-Routable Pods](#9-ingress-security-for-internet-routable-pods)
10. [Observability and Audit](#10-observability-and-audit)
11. [Multi-Site and Multi-Cluster](#11-multi-site-and-multi-cluster)
12. [Performance Comparison](#12-performance-comparison)
13. [Component-by-Component Diff](#13-component-by-component-diff)
14. [Architecture Diagram: With Cilium](#14-architecture-diagram-with-cilium)
15. [Deployment Decision Matrix](#15-deployment-decision-matrix)

---

## 1. Executive Summary

When Cilium is the CNI, the Wirescale architecture simplifies
significantly. Cilium absorbs the entire L2-L4 data plane: veth/netkit
management, kernel route programming, WireGuard encryption, eBPF policy
enforcement, and observability. Wirescale shrinks from a full CNI to a
**control-plane-only IPv4 compatibility layer**, providing the CLAT,
NAT64, and DNS64 functions that Cilium lacks.

### What Cilium Replaces

| Function | Without Cilium (Wirescale standalone) | With Cilium |
|----------|--------------------------------------|-------------|
| CNI binary (veth creation, IP assignment) | wirescale-cni | Cilium CNI |
| WireGuard mesh management | wirescale-agent | Cilium agent (`cilium_wg0`) |
| eBPF policy enforcement (L3/L4) | wirescale-agent (TC on veth) | Cilium agent (TC/netkit on lxc) |
| L7 policy (HTTP, gRPC, DNS) | Not available | Cilium + Envoy |
| Identity model | Custom BPF maps | Cilium security identities |
| Observability | Custom BPF ring buffer | Hubble |
| Kernel route programming | wirescale-agent | Cilium agent |
| Bandwidth management | Not available | Cilium EDT + BBR |

### What Wirescale Still Provides

| Function | Why Cilium Can't Do It |
|----------|----------------------|
| **CLAT (per-pod IPv4 via TUN)** | Cilium has no CLAT support at all |
| **Per-node stateless NAT64** | Cilium's NAT46x64 is gateway-centric and stateful |
| **DNS64 (CoreDNS plugin config)** | Cilium does not provide DNS64 |
| **Selective cross-site encryption** | Cilium WireGuard is all-or-nothing per cluster |
| **XDP ingress firewall for GUA pods** | Cilium host firewall is TC-based, not XDP on eth0 |
| **Cross-site WireGuard gateways** | Cilium ClusterMesh requires Cilium on both ends |
| **External peer mesh (non-k8s nodes)** | Cilium ClusterMesh is k8s-to-k8s only |

### Net Result

With Cilium, the deployment simplifies to:

```
Cilium:     CNI + WireGuard + L3-L7 policy + Hubble + bandwidth mgmt
Wirescale:  CLAT engine + NAT64 engine + DNS64 config + cross-site gateways
Fabric:     BGP routing for rack /64 and pod /64 (unchanged)
```

---

## 2. Component Ownership: Cilium vs Wirescale

### Per-Node Components

```
+------------------------------------------------------------+
| Cilium agent (DaemonSet)                                   |
|                                                            |
|  +------------------+  +------------------+  +-----------+ |
|  | Cilium CNI       |  | cilium_wg0       |  | Policy    | |
|  | - lxc/netkit     |  | - kernel WG      |  | Enforcer  | |
|  | - IPv6 addr      |  | - per-node key   |  | (eBPF on  | |
|  | - host routes    |  | - peer mgmt      |  |  lxc/nk)  | |
|  +------------------+  +------------------+  +-----------+ |
|                                                            |
|  +------------------+  +------------------+  +-----------+ |
|  | Hubble           |  | Envoy (L7)       |  | Bandwidth | |
|  | - flow events    |  | - HTTP/gRPC      |  | Manager   | |
|  | - gRPC server    |  | - FQDN egress    |  | (EDT+BBR) | |
|  +------------------+  +------------------+  +-----------+ |
+------------------------------------------------------------+

+------------------------------------------------------------+
| wirescale-agent (DaemonSet, reduced scope)                 |
|                                                            |
|  +------------------+  +------------------+                |
|  | NAT64 Engine     |  | CLAT Engine      |                |
|  | (eBPF on nat64   |  | (per-pod IPv4    |                |
|  |  interface)      |  |  via clat0 TUN)  |                |
|  +------------------+  +------------------+                |
|                                                            |
|  +------------------+                                      |
|  | Cross-Site       |  (only on gateway nodes)             |
|  | WireGuard Mesh   |                                      |
|  +------------------+                                      |
+------------------------------------------------------------+
```

### Control Plane

```
Cilium operator:         IPAM (/64 allocation), CiliumNode management
wirescale-controller:    NAT64/CLAT coordination, cross-site topology,
                         WirescaleExternalPeer management
                         (no longer handles IPAM, policy compilation,
                         or intra-site WireGuard mesh)
```

---

## 3. Address Architecture (Unchanged)

The IPv6 address plan is identical whether Cilium or Wirescale manages
the data plane. The fabric, not the CNI, owns the address topology.

```
Site A (DC-East):        3fff:0a00::/48
  Rack /64s:             3fff:0a00:ff00::/56  (one per rack, shared L2)
    Rack 1:              3fff:0a00:ff01::/64
  Pod /64s:              3fff:0a00:0000::/52  (one per host, routed)
    worker-1:            3fff:0a00:0001::/64

Per host:
  eth0 (rack):           3fff:0a:ff01::11/128   (from rack /64)
  Pod /64:               3fff:0a:0001::/64      (dedicated, fabric-routed)
```

### How Cilium Consumes the /64

Cilium's IPAM in **Kubernetes host-scope mode** reads `spec.podCIDRs`
from the Node object. The infrastructure provisioning system (Terraform,
Ansible, or the fabric controller) assigns each node its /64:

```yaml
apiVersion: v1
kind: Node
metadata:
  name: worker-1
spec:
  podCIDRs:
    - "3fff:0a00:0001::/64"    # pod /64 from site allocation
```

Cilium reads this and allocates pod IPs from the /64. No Cilium-specific
IPAM configuration is needed beyond:

```yaml
# Cilium Helm values
ipam:
  mode: kubernetes           # use Node.spec.podCIDRs
ipv6NativeRoutingCIDR: "3fff:0a00::/48"  # site prefix, no masquerade
```

The `ipv6NativeRoutingCIDR` tells Cilium that traffic within the site
/48 should not be masqueraded -- preserving pod source IPs end-to-end.

### IPv4 Addresses (CLAT, Still Wirescale)

Cilium assigns IPv6 addresses only. The CLAT IPv4 address
(`100.64.N.P`) is still provisioned by wirescale-agent's CLAT engine
inside each pod's network namespace, exactly as in the standalone
architecture.

---

## 4. Routing and Data Plane

### Cilium Native Routing Mode

Cilium operates in **native routing mode** (no VXLAN/Geneve overlay).
The fabric's BGP installs kernel routes for each remote node's pod /64:

```
# Kernel routing table on worker-1 (installed by fabric BGP, not Cilium):
3fff:0a:0002::/64 via 3fff:0a:ff01::12 dev eth0   # host-2, same rack
3fff:0a:0003::/64 via 3fff:0a:ff01::1  dev eth0    # host-3, via ToR
::/0              via 3fff:0a:ff01::1  dev eth0    # default route
```

Cilium delegates all non-local forwarding to these kernel routes. It
does not need to install inter-node routes itself.

### Cilium BGP Control Plane: Not Needed

Cilium embeds a BGP speaker (GoBGP) via `CiliumBGPClusterConfig`.
Since the fabric already handles BGP (per ROUTABLE-PREFIX.md), Cilium's
BGP Control Plane SHOULD NOT be deployed. No `CiliumBGPClusterConfig`,
`CiliumBGPPeerConfig`, or `CiliumBGPAdvertisement` resources should
exist.

### Comparison

| Aspect | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| Route source | Fabric BGP -> kernel routes | Fabric BGP -> kernel routes (same) |
| CNI installs per-pod /128 host routes | wirescale-cni | Cilium CNI |
| Inter-node routing | Kernel FIB lookup | Kernel FIB lookup (same) |
| Pod interface type | veth pair | veth or netkit (Linux 6.8+) |

With netkit (available on Linux 6.8+), Cilium replaces veth pairs with
a purpose-built kernel device that eliminates cross-namespace qdisc
overhead. This provides measurably lower latency and higher throughput
for the pod-to-host path.

---

## 5. WireGuard Encryption

### Cilium's WireGuard vs Wirescale's WireGuard

Both use the **same kernel WireGuard module**. The difference is
management, not mechanism:

| Property | Wirescale WireGuard | Cilium WireGuard |
|----------|--------------------|--------------------|
| Interface name | `wg0` | `cilium_wg0` |
| Listen port | 51820 | 51871 |
| Key storage | WirescaleNode CRD | CiliumNode annotation |
| Peer management | Watch WirescaleNode CRDs | Watch CiliumNode CRDs |
| AllowedIPs | Pod /64 per peer | Pod /64 per peer (or individual IPs) |
| GRO/GSO | Kernel-native | Kernel-native (same) |
| Threaded NAPI | Agent enables | Agent enables |
| Conntrack bypass | nftables `notrack` on port 51820 | nftables `notrack` on port 51871 |

Performance is identical -- same kernel module, same crypto, same
GRO/GSO amortization.

### The Selective Encryption Gap

This is the most significant architectural difference.

**Wirescale** supports four encryption modes:
- `always` -- all inter-node traffic via WireGuard
- `cross-site` -- same-site native, cross-site encrypted
- `policy` -- per-flow encryption via WirescalePolicy
- `never` -- no WireGuard

**Cilium** supports only:
- All inter-node traffic encrypted (WireGuard enabled)
- No encryption (WireGuard disabled)

Cilium has no concept of site boundaries or selective encryption.
The `encryption.nodeEncryption` flag extends encryption to node-to-node
traffic but does not allow partial application by topology.

### Implications for the /64-per-Host GUA Model

In a single-site deployment, Cilium's all-or-nothing model is
acceptable: either encrypt everything (like `always` mode) or encrypt
nothing (like `never` mode).

In a **multi-site deployment**, this is a problem. Wirescale's
`cross-site` mode gives line-rate same-site performance (no WireGuard
overhead) while encrypting untrusted cross-site transit. With Cilium,
you must choose:

- Enable WireGuard: all traffic encrypted, including same-site
  (unnecessary overhead, ~20-40% throughput reduction for intra-site)
- Disable WireGuard: no encryption anywhere, including cross-site
  (unacceptable for untrusted transit)

**Resolution for multi-site with Cilium:** Disable Cilium WireGuard for
intra-site traffic. Use wirescale-agent's cross-site WireGuard gateways
(as described in ROUTABLE-PREFIX.md Section 9) for inter-site
encryption. This is the hybrid model:

```
Intra-site:  Cilium native routing, no encryption (line rate)
Cross-site:  Wirescale gateway WireGuard (site-to-site encryption)
```

This means wirescale-agent still runs on gateway nodes even with Cilium,
managing `wg0` for cross-site peering independently of Cilium's
`cilium_wg0`.

---

## 6. IPv4 Compatibility: The Critical Gap

### Cilium's IPv4 Limitations in IPv6-Only Clusters

Cilium provides:
- **NAT46x64 gateway**: A stateful, gateway-centric NAT64. Traffic
  destined for `64:ff9b::/96` must be routed to a designated gateway
  node. The gateway performs stateful IPv6-to-IPv4 translation.
- **No DNS64**: Requires external DNS64 (CoreDNS `dns64` plugin or
  Cloudflare/Google DNS64 resolvers).
- **No CLAT**: No per-pod IPv4 address. Pods cannot bind to IPv4
  sockets, cannot connect to IPv4 addresses using IPv4 API calls, and
  cannot use IPv4-only libraries or applications.

### Why CLAT Matters

Without CLAT, applications that call `connect("93.184.216.34", 80)`
using an IPv4 socket will fail. DNS64 only helps if the application
uses `getaddrinfo()` and then connects to the returned AAAA record.
Applications that hardcode IPv4 addresses, use IPv4-only libraries, or
make raw IPv4 socket calls will break.

CLAT provides a real IPv4 address (`100.64.N.P`) on a `clat0` TUN
interface in each pod. The IPv4 stack works exactly as on a dual-stack
host. This is transparent to applications -- they see and use a normal
IPv4 address.

### With Cilium: Wirescale Provides CLAT + NAT64 + DNS64

The wirescale-agent continues to run on every node, but with a reduced
role:

```
wirescale-agent responsibilities (with Cilium):
  1. Create clat0 TUN interface in each pod's netns
  2. Assign CLAT IPv4 address (100.64.N.P)
  3. Install IPv4 default route via clat0 in pod
  4. Run CLAT eBPF translation on pod veth (TC hook)
  5. Run NAT64 eBPF translation on nat64 interface
  6. DNS64: ensure CoreDNS has dns64 plugin configured

NOT responsible for (Cilium handles):
  - veth/netkit creation (Cilium CNI does this)
  - IPv6 address assignment (Cilium IPAM does this)
  - WireGuard peer management (Cilium agent does this)
  - Policy enforcement (Cilium eBPF does this)
  - Host route installation (Cilium CNI does this)
```

### eBPF Hook Coexistence

Both Cilium and Wirescale attach TC eBPF programs to the pod's
host-side veth. This works because the `clsact` qdisc supports
multiple programs in a priority chain:

```
Pod veth host-side:
  TC egress chain:
    prio 1: Cilium policy enforcement (lxc program)
    prio 2: Wirescale CLAT IPv4->IPv6 translation

  TC ingress chain:
    prio 1: Wirescale CLAT IPv6->IPv4 translation (return path)
    prio 2: Cilium policy enforcement
```

The CLAT program only acts on IPv4 packets (from `clat0`). Cilium's
programs only act on IPv6 packets (from `eth0`). The two do not
conflict because they operate on different packet types.

**Caveat with netkit:** If Cilium uses netkit (Linux 6.8+) instead of
veth, the eBPF attachment model changes. Wirescale's CLAT program must
attach to the netkit device's TC hook rather than a veth. This requires
Wirescale to detect the device type and adapt. Netkit TC hooks function
identically to veth TC hooks from the eBPF program's perspective.

### Comparison: NAT64 Architectures

| Property | Wirescale NAT64 | Cilium NAT46x64 |
|----------|----------------|-----------------|
| Deployment | Per-node (every node translates) | Gateway (dedicated node(s)) |
| Translation | Stateless SIIT (eBPF) | Stateful conntrack (eBPF) |
| Latency | Local to the node (~50-100 ns) | Extra hop to gateway node |
| Bottleneck | None (distributed) | Gateway node throughput |
| Failure mode | Node-local (isolated) | Gateway failure = no IPv4 egress |
| Configuration | Automatic (agent creates nat64 iface) | Helm flag + designated gateway |

Wirescale's per-node NAT64 is architecturally superior for production
deployments. With Cilium as CNI, continue using Wirescale's NAT64
engine rather than Cilium's gateway NAT46x64.

---

## 7. Policy Enforcement

### Cilium Replaces Wirescale's Policy Engine

With Cilium, the entire policy enforcement stack changes:

| Aspect | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| CRD | WirescalePolicy | CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy |
| Enforcement | TC eBPF on veth | TC eBPF on lxc/netkit |
| L3/L4 | Yes | Yes |
| L7 (HTTP, gRPC) | No | Yes (via Envoy proxy) |
| FQDN egress | No | Yes (via DNS proxy) |
| Identity source | BPF maps (IP -> identity_id) | ipcache BPF map (IP -> numeric identity) |
| Map update | Shadow map + atomic swap | Incremental BPF map updates |
| Default posture | Deny-by-default | Deny-by-default when any policy selects a pod |
| Time-bounded access | WirescaleAccessGrant CRD | Not built-in (requires external tooling) |

### What Cilium Adds

**L7 policy:** Cilium can inspect HTTP methods/paths, gRPC services,
Kafka topics, and DNS queries. This is done by redirecting matching
flows through an Envoy proxy sidecar on each node:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-l7-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web-frontend
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/.*"
              - method: "POST"
                path: "/api/v1/orders"
```

**FQDN-based egress:** Cilium intercepts DNS queries via its DNS proxy
and dynamically allows connections to resolved IPs:

```yaml
egress:
  - toFQDNs:
      - matchName: "api.stripe.com"
      - matchPattern: "*.googleapis.com"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
```

### What Cilium Loses

**Time-bounded access grants:** Wirescale's `WirescaleAccessGrant` CRD
provides temporary, approval-gated access with automatic expiry. Cilium
has no equivalent. For environments that need this, either:
- Continue using WirescaleAccessGrant as a CRD that generates
  CiliumNetworkPolicy objects (controller translates)
- Use external policy automation (OPA/Gatekeeper with time-based rules)

**ServiceAccount selectors:** Wirescale's `serviceAccountSelector` field
in WirescalePolicy allows selecting source pods by ServiceAccount name.
Cilium's equivalent is less direct -- you can label pods by SA and use
label selectors, or use `fromServiceAccounts` in CiliumNetworkPolicy
(available but less flexible).

### L7 + WireGuard Interaction Warning

Cilium routes L7-policy-matched traffic through Envoy. In Cilium
versions prior to 1.14.8/1.15.2, this traffic **bypassed WireGuard
encryption** (CVE-2024-28250). The fix requires careful configuration.
Deployments using both L7 policies and WireGuard encryption MUST verify
they run a patched Cilium version and that L7-proxied traffic is
correctly routed through `cilium_wg0`.

---

## 8. Identity Model

### Cilium Security Identities

Cilium's identity is a **32-bit numeric ID** derived from a pod's label
set. All pods with identical labels share the same identity number.
The identity is distributed cluster-wide via `CiliumIdentity` CRDs.

```
Pod "web-abc" in ns production:
  labels: {app: web, tier: frontend, version: v3}
  -> Cilium identity: 48291 (hash of label set)

Pod "web-def" in ns production (same labels):
  -> Cilium identity: 48291 (same -- shared identity)
```

### Wirescale Identity Model

Wirescale's identity is a structured tuple:

```
(namespace, serviceAccount, labels, node)
```

This is richer -- two pods with the same labels but different
ServiceAccounts or on different nodes have different identities.

### Comparison

| Property | Cilium Identity | Wirescale Identity |
|----------|----------------|-------------------|
| Granularity | Label set (coarse) | (NS, SA, labels, node) (fine) |
| Sharing | All pods with same labels share ID | Only exact tuple matches share ID |
| Node awareness | No (same ID regardless of node) | Yes (node is part of identity) |
| SA awareness | No (must encode as label) | Yes (native field) |
| Distribution | CiliumIdentity CRD + ipcache | WirescaleNode CRD + BPF maps |
| Lookup cost | O(1) hash map | O(log N) LPM trie + O(1) hash |

For most policy use cases, Cilium's label-based identity is sufficient.
Wirescale's node-aware identity is relevant when policies need to
distinguish "same pod on different nodes" (rare in practice).

---

## 9. Ingress Security for Internet-Routable Pods

### The Problem

With GUA pods (ROUTABLE-PREFIX.md), every pod is reachable from the
internet unless firewalled. Both architectures must solve this.

### Wirescale Standalone: XDP on eth0

Wirescale installs an XDP program on the physical NIC that drops
external-to-pod traffic at the driver level before it enters the kernel
network stack:

```
Physical NIC -> XDP program (14-26 Mpps/core)
  External src + local pod dst + no allow rule -> XDP_DROP
  (packet never reaches kernel stack)
```

### With Cilium: TC-based Host Firewall

Cilium's host firewall operates at the TC hook level (after XDP, after
the kernel processes the packet):

```
Physical NIC -> kernel stack -> TC hook -> Cilium host firewall
  (packet has already been processed by NIC driver and allocated sk_buff)
```

Cilium uses XDP on the physical NIC for Service load-balancing (DSR),
not for ingress firewalling. The host firewall is policy-driven via
`CiliumClusterwideNetworkPolicy` with `nodeSelector`:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: deny-external-to-pods
spec:
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/worker: ""
  ingress:
    - fromEntities:
        - cluster
        - health
```

### Comparison

| Property | Wirescale XDP Firewall | Cilium Host Firewall |
|----------|----------------------|---------------------|
| Hook point | XDP (driver level) | TC (after kernel stack entry) |
| Packet rate | 14-26 Mpps/core | 2-5 Mpps/core |
| DDoS protection | Yes (drops before sk_buff allocation) | Limited (packet already in kernel) |
| Per-pod granularity | Yes (checks dst against pod prefix) | Yes (via endpoint identity) |
| Configuration | Custom BPF map (WirescalePolicy-driven) | CiliumClusterwideNetworkPolicy |

### Recommendation for GUA Deployments

For internet-routable pods, the XDP ingress firewall from Wirescale
provides materially better DDoS protection. With Cilium as CNI,
wirescale-agent SHOULD continue to install its XDP program on `eth0`
for external-to-pod ingress filtering, complementing Cilium's per-pod
policy enforcement on veths.

The two do not conflict: XDP runs before TC. Packets dropped by XDP
never reach Cilium's hooks.

---

## 10. Observability and Audit

### Hubble Replaces Wirescale's Custom Audit

Hubble provides significantly richer observability than Wirescale's
custom BPF ring buffer:

| Capability | Wirescale Audit | Hubble |
|-----------|----------------|--------|
| L3/L4 flow events | Yes | Yes |
| L7 flow events (HTTP, DNS) | No | Yes |
| Multi-node aggregation | External log shipping | hubble-relay (built-in) |
| UI | None | hubble-ui |
| CLI | `kubectl wirescale flows` | `hubble observe` |
| Drop reasons | Policy ID only | 30+ detailed reason codes |
| Prometheus metrics | Custom (wirescale-agent) | Built-in (`hubble_*` metrics) |
| Overhead | Low (deny-only by default) | Higher (always-on tracing) |

### What Wirescale Audit Still Adds

Wirescale's audit design logs denies always and allows only when
`audit: true` is set per-policy. This is lower overhead than Hubble's
always-on tracing. For high-throughput environments where Hubble's CPU
cost is unacceptable, wirescale-agent can continue emitting targeted
audit events alongside Hubble.

### Recommended Configuration

- **Hubble**: Enable for development, staging, and debugging. Use
  hubble-relay for cluster-wide flow visibility.
- **Wirescale audit**: Enable for production security audit trail
  (deny-only logging with identity attribution).
- Both can run simultaneously without conflict (separate event
  pipelines).

---

## 11. Multi-Site and Multi-Cluster

### Cilium ClusterMesh vs Wirescale Cross-Site

| Property | Cilium ClusterMesh | Wirescale Cross-Site |
|----------|-------------------|---------------------|
| Requirement | Cilium on both ends | Standard WireGuard on both ends |
| Non-k8s peers | Not supported | WirescaleExternalPeer CRD |
| Encryption | Cilium WireGuard (all-or-nothing) | Selective (cross-site only) |
| Service discovery | Global services via ClusterMesh | MagicDNS cross-cluster resolution |
| Control plane | clustermesh-apiserver (etcd-backed) | Kubernetes CRDs + gateway peering |
| Identity sharing | CiliumIdentity synced across clusters | WirescaleNode CRDs exchanged |

### Multi-Site with Cilium

For multi-site deployments with Cilium as CNI:

```
Site A (Cilium)                     Site B (Cilium)
  Cilium: native routing             Cilium: native routing
  No Cilium WireGuard                No Cilium WireGuard
  |                                   |
  +-- wirescale gateway-a            +-- wirescale gateway-b
      wg0: peer gateway-b                wg0: peer gateway-a
      AllowedIPs: 3fff:0b::/48          AllowedIPs: 3fff:0a::/48
```

- Cilium handles intra-site: CNI, policy, observability
- Wirescale handles inter-site: WireGuard encryption between gateways
- The fabric routes cross-site traffic to gateway nodes
- Gateway nodes encrypt/decrypt and forward to/from the remote site

This is the cleanest separation: Cilium owns the site, Wirescale owns
the WAN.

### External Peers

Cilium ClusterMesh cannot connect non-Kubernetes nodes (developer
laptops, bare-metal servers, CI runners). Wirescale's
`WirescaleExternalPeer` CRD and `wirescale-join` agent continue to
serve this role, connecting through gateway nodes exactly as in the
standalone architecture.

---

## 12. Performance Comparison

### Same-Site Pod-to-Pod (Native IPv6, No Encryption)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| Interface type | veth | veth or netkit |
| eBPF programs in path | 1 (policy on veth) | 1 (policy on lxc/netkit) |
| Throughput (10G) | ~9.4 Gbps | ~9.4 Gbps (veth) / ~9.6 Gbps (netkit) |
| Latency | ~5 us | ~5 us (veth) / ~3 us (netkit) |

Netkit provides a small but measurable improvement over veth for
latency-sensitive workloads.

### Same-Site Pod-to-Pod (WireGuard Encrypted)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| WireGuard interface | wg0 | cilium_wg0 |
| Kernel module | Same | Same |
| GRO/GSO | Same | Same |
| Throughput (10G) | ~9.0 Gbps | ~9.0 Gbps |

Identical -- same kernel WireGuard module, same crypto, same
GRO/GSO amortization path.

### IPv4 via CLAT (Pod-to-Pod)

| Metric | Wirescale Standalone | With Cilium |
|--------|---------------------|-------------|
| CLAT eBPF programs | 2 (TC on each veth) | 2 (TC on each lxc/netkit) |
| Overhead vs pure IPv6 | ~5% | ~5% |
| Throughput (10G) | ~8.5 Gbps | ~8.5 Gbps |

CLAT performance is unchanged -- the eBPF translation cost is
independent of the CNI.

### IPv4 via NAT64 (Pod-to-External)

| Metric | Wirescale NAT64 | Cilium NAT46x64 |
|--------|----------------|-----------------|
| Translation location | Local node | Gateway node |
| Extra network hops | 0 | 1+ (to gateway) |
| Translation type | Stateless SIIT | Stateful conntrack |
| Per-packet cost | ~50-100 ns | ~100-200 ns + hop latency |
| Throughput (10G) | ~8.0 Gbps | Bottlenecked by gateway |
| Failure impact | Node-local | Cluster-wide IPv4 outage |

Wirescale's per-node stateless NAT64 is strictly better than Cilium's
gateway-centric stateful approach.

---

## 13. Component-by-Component Diff

### Full Comparison Table

| Component | Without Cilium | With Cilium | Delta |
|-----------|---------------|-------------|-------|
| **CNI binary** | wirescale-cni | Cilium CNI | Replaced |
| **Pod interface** | veth pair | veth or netkit | Upgraded (netkit on 6.8+) |
| **IPv6 IPAM** | wirescale-controller | Cilium operator (kubernetes mode) | Replaced |
| **Per-pod /128 routes** | wirescale-cni | Cilium CNI | Replaced |
| **WireGuard (intra-site)** | wirescale-agent `wg0` | Cilium agent `cilium_wg0` | Replaced |
| **WireGuard (cross-site)** | wirescale-agent `wg0` | wirescale-agent `wg0` (gateways only) | Reduced scope |
| **Selective encryption** | wirescale-agent eBPF encrypt_map | Not available in Cilium | Wirescale still needed |
| **L3/L4 policy** | wirescale-agent TC eBPF | Cilium TC eBPF | Replaced |
| **L7 policy** | Not available | Cilium + Envoy | Added |
| **FQDN egress** | Not available | Cilium DNS proxy | Added |
| **CLAT (per-pod IPv4)** | wirescale-agent | wirescale-agent | Unchanged |
| **NAT64** | wirescale-agent (per-node) | wirescale-agent (per-node) | Unchanged |
| **DNS64** | CoreDNS dns64 plugin | CoreDNS dns64 plugin | Unchanged |
| **XDP ingress firewall** | wirescale-agent on eth0 | wirescale-agent on eth0 | Unchanged |
| **Conntrack bypass** | nftables notrack (port 51820) | nftables notrack (port 51871) | Port changes |
| **Identity model** | (NS, SA, labels, node) tuple | Numeric ID from label set | Simplified |
| **Policy CRD** | WirescalePolicy | CiliumNetworkPolicy | Replaced |
| **Time-bounded access** | WirescaleAccessGrant | Not available | Wirescale still needed |
| **Observability** | Custom BPF ringbuf | Hubble | Replaced (richer) |
| **Bandwidth management** | Not available | Cilium EDT + BBR | Added |
| **External peers** | WirescaleExternalPeer | WirescaleExternalPeer | Unchanged |
| **Multi-cluster** | Gateway WG peering | Gateway WG peering (or ClusterMesh) | Option added |
| **Kernel sysctl tuning** | wirescale-agent | Cilium agent + wirescale-agent | Shared |

### Summary Scorecard

```
Functions moved to Cilium:          8  (CNI, IPAM, WG, policy, identity,
                                        routes, observability, bandwidth)
Functions retained by Wirescale:    6  (CLAT, NAT64, DNS64, XDP firewall,
                                        cross-site WG, external peers)
Functions added by Cilium:          3  (L7 policy, FQDN egress, bandwidth mgmt)
Functions lost:                     0  (time-bounded access can be adapted)
```

---

## 14. Architecture Diagram: With Cilium

```
+------------------------------------------------------------------+
|                        CONTROL PLANE                              |
|                                                                   |
|  +---------------------------+  +-----------------------------+   |
|  | Cilium operator           |  | wirescale-controller        |   |
|  | - IPAM (/64 allocation)   |  | (reduced scope)             |   |
|  | - CiliumNode management   |  | - NAT64/CLAT coordination   |   |
|  | - Identity allocation     |  | - Cross-site WG topology    |   |
|  +---------------------------+  | - WirescaleExternalPeer mgmt|   |
|                                 | - AccessGrant lifecycle     |   |
|  +---------------------------+  +-----------------------------+   |
|  | Kubernetes API Server     |                                    |
|  | CiliumNetworkPolicy CRDs  |                                    |
|  | WirescaleExternalPeer CRDs|                                    |
|  +---------------------------+                                    |
+------------------------------------------------------------------+
                              |
              CRD watch/update via kube API
                              |
+------------------------------------------------------------------+
|                         DATA PLANE (per node)                     |
|                                                                   |
|  +------------------------------------------------------------+  |
|  | Cilium agent                                                |  |
|  |  +----------------+ +----------------+ +------------------+ |  |
|  |  | CNI (lxc/nk)   | | cilium_wg0     | | Policy (TC eBPF) | |  |
|  |  | IPv6 addr, /128| | kernel WG      | | L3/L4 + L7 proxy | |  |
|  |  | routes, MTU    | | peer mgmt      | | FQDN egress      | |  |
|  |  +----------------+ +----------------+ +------------------+ |  |
|  |  +----------------+ +----------------+                      |  |
|  |  | Hubble         | | Bandwidth Mgr  |                      |  |
|  |  | flow events    | | EDT + BBR      |                      |  |
|  |  +----------------+ +----------------+                      |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  +------------------------------------------------------------+  |
|  | wirescale-agent (reduced scope)                             |  |
|  |  +----------------+ +----------------+ +------------------+ |  |
|  |  | CLAT Engine    | | NAT64 Engine   | | XDP Ingress FW   | |  |
|  |  | per-pod clat0  | | per-node eBPF  | | on eth0 (DDoS)   | |  |
|  |  | IPv4 via TUN   | | stateless SIIT | |                  | |  |
|  |  +----------------+ +----------------+ +------------------+ |  |
|  |  +------------------------------------------------------+  |  |
|  |  | Cross-Site WG (gateway nodes only)                    |  |  |
|  |  | wg0: site-to-site encryption, external peers          |  |  |
|  |  +------------------------------------------------------+  |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

---

## 15. Deployment Decision Matrix

### When to Use Cilium + Wirescale (Hybrid)

- You need **L7 policy** (HTTP path filtering, gRPC method control)
- You need **FQDN-based egress control** (allow only specific domains)
- You need **Hubble** for deep network observability
- You need **bandwidth management** (per-pod rate limiting)
- You are already running Cilium and want to add IPv4 compatibility
  to an IPv6-only cluster
- You want **netkit** performance improvements (Linux 6.8+)

### When to Use Wirescale Standalone

- You need **selective cross-site encryption** (line rate intra-site)
- You want **simpler operations** (one agent, one CNI, one policy CRD)
- You don't need L7 policy
- You want the **lowest possible overhead** (no Envoy, no Hubble)
- You need **time-bounded access grants** natively
- Your threat model requires **XDP-level ingress filtering** as the
  primary defense for internet-routable pods

### When to Use Cilium Alone (No Wirescale)

- Your cluster is **dual-stack** (IPv4 + IPv6) -- no need for CLAT/NAT64
- All applications are IPv6-native -- no IPv4 compatibility needed
- Single-site deployment -- no cross-site encryption needed
- No external non-k8s peers -- no need for WirescaleExternalPeer
- Cilium's all-or-nothing WireGuard encryption is acceptable

### Feature Matrix

| Requirement | Wirescale Only | Cilium Only | Cilium + Wirescale |
|-------------|:-:|:-:|:-:|
| IPv6 native routing | Yes | Yes | Yes |
| /64-per-host IPAM | Yes | Yes | Yes |
| Fabric-managed BGP | Yes | Yes | Yes |
| WireGuard encryption | Yes | Yes | Yes |
| Selective encryption (cross-site) | Yes | No | Yes (via Wirescale gateways) |
| CLAT (per-pod IPv4) | Yes | No | Yes |
| Per-node NAT64 | Yes | Gateway only | Yes (Wirescale NAT64) |
| DNS64 | Yes | External only | Yes |
| L3/L4 policy | Yes | Yes | Yes (Cilium) |
| L7 policy | No | Yes | Yes (Cilium) |
| FQDN egress | No | Yes | Yes (Cilium) |
| Time-bounded access | Yes | No | Yes (Wirescale) |
| XDP ingress firewall | Yes | No (TC-based) | Yes (Wirescale) |
| Hubble observability | No | Yes | Yes (Cilium) |
| Bandwidth management | No | Yes | Yes (Cilium) |
| External non-k8s peers | Yes | No | Yes (Wirescale) |
| ClusterMesh (k8s-to-k8s) | No | Yes | Yes (Cilium) |
| netkit (Linux 6.8+) | No | Yes | Yes (Cilium) |
