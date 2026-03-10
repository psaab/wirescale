# Wirescale: Network Security and Dynamic Access Control

> Zero-trust network security with identity-aware dynamic access control,
> centralized authentication/authorization via **wirescale-control** (the
> cluster-level Policy Decision Point), and decentralized enforcement via
> eBPF on every node (the Policy Enforcement Point).
>
> Status: security design and implementation plan. Unless explicitly marked as
> implemented, controls in this document should be treated as target behavior.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

**See also:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Core architecture (ULA overlay model)
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
- [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) -- Globally routable /64-per-host design
- [CILIUM-INTEGRATION.md](CILIUM-INTEGRATION.md) -- Architecture comparison with Cilium as CNI
- [CILIUM-SECURITY-GAPS.md](CILIUM-SECURITY-GAPS.md) -- Security isolation
  gaps in Cilium-only deployments and how Wirescale closes them

---

## Table of Contents

1. [Security Philosophy](#1-security-philosophy)
2. [Three-Tier Control Hierarchy](#2-three-tier-control-hierarchy)
3. [Identity Model](#3-identity-model)
4. [Hierarchical Trust Chain](#4-hierarchical-trust-chain)
5. [Dynamic Access Control Architecture](#5-dynamic-access-control-architecture)
6. [Policy Language and CRDs](#6-policy-language-and-crds)
7. [Enforcement Engine](#7-enforcement-engine)
8. [Node and Cluster Admission](#8-node-and-cluster-admission)
9. [Cross-Cluster Authentication](#9-cross-cluster-authentication)
10. [Key Lifecycle Management](#10-key-lifecycle-management)
11. [Mutual Authentication](#11-mutual-authentication)
12. [Audit and Observability](#12-audit-and-observability)
13. [Threat Model and Mitigations](#13-threat-model-and-mitigations)
14. [Implementation Details](#14-implementation-details)

---

## 1. Security Philosophy

### Zero-Trust with Central Authn/Authz, Decentralized Enforcement

Traditional network security draws a perimeter and trusts everything inside.
Wirescale follows the zero-trust model with a clear architectural split:
**authentication and authorization are centralized** at the cluster controller
(`wirescale-control`), while **enforcement is decentralized** at every node
(`wirescale-agent`) via eBPF and WireGuard. No node ever needs to know about
every pod in the fleet.

Core tenets:

- **Every inter-node packet is encrypted** -- WireGuard provides authenticated
  encryption (ChaCha20-Poly1305) for all traffic leaving a node. There is no
  "trusted zone."
- **Identity is cryptographic, not network-based** -- a pod's identity derives
  from its Kubernetes ServiceAccount, namespace, and labels, bound to the
  WireGuard key of the node it runs on. IP addresses are ephemeral identifiers,
  not trust anchors.
- **Policy is deny-by-default** -- no pod can communicate with another pod
  unless an explicit policy permits it. The default posture is full isolation.
- **Enforcement is distributed** -- every node enforces policy locally via
  eBPF. There is no central chokepoint that can be bypassed.
- **Central authority, minimal state** -- `wirescale-control` is the single
  authority for authentication, authorization, identity resolution, and policy
  compilation within a cluster. Nodes pull state on demand and cache only what
  they need for active flows. No node watches all pods across the fleet.
- **Control plane compromise does not expose data plane** -- the control plane
  only sees public keys and metadata. Private keys never leave node memory.
  A compromised control plane cannot decrypt mesh traffic.

Normative baseline:

- Inter-node data-plane traffic MUST be encrypted in full-mesh mode.
- Workload communication SHOULD default to deny and require explicit allow.
- Private WireGuard keys MUST remain node-local and MUST NOT be persisted in
  control-plane resources.
- Agents MUST authenticate to `wirescale-control` via mTLS before participating
  in the mesh.
- `wirescale-control` MUST validate node identity against the Kubernetes API
  before authorizing any peer connections or serving identity/policy data.
- Identity and policy responses from `wirescale-control` MUST be cached locally
  by agents and MUST be refreshed on TTL expiry.
- No agent MUST watch or receive state for pods that are not involved in active
  flows on that node.

### Layered Defense

```
Layer 0: Hierarchical Trust (global directory -> cluster CA -> node certs)
         - Three-tier certificate hierarchy
         - Cross-cluster trust via federated cluster CAs
         - Root of trust: global directory

Layer 1: Control-Plane Authentication (node-to-control)
         - mTLS or projected ServiceAccount tokens
         - Node identity validated against Kubernetes API
         - All control operations gated by node authentication

Layer 2: WireGuard Encryption (always on, non-negotiable)
         - All inter-node traffic encrypted
         - Cryptokey routing: only known peers can send/receive
         - Unknown sources silently dropped

Layer 3: eBPF Policy Enforcement (per-pod, per-packet)
         - L3/L4 filtering based on identity labels
         - Applied at the pod's veth interface
         - Deny-by-default posture

Layer 4: Dynamic Access Control (identity-aware)
         - Kubernetes-native identity (SA, namespace, labels)
         - Time-bounded access grants
         - Pull-based policy from control on demand

Layer 5: Audit Trail (attribution and forensics)
         - Connection logging with identity attribution
         - Policy decision logging
         - Key lifecycle events
         - Control-plane operation audit log
```

### PDP/PEP Architectural Split

The security architecture follows the classic Policy Decision Point / Policy
Enforcement Point separation, adapted for Kubernetes networking:

```
+------------------------------------------+
|   Policy Decision Point (PDP)            |
|   wirescale-control (per-cluster)        |
|                                          |
|   - Evaluates policy centrally           |
|   - Resolves identities authoritatively  |
|   - Compiles policy into BPF rules       |
|   - Authorizes peer establishment        |
|   - Federates with remote clusters       |
+------------------------------------------+
              |
              | gRPC (identity, policy, peer info)
              | Pull-based: nodes request what they need
              |
+------------------------------------------+
|   Policy Enforcement Point (PEP)         |
|   wirescale-agent (per-node)             |
|                                          |
|   - Enforces compiled rules in eBPF      |
|   - Caches identity for active flows     |
|   - Configures WireGuard peers locally   |
|   - Zero control-plane involvement in    |
|     steady-state packet forwarding       |
+------------------------------------------+
```

This split means:
- The PDP (controller) has the global view needed for correct policy evaluation.
- The PEP (agent) has the minimal state needed for line-rate enforcement.
- A node with 50 local pods communicating with 200 remote pods caches ~250
  identities, not 500,000 (the cluster total).

---

## 2. Three-Tier Control Hierarchy

Wirescale's security architecture is organized into three tiers. Each tier
has a distinct scope of knowledge and a specific role in authentication,
authorization, and enforcement.

### Tier 1: Global Directory (`wirescale-directory`)

The global directory is a lightweight, globally replicated service that serves
as the root of trust for cross-cluster authentication. It knows about
clusters, not about individual pods or nodes.

```
wirescale-directory:
  Stores:
    cluster_id -> {
      gateway_endpoints: [ip:port, ...],
      prefix_allocation: 3fff:c1::/48,
      cluster_CA_cert: <PEM>,
      metadata: { region, provider, labels }
    }

  Responsibilities:
    - Root of trust for cross-cluster authentication
    - Issues/validates cluster-level certificates
    - Maps cluster IDs to gateway endpoints and CA certs
    - Manages global prefix allocation

  Does NOT know about:
    - Individual pods or nodes
    - Per-pod identities or policies
    - Intra-cluster state of any kind
```

The global directory MUST be highly available and SHOULD be globally
replicated. Its data set is small (one entry per cluster) and changes
infrequently (cluster joins/leaves). It is not in the hot path for
any per-packet or per-flow operation.

### Tier 2: Cluster Controller (`wirescale-control`)

The cluster controller is the central authn/authz authority within a single
cluster. It knows all nodes and pods within its cluster but knows nothing
about the internal state of remote clusters.

```
wirescale-control (per-cluster, horizontally scalable):
  Stores:
    - All node registrations (public keys, endpoints, CIDRs)
    - All pod identities (IP -> namespace, SA, labels, node)
    - Compiled policy rules (per-node scoped)
    - Active peer relationships

  Responsibilities:
    - Central authn/authz authority within the cluster (PDP)
    - Identity resolution for local and cross-cluster queries
    - Policy compilation and distribution to agents
    - Peer authorization and key exchange brokering
    - Cross-cluster: queries global directory for remote cluster info,
      then queries remote cluster controller for specific identities

  Scalability:
    - Stateless replicas behind a load balancer
    - State derived from Kubernetes API (pods, policies, nodes)
    - Horizontally scalable: add replicas as cluster grows
```

### Tier 3: Node Agent (`wirescale-agent`)

The node agent is a per-node daemon with minimal state. It enforces policy
locally via eBPF and caches only what it needs for active flows.

```
wirescale-agent (per-node):
  Stores:
    - Identity cache: LRU with TTL, only active flows (BPF map)
    - Policy map: rules for local pods only (BPF map)
    - Peer cache: active WireGuard peers only (BPF map)
    - WireGuard private key: memory-only, never persisted

  Responsibilities:
    - Decentralized enforcement (PEP) via eBPF
    - On cache miss: queries local cluster controller
    - Registers local pod identities with controller
    - Configures WireGuard peers on demand

  MUST NOT:
    - Watch all pods across the fleet
    - Receive pushed state for pods not on this node
    - Store policy for remote pods it has no active flows with
```

### State Distribution: Old vs. New

| What | Old (O(N) Push) | New (Pull-Based) |
|------|-----------------|------------------|
| Identity state per node | O(all_pods_in_fleet) | O(active_flows) -- pull-based cache |
| Policy per node | Grows with cluster size | Local pods + cached remote rules |
| CRD watches per node | O(N) events/sec | O(1) -- own node only |
| Cross-cluster identity | Full sync | On-demand resolution, cached |
| Trust chain | Single cluster CA | Hierarchical: global dir -> cluster CA -> node certs |
| Node join cost | O(N) fan-out | O(1) registration with controller |

---

## 3. Identity Model

### What Is an Identity in Wirescale?

A Wirescale identity is the tuple:

```
(cluster_id, namespace, serviceAccount, labels, node)
```

This maps naturally to Kubernetes:
- **Cluster** -- which cluster the pod belongs to (for cross-cluster)
- **Namespace** -- isolation boundary
- **ServiceAccount** -- the pod's authenticated identity within RBAC
- **Labels** -- the pod's declared role (e.g., `app=frontend`, `tier=web`)
- **Node** -- the physical host, identified by its WireGuard public key

For intra-cluster communication, `cluster_id` is implicit.

### Numeric Identity

For BPF map efficiency, each unique identity tuple is assigned a compact
numeric identity by `wirescale-control`:

```
numeric_identity (u32) -> {
  cluster_id:       u16,
  namespace_id:     u16,
  serviceaccount_id: u16,
  label_hash:       u64,
  node_id:          u16,
  flags:            u16   // external_peer, system_pod, cross_cluster, etc.
}
```

The numeric identity is the key used in all BPF policy lookups. It is
assigned by the controller and communicated to agents via gRPC responses.

### Pull-Based Identity Resolution

Nodes do NOT receive pushed identity state for all pods. When a node sees
traffic from an unknown source:

```
Step 1: Check local identity cache (LRU, TTL-based BPF map)
        Cache hit:  O(1) map lookup (~30 ns) -> identity resolved
        Cache miss: continue to step 2

Step 2: Agent queries wirescale-control for identity
        gRPC request: "who owns IP X?"
        Latency: ~5-10 ms (gRPC round-trip to controller)

Step 3: Controller returns identity response:
        {
          pod_name:        "api-server-xyz",
          namespace:       "production",
          service_account: "api-sa",
          labels:          {"app": "api", "tier": "backend"},
          numeric_identity: 42,
          node_id:         3,
          ttl:             60s
        }

Step 4: Agent caches result in BPF map with TTL
        Subsequent packets hit cache directly (~30 ns)

Step 5: On TTL expiry, next access triggers background refresh
        Stale entries remain usable during refresh (fail-open for
        existing identities, not for unknown ones)
```

For cross-cluster identity resolution:

```
Step 1: Local cache miss (same as above)

Step 2: Agent queries local wirescale-control

Step 3: Controller recognizes IP belongs to remote cluster
        (prefix allocation from global directory)

Step 4: Controller queries remote cluster's controller via mTLS
        (controller-to-controller authenticated channel)

Step 5: Remote controller returns identity

Step 6: Local controller returns result to agent with TTL

Step 7: Agent caches result locally
```

### Cache Invalidation

Rather than broadcasting all identity changes to all nodes, the controller
uses targeted invalidation:

- When a pod identity changes (labels updated, pod recreated with same IP),
  the controller pushes an invalidation event ONLY to nodes that have that
  identity in their cache.
- The controller tracks which nodes have queried which identities (via the
  gRPC query log) and maintains a reverse index.
- Invalidation events are small (just the IP prefix and a "stale" marker)
  and targeted (not broadcast).
- On receiving an invalidation, the agent marks the cache entry as stale
  and re-queries on next access.

### Identity vs. IP Address

Policies reference identities (labels, namespaces, service accounts), not
IP addresses. This is essential because:

- Pod IPs are ephemeral and change on restart
- IP-based policies break during rolling deployments
- CLAT IPv4 addresses add a second address per pod
- NAT64 makes external IPv4 addresses appear as IPv6

The eBPF enforcement engine maintains a **reverse map** from IP to identity,
updated on demand as cache misses are resolved and refreshed on TTL expiry.

---

## 4. Hierarchical Trust Chain

### Overview

Wirescale uses a three-level certificate hierarchy that mirrors the three-tier
control hierarchy. This replaces the single-CA model with a federated approach
where each cluster is its own trust domain.

```
Level 1: Global Directory CA
         - Self-signed root (or externally rooted)
         - Issues cluster-level certificates
         - Validates cluster identity for cross-cluster operations

Level 2: Cluster CA (per-cluster)
         - Signed by global directory CA (or independently operated,
           registered with global directory)
         - Issues node and agent certificates
         - Managed by wirescale-control

Level 3: Node Certificates (per-node)
         - Signed by cluster CA
         - Used for mTLS between agent and controller
         - WireGuard keys are separate (not certificate-based)
```

### Level 1: Global Directory as Root of Trust

```
Global Directory CA:
  - Issues certificates to each cluster's CA
  - Maintains registry: cluster_id -> cluster_CA_cert
  - Cross-cluster authentication works by:
    1. Cluster-A presents its cluster cert to global directory
    2. Global directory validates cert, returns Cluster-B's CA cert
    3. Cluster-A's controller contacts Cluster-B's controller
    4. Both sides validate each other via their respective cluster CAs,
       which are both traceable to the global directory

  Trust properties:
  - No single CA signs everything (blast radius containment)
  - Cluster CA compromise affects only that cluster
  - Global directory CA rotation does not require re-issuing node certs
  - Clusters can operate independently if global directory is unreachable
    (existing cross-cluster sessions continue, new ones are delayed)
```

### Level 2: Cluster CA

```
Cluster CA (managed by wirescale-control):
  - Stored securely within the cluster (e.g., Kubernetes Secret with
    restricted RBAC, or external HSM/KMS)
  - Signs node certificates for agents joining the cluster
  - Signs controller certificates for inter-controller mTLS

  Certificate contents:
    Subject: CN=wirescale-agent-<node-name>, O=<cluster-id>
    SAN: DNS:<node-name>, IP:<node-ip>
    Issuer: CN=wirescale-cluster-ca, O=<cluster-id>
    Validity: configurable (default: 24 hours, auto-renewed)
    Extensions:
      - X509v3 Key Usage: Digital Signature, Key Encipherment
      - X509v3 Extended Key Usage: TLS Client Auth
```

### Level 3: Node-to-Control Authentication

```
Node-to-control authentication:
  Option A: mTLS with cluster CA-signed certificates
    - Agent presents certificate signed by cluster CA
    - Control validates certificate chain
    - Control extracts node identity from certificate subject

  Option B: Projected ServiceAccount tokens
    - Agent presents projected SA token to control
    - Control validates via Kubernetes TokenReview API
    - Control maps SA identity to node identity

  Both options:
    - Establish authenticated gRPC channel for all subsequent operations
    - Control MUST reject connections from unrecognized nodes
    - All identity queries, policy requests, and peer authorizations
      flow over this authenticated channel
```

### WireGuard Keys (Separate from Certificate Hierarchy)

WireGuard keys are NOT part of the certificate hierarchy. They are ephemeral
Curve25519 keypairs that are:

- Generated at agent boot from `/dev/urandom`
- Stored only in agent process memory (never persisted)
- Registered with `wirescale-control` over the authenticated gRPC channel
- Exchanged between nodes through the control plane
- Rotated automatically on a configurable schedule

The certificate hierarchy authenticates the control plane. WireGuard keys
authenticate the data plane. The two are linked by the control plane: a node
MUST be authenticated (via certificate or SA token) before its WireGuard
public key is accepted by the controller.

```
Trust chain for data-plane packets:
  Global dir CA -> Cluster CA -> Node cert (mTLS to control)
                                     |
                                     v
                              Control accepts WireGuard pubkey
                                     |
                                     v
                              WireGuard peer established
                                     |
                                     v
                              Packet decrypted (proves node identity)
                                     |
                                     v
                              IP -> Pod identity (from cache or control)
                                     |
                                     v
                              Policy evaluated -> ALLOW or DROP
```

---

## 5. Dynamic Access Control Architecture

### Overview

Static firewall rules are insufficient for Kubernetes. Pods are ephemeral,
deployments scale up/down, canary releases shift traffic. Wirescale
implements **dynamic access control** that recomputes enforcement rules
in real-time as the cluster state changes.

The key architectural principle: **the controller decides, the agent
enforces.** The controller is the Policy Decision Point (PDP) with a global
view of the cluster. The agent is the Policy Enforcement Point (PEP) with
only the rules it needs for local pods.

### Architecture

```
+---------------------------------------------------+
|      wirescale-control (HA, stateless replicas)    |
|                                                    |
|  Policy Compiler (PDP)                             |
|    |                                               |
|    | Watches (Kubernetes API):                     |
|    |   - WirescalePolicy CRDs                      |
|    |   - NetworkPolicy objects                     |
|    |   - Pod objects (labels, SA, namespace)        |
|    |   - Namespace objects (labels)                |
|    |                                               |
|    | On any change:                                |
|    |   1. Recompile affected policies              |
|    |   2. Push updates to subscribed agents        |
|    |      (ONLY nodes affected by the change)      |
|    |   3. Increment policy generation counter      |
|                                                    |
|  Identity Service                                  |
|    |   - Responds to "who owns IP X?" queries      |
|    |   - Maintains authoritative identity map       |
|    |   - Pushes targeted invalidation events        |
|                                                    |
|  Peer Broker                                       |
|    |   - Authorizes WireGuard peer establishment    |
|    |   - Returns remote public key and endpoint     |
|    |   - Enforces peering policies                  |
|                                                    |
|  Cross-Cluster Federator                           |
|    |   - Queries global directory for remote info   |
|    |   - Establishes mTLS to remote controllers     |
|    |   - Proxies cross-cluster identity resolution  |
+---------------------------------------------------+
             |                        |
    gRPC policy stream       gRPC identity/peer queries
             |                        |
+---------------------------------------------------+
|      wirescale-agent (per node, PEP)               |
|                                                    |
|  Authenticates to control at startup (mTLS)        |
|                                                    |
|  Policy Enforcer                                   |
|    |                                               |
|    | Subscribes to policy stream from control       |
|    | (receives ONLY rules for local pods)           |
|    |                                               |
|    | On update:                                    |
|    |   1. Parse compiled rule set                  |
|    |   2. Update BPF maps atomically              |
|    |   3. New packets see new rules immediately    |
|    |   4. Report generation ack to control         |
|                                                    |
|  Identity Cache                                    |
|    |   - BPF LPM trie with TTL-based entries       |
|    |   - Queries control on cache miss             |
|    |   - Background refresh on TTL expiry          |
|    |   - Receives targeted invalidation events      |
|                                                    |
|  Peer Manager                                      |
|    |   - Requests peer info from control on demand |
|    |   - Configures WireGuard peers locally        |
|    |   - Garbage-collects idle peers               |
+---------------------------------------------------+
```

### Policy Compilation Model

Policies are compiled from high-level identity-based rules into low-level
BPF map entries. This compilation happens in `wirescale-control` (the PDP),
not in the agent, for three reasons:

1. **Global view:** Control sees all pods across all nodes. It can resolve
   `podSelector` and `namespaceSelector` against the full cluster state.
2. **Atomicity:** A compiled rule set is applied as a single BPF map swap
   (see [Enforcement Engine](#7-enforcement-engine)). No partial updates.
3. **Per-node scoping:** Each node receives ONLY rules relevant to pods
   it hosts. A node with 50 local pods gets ~50 pods' worth of rules,
   not the full cluster policy set.

### On-Demand Policy Evaluation for Remote Identities

When a local pod needs to communicate with a remote identity that is not
yet covered by a cached rule:

```
1. Agent encounters a policy lookup miss for a (src_identity, dst_identity)
   pair
2. Agent queries controller: "can my pod X talk to identity Y?"
3. Controller evaluates policy centrally using its global view
4. Controller returns:
   - allow/deny decision
   - Compiled BPF rule for caching
   - TTL for the cached rule
5. Agent installs rule in BPF policy map with TTL
6. Subsequent packets for this flow use the cached rule (~20 ns)
```

This means nodes never need the full policy set -- only rules for flows
they are actually handling.

### Recompilation Triggers

| Event | What Changes | Latency Target |
|-------|-------------|---------------|
| Pod created | Agent registers identity with control; policies selecting this pod's labels pushed to affected nodes | < 2s |
| Pod deleted | Identity removed from control; allow rules for this IP removed from affected nodes | < 2s |
| Pod labels changed | Identity changes in control; all policies re-evaluated against new labels | < 2s |
| Namespace labels changed | All namespace-scoped selectors re-evaluated | < 5s |
| WirescalePolicy created/updated/deleted | Full recompilation of affected rule sets, pushed to affected nodes | < 5s |
| NetworkPolicy created/updated/deleted | Full recompilation of affected rule sets, pushed to affected nodes | < 5s |
| Node joined/left | Peer registry updated; affected nodes notified | < 10s |

### Consistency Guarantees

- **Eventually consistent:** Policy changes propagate within the latency
  targets above. During propagation, some nodes MAY enforce the old policy
  while others enforce the new one. This is acceptable because:
  - The old policy was already secure (deny-by-default)
  - The new policy only adds or removes allow rules
  - Temporary skew windows are possible and MUST be monitored/alerted
- **Generation counter:** Each compiled policy set carries a monotonically
  increasing generation number. Agents report the generation they are
  enforcing. Control can detect and alert on stale agents.
- **Atomic BPF map swap:** BPF map updates on each agent are performed by
  writing to a shadow map and then atomically swapping the active map
  pointer. No packet ever sees a half-updated rule set.
- **Graceful degradation:** If `wirescale-control` is unreachable, agents
  continue enforcing the last-known policy. Existing WireGuard sessions
  and cached identities remain valid. Only new peer establishment and
  new identity resolution are delayed until control recovers.

---

## 6. Policy Language and CRDs

### Kubernetes NetworkPolicy (Native Support)

Wirescale targets full compatibility with the standard Kubernetes
NetworkPolicy API; implementation status is tracked in Section 14.
Existing policies work without modification:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
```

### WirescalePolicy (Extended)

WirescalePolicy extends NetworkPolicy with capabilities needed for a
mesh network:

#### Identity-Based Rules

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: api-access
  namespace: production
spec:
  # Target pods
  podSelector:
    matchLabels:
      app: api-server

  ingress:
    # Allow from pods by label
    - from:
        - podSelector:
            matchLabels:
              app: web-frontend
          namespaceSelector:
            matchLabels:
              env: production

      # Allow from specific ServiceAccount
        - serviceAccountSelector:
            names:
              - monitoring-sa
              - admin-sa
            namespaces:
              - kube-system
              - monitoring

      # Allow from external mesh peers
        - externalPeer:
            names:
              - office-vpn
              - ci-runner

      # Allow from remote clusters
        - clusterSelector:
            matchLabels:
              env: production
          podSelector:
            matchLabels:
              app: web-frontend

      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 8443
```

#### Time-Bounded Access

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: maintenance-window
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database

  # Time-bounded: only active during maintenance window
  schedule:
    start: "2026-03-05T02:00:00Z"
    end: "2026-03-05T06:00:00Z"
    recurring: "RRULE:FREQ=WEEKLY;BYDAY=TH"

  ingress:
    - from:
        - serviceAccountSelector:
            names: [dba-sa]
            namespaces: [maintenance]
      ports:
        - protocol: TCP
          port: 5432
```

#### Egress Control with FQDN

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: external-api-access
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service

  egress:
    # Allow HTTPS to specific external services
    - to:
        - fqdn:
            matchPatterns:
              - "api.stripe.com"
              - "*.googleapis.com"
      ports:
        - protocol: TCP
          port: 443

    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

#### Default Deny with Explicit Allow

```yaml
# Namespace deny baseline (order-independent under additive policy semantics)
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}   # all pods
  policyTypes:
    - Ingress
    - Egress
  # No ingress/egress rules = deny all

---
# Then allow specific flows
apiVersion: wirescale.io/v1alpha1
kind: WirescalePolicy
metadata:
  name: allow-web-to-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
      ports:
        - protocol: TCP
          port: 8080
```

### WirescaleAccessGrant (Dynamic, Time-Bounded)

For temporary access grants (debugging, incident response):

```yaml
apiVersion: wirescale.io/v1alpha1
kind: WirescaleAccessGrant
metadata:
  name: debug-session-12345
  namespace: production
spec:
  # Who is requesting access
  requestor:
    externalPeer: dev-laptop
    # OR
    serviceAccount:
      name: debugger-sa
      namespace: debug-tools

  # What they can access
  target:
    podSelector:
      matchLabels:
        app: failing-service
    ports:
      - protocol: TCP
        port: 8080
      - protocol: TCP
        port: 9090    # debug/metrics port

  # Time bounds (mandatory for access grants)
  duration: 2h
  # OR explicit window:
  # notBefore: "2026-03-02T14:00:00Z"
  # notAfter: "2026-03-02T16:00:00Z"

  # Approval required?
  approval:
    required: true
    approvers:
      - user: oncall@example.com
      - group: platform-team

status:
  state: approved          # pending | approved | denied | expired | revoked
  approvedBy: oncall@example.com
  approvedAt: "2026-03-02T14:05:00Z"
  expiresAt: "2026-03-02T16:05:00Z"
  revokedAt: null
```

`wirescale-control` watches `WirescaleAccessGrant` objects and:
1. Validates the time bounds
2. Checks approval status
3. Compiles a temporary allow rule and streams it to affected agents
4. Automatically revokes the rule at expiry (no human action needed)
5. Updates the status to `expired`

---

## 7. Enforcement Engine

### BPF Map Architecture

The enforcement engine uses several BPF maps per node. Maps 1, 2, 3,
and 6 incorporate cache semantics for the pull-based identity and peer
model:

```
Map 1: identity_cache (LPM trie, per-node)
  Key:   IP prefix (e.g., fd00:1d:3::7/128)
  Value: {
    identity_id: u32,      // index into identity table
    ttl_expiry: u64,       // ktime_ns when entry becomes stale
    generation: u32        // identity generation counter
  }
  On cache miss: packet queued, agent queries wirescale-control,
                 inserts result with TTL
  On TTL expiry: entry becomes stale, refresh triggered on next access

Map 2: identity_table (array, per-node)
  Key:   identity_id (u32)
  Value: {
    cluster_id: u16,
    namespace_id: u16,
    serviceaccount_id: u16,
    label_hash: u64,       // precomputed hash of label set
    node_id: u16,
    flags: u16             // external_peer, system_pod, cross_cluster, etc.
  }
  Entries are cached from wirescale-control, not globally distributed.
  Populated on demand as identity_cache entries are resolved.

Map 3: policy_map (hash, per-node)
  Key:   {
    src_identity: u32,
    dst_identity: u32,
    dst_port: u16,
    protocol: u8,
    pad: u8
  }
  Value: {
    action: u8,            // ALLOW=1, DROP=0, LOG=2
    flags: u8,             // audit, rate-limit
    policy_id: u16,        // for audit trail
    generation: u32        // policy generation counter
  }
  Only contains rules for LOCAL pods (received from control).
  On-demand rules for remote identities cached with TTL.

Map 4: policy_map_shadow (same structure as policy_map)
  Used for atomic swap during policy updates.

Map 5: active_map_selector (array, 1 entry)
  Key:   0
  Value: 0 or 1 (which policy_map is active)

Map 6: peer_cache (hash, per-node)
  Key:   destination /64 prefix
  Value: {
    wg_peer_index: u32,    // WireGuard peer index
    last_used_ts: u64,     // last packet timestamp (ktime_ns)
    ttl_expiry: u64        // peer TTL for garbage collection
  }
  Used to track active WireGuard peers for GC.
  Idle peers (no traffic beyond TTL) are candidates for removal.

Map 7: connection_log (ringbuf, per-node)
  Used for async audit event delivery to userspace.
```

### eBPF Program (TC on Pod veth)

Every pod's host-side veth has a TC eBPF program attached. The program
runs on both ingress (packets entering the pod) and egress (packets
leaving the pod):

```c
// Pseudocode for the enforcement program
SEC("tc/ingress")
int wirescale_policy(struct __sk_buff *skb) {
    // 1. Parse packet headers
    struct iphdr *ip4;
    struct ipv6hdr *ip6;
    __u16 dst_port;
    __u8 protocol;
    parse_headers(skb, &ip4, &ip6, &dst_port, &protocol);

    // 2. Determine source IP
    __u128 src_ip = ip6 ? ip6->saddr : map_v4_to_v6(ip4->saddr);

    // 3. Look up source identity in cache
    struct identity_entry *src_entry =
        bpf_map_lookup_elem(&identity_cache, &src_ip);
    if (!src_entry) {
        // Cache miss: notify agent, queue or drop
        emit_cache_miss_event(skb, src_ip);
        return TC_ACT_SHOT;  // Unknown source = drop
    }

    // 3a. Check TTL -- stale entries still used (fail-open for
    //     existing identities), agent refreshes asynchronously
    if (src_entry->ttl_expiry < bpf_ktime_get_ns())
        emit_ttl_refresh_event(skb, src_ip);

    struct identity *src_id =
        bpf_map_lookup_elem(&identity_table, &src_entry->identity_id);
    if (!src_id)
        return TC_ACT_SHOT;

    // 4. Look up destination identity (this pod)
    __u128 dst_ip = ip6 ? ip6->daddr : map_v4_to_v6(ip4->daddr);
    struct identity_entry *dst_entry =
        bpf_map_lookup_elem(&identity_cache, &dst_ip);

    // 5. Check policy
    int active = bpf_map_lookup_elem(&active_map_selector, &zero);
    struct policy_map *pmap = active ? &policy_map : &policy_map_shadow;

    struct policy_key key = {
        .src_identity = src_entry->identity_id,
        .dst_identity = dst_entry ? dst_entry->identity_id : 0,
        .dst_port = dst_port,
        .protocol = protocol,
    };

    struct policy_value *decision = bpf_map_lookup_elem(pmap, &key);

    // 6. Default deny
    if (!decision || decision->action == DROP) {
        // Log drop event to ringbuf
        emit_audit_event(skb, src_id, dst_entry, DENY);
        return TC_ACT_SHOT;
    }

    // 7. Allow (with optional audit)
    if (decision->flags & AUDIT)
        emit_audit_event(skb, src_id, dst_entry, ALLOW);

    return TC_ACT_OK;
}
```

### Atomic Policy Update

When the agent receives a new compiled policy set from `wirescale-control`
via the gRPC policy stream:

```
1. Write all new entries to policy_map_shadow
2. Memory barrier (bpf_map_update_elem is atomic per-entry)
3. Swap active_map_selector: 0 -> 1 (or 1 -> 0)
4. All subsequent packets use the new map
5. Drain old map entries asynchronously
```

This ensures no packet ever sees a partially updated policy. The swap is
a single atomic write to a 1-entry array map.

### Performance

| Operation | Cost | Notes |
|-----------|------|-------|
| Identity lookup (LPM trie, cache hit) | O(log prefix_len) ~30 ns | LPM trie for CIDR matching |
| Identity lookup (cache miss) | ~5-10 ms | gRPC round-trip to control |
| Policy lookup (hash) | O(1) ~20 ns | BPF hash map, pre-hashed key |
| Total per-packet overhead (cached) | ~50-80 ns | << WireGuard crypto cost |
| Map update (full swap) | ~1 ms for 10,000 entries | Non-blocking to packet path |

The policy enforcement overhead is negligible compared to WireGuard
encryption (~150-300 ns amortized). It does not affect line-rate
performance. Cache misses incur a one-time gRPC latency penalty; steady-
state traffic operates entirely from local BPF maps with no control-plane
involvement. See [PERFORMANCE.md](PERFORMANCE.md) for detailed analysis.

---

## 8. Node and Cluster Admission

### Node Admission (Within a Cluster)

A new node joins the mesh through this sequence:

```
1. Node boots, kubelet registers with API server
2. wirescale-agent starts (DaemonSet)
3. Agent generates WireGuard keypair (memory-only)
4. Agent authenticates to wirescale-control:
   - Presents mTLS certificate (signed by cluster CA) or projected SA token
   - Control validates against Kubernetes API:
     - Is this a valid, registered node?
     - Is the agent ServiceAccount authorized?
     - Does the presented identity match the connecting source?

5. Control admits the node:
   - Public key and endpoint stored in control's peer registry
   - Pod CIDRs allocated (or confirmed from Kubernetes node spec)
   - Node is now discoverable by other nodes via control

6. Other nodes discover the new node on demand:
   - When node-A needs to reach a pod on the new node,
     agent-A queries control for peer info
   - Control returns public key, endpoint, AllowedIPs
   - Agent-A configures WireGuard peer locally

7. NO global fan-out
   - O(1) registration instead of O(N) fan-out
   - Nodes that never communicate with the new node
     never learn about it
```

### Cluster Admission (Into the Global Directory)

A new cluster joins the global directory:

```
1. Cluster operator generates cluster CA keypair
2. Cluster operator requests registration with global directory:
   - Presents cluster CA certificate
   - Provides: gateway endpoints, requested prefix allocation, metadata
3. Global directory validates the request:
   - Authenticates the cluster operator (out-of-band or via admin API)
   - Checks prefix allocation does not conflict
   - Signs cluster CA certificate (or records it as a trusted CA)
4. Global directory registers the cluster:
   - cluster_id -> {gateway_endpoints, prefix, CA_cert, metadata}
5. Cluster is now discoverable by other clusters
6. wirescale-control starts: connects to global directory for
   cross-cluster operations
```

### Node Revocation

When a node must be removed (compromised, decommissioned):

```
Option A: Graceful removal
  1. kubectl delete node <name>
  2. Control removes node from peer registry
  3. Any node that queries for the removed node gets "not found"
  4. Existing WireGuard sessions time out (rekey timer)
  5. Much faster than CRD propagation at scale

Option B: Emergency revocation
  1. Admin marks node as revoked in control (or deletes node object)
  2. Control immediately rejects all peer queries for that node
  3. Control pushes revocation to nodes with active peers to that node
  4. Node's private key is useless -- no peer accepts it
  5. Existing sessions expire on WireGuard timer cadence
     (on the order of minutes)

Option C: Key rotation (suspected partial compromise)
  1. Agent on the suspect node generates new keypair
  2. Registers new public key with control
  3. Control updates peer registry, notifies nodes with active sessions
  4. Old key transitions through a short grace window, then becomes invalid
```

### Cluster Revocation

When a cluster must be removed from the federation:

```
1. Global directory admin removes cluster entry
2. Remote clusters querying the global directory for this cluster
   receive "not found"
3. Existing cross-cluster WireGuard sessions time out
4. No new cross-cluster connections can be established to/from
   the revoked cluster
5. Intra-cluster operations are unaffected (the cluster's own CA
   and controller continue to function independently)
```

### Node Attestation (Hardened Mode)

For high-security environments, `wirescale-control` can enforce additional
checks before admitting a node:

- **Node attestation:** TPM-based attestation, or signed kubelet
  certificates with verified chain of trust
- **Key rotation frequency:** Reject nodes whose key age exceeds a
  configurable threshold
- **Endpoint IP validation:** Node endpoint MUST be in a known subnet
- **Rate limiting:** Maximum 1 key change per hour to prevent abuse
- **Audit:** All admission decisions are logged with full context

These checks are evaluated by control at authentication time, eliminating
the need for a separate admission webhook. Control serves as both the
policy decision point and enforcement point for node admission.

---

## 9. Cross-Cluster Authentication

### Federated Trust Model

Cross-cluster authentication uses the hierarchical trust chain without
requiring a single global CA to sign everything. Each cluster maintains
its own CA; the global directory federates trust between them.

```
Cross-Cluster Authentication Flow:

Cluster-A wants to reach a pod in Cluster-B:

  1. Cluster-A's controller queries the global directory:
     "give me info for cluster-B"

  2. Global directory authenticates Cluster-A's controller:
     - Validates cluster certificate against registered CA
     - Returns: Cluster-B's CA cert, controller endpoints, prefix

  3. Cluster-A's controller establishes mTLS to Cluster-B's controller:
     - Presents its own cluster certificate
     - Validates Cluster-B's certificate against the CA cert
       received from the global directory
     - Both sides are now mutually authenticated

  4. Cluster-A's controller requests identity/peer info:
     - "What is the identity of pod at IP 3fff:c2:3::7?"
     - Cluster-B's controller evaluates cross-cluster policy
     - Returns identity info (or denies the request)

  5. Cluster-A's controller returns result to requesting agent:
     - Agent caches the cross-cluster identity with TTL
     - WireGuard peer established through cross-cluster gateway
```

### Cross-Cluster WireGuard Tunnels

Node-to-node WireGuard tunnels across clusters:

```
Node-A (Cluster-1) <-> Node-B (Cluster-2):

  Key exchange is mediated by the control plane:
  1. Agent-A requests cross-cluster peer info from Control-1
  2. Control-1 contacts Control-2 (via mTLS, authenticated by cluster CAs)
  3. Control-2 validates the request:
     - Is Cluster-1 authorized to peer with nodes in Cluster-2?
     - Are there policies allowing traffic between the relevant pods?
  4. Control-2 returns Node-B's public key and endpoint
  5. Control-1 returns this to Agent-A
  6. Agent-A configures WireGuard peer for Node-B
  7. Symmetric process: Control-2 informs Agent-B about Node-A

  No global PKI needed:
  - Cluster CAs are federated through the global directory
  - WireGuard keys are exchanged through the authenticated control plane
  - Each cluster independently manages its own keys
```

### Cross-Cluster Policy Enforcement

Cross-cluster traffic is subject to policy on BOTH sides:

```
Pod-A (Cluster-1) -> Pod-B (Cluster-2):

  Egress enforcement (Cluster-1, Node-A):
  1. eBPF checks local egress policy for Pod-A
  2. If remote identity not cached: agent queries Control-1
  3. Control-1 resolves identity via Control-2
  4. Policy evaluated against the resolved identity

  Ingress enforcement (Cluster-2, Node-B):
  1. Packet arrives via cross-cluster WireGuard tunnel
  2. eBPF checks ingress policy for Pod-B
  3. Source identity resolved from cache or via Control-2
  4. Policy evaluated against the resolved identity

  Both sides must ALLOW for the flow to succeed.
```

### Trust Properties

- **No single point of global compromise:** Compromising one cluster's CA
  does not affect other clusters. The attacker can only forge identities
  within the compromised cluster.
- **Global directory compromise:** An attacker controlling the global
  directory can introduce fraudulent cluster entries, potentially enabling
  man-in-the-middle attacks on cross-cluster connections. Mitigations:
  certificate pinning, out-of-band cluster CA verification, audit logging.
- **Cluster isolation:** A cluster can leave the federation at any time
  by removing its entry from the global directory. Intra-cluster operations
  are unaffected.
- **Selective federation:** Clusters can choose which other clusters they
  federate with. Cross-cluster policy can deny all traffic from specific
  clusters.

---

## 10. Key Lifecycle Management

### Key Generation

```
Event: Agent starts on node-N
  - Read /dev/urandom (256 bits)
  - Derive Curve25519 keypair
  - Private key: stored in agent process memory only
  - Public key: registered with wirescale-control via authenticated gRPC

Properties:
  - Private key survives agent restarts ONLY if the agent process
    stays alive (memory-only)
  - Agent restart = new keypair = brief handshake interruption
  - DaemonSet restart policy: Always (Kubernetes restarts crashed agents)
  - Control updates peer registry, notifies nodes with active sessions
```

### Automatic Key Rotation

The agent rotates keys on a configurable schedule (default: 24 hours):

```
1. Agent generates new keypair
2. Agent registers new public key with wirescale-control
   (old key remains valid for a grace period of 5 minutes)
3. Control updates peer registry
4. Nodes with active sessions to this node are notified via gRPC:
   - Add new key
   - Keep old key for grace period (handles in-flight handshakes)
5. After grace period: old key removed from registry
6. Old key is permanently invalid

Timeline:
  T+0s:   New key generated, registered with control
  T+2s:   Active peers notified (gRPC push)
  T+5s:   All active peers have new key
  T+300s: Old key removed from registry (grace period)

Key difference from push model:
  - Only nodes with ACTIVE sessions are notified
  - Nodes that never communicated with this node are unaffected
  - O(active_peers) notification instead of O(N) broadcast
```

### Cluster CA Rotation

```
Cluster CA rotation (managed by wirescale-control):
  1. New cluster CA keypair generated
  2. New CA registered with global directory (alongside old CA)
  3. Control begins issuing new node certificates signed by new CA
  4. Grace period: both old and new CA are trusted
  5. All nodes re-authenticate with new certificates
  6. Old CA removed from global directory
  7. Old CA is no longer trusted

  This process is transparent to agents -- they simply re-authenticate
  when their certificate is renewed.
```

### Emergency Key Revocation

```bash
# Revoke a node immediately
kubectl delete node compromised-node
# Control removes from peer registry; all queries return "not found"

# Revoke an external peer
kubectl wirescale revoke-peer compromised-laptop
# Control removes from registry, pushes revocation to active peers

# Revoke an entire cluster from the federation
wirescale-directory revoke-cluster compromised-cluster-id
# Global directory removes entry; cross-cluster connections fail

# Effect: Nodes with active sessions are notified within seconds.
# The revoked key can no longer establish WireGuard handshakes.
# Existing sessions time out within 2 minutes (WireGuard rekey timer).
# Nodes without active sessions never learn about the revocation
# (they never knew about the peer in the first place).
```

### Key Escrow

**There is no key escrow.** Private keys exist only in process memory.
This is a deliberate security decision:
- No backup of private keys = no risk of key exfiltration from backups
- Lost key = generate new key (the agent does this automatically on restart)
- No master key that can decrypt all traffic (forward secrecy via
  WireGuard's ephemeral keys per session)

---

## 11. Mutual Authentication

### WireGuard's Built-In Mutual Auth

Every WireGuard handshake is mutually authenticated:

```
Initiator (node A) -> Responder (node B):

1. A encrypts (A's static pubkey) with B's static pubkey
   B decrypts and learns A's identity

2. B responds with its ephemeral key and encrypted key confirmation
   (B's static key is proven via the Noise transcript, not sent as plaintext)

3. Both derive session keys from the shared secret

Result: Both sides prove they hold the private key
        corresponding to the public key registered with control
```

No certificates, no certificate authorities, no revocation lists for the
data plane. `wirescale-control` is the peer broker and key registry. Peer
removal from control's registry = revocation.

### Control-Mediated Peer Authorization

Before two nodes can establish a WireGuard session, control MUST authorize
the peering:

```
Node-A wants to reach a pod on Node-B:
  1. Agent-A queries control: "give me peer info for Node-B"
  2. Control checks:
     - Is Node-A authenticated and valid?
     - Is Node-B registered and not revoked?
     - Are there any policies that would allow traffic
       between pods on A and pods on B?
  3. If authorized, control returns:
     - Node-B's public key
     - Node-B's endpoint (IP:port)
     - AllowedIPs for Node-B
  4. Agent-A configures WireGuard peer locally
  5. WireGuard handshake proceeds (mutual auth via Noise protocol)

Benefits:
  - Nodes only learn about peers they actually need
  - Control can enforce peering policies (e.g., tenant isolation)
  - Revocation is immediate: control stops serving the peer info
  - No O(N) CRD watch storms on node join/leave
```

### Pod-Level Authentication

WireGuard authenticates nodes, not pods. Pod-level authentication is
provided by the identity system:

```
Pod A sends packet to Pod B:
  1. WireGuard guarantees the packet came from node-A
     (cryptographic proof via decryption)
  2. Node-A guarantees Pod A has IP fd00:1d:1::5
     (only kubelet on node-A can assign this IP)
  3. wirescale-agent resolves fd00:1d:1::5 = pod "web-xyz"
     with identity (production, web-sa, app=web)
     (from local cache or via control query)
  4. Policy engine checks: is (production, web-sa, app=web) allowed
     to reach Pod B on this port?

This is a transitive trust chain:
  WireGuard key -> Node -> kubelet -> Pod -> Identity -> Policy
```

### External Peer Authentication

External peers (non-Kubernetes nodes) authenticate via:

1. **Pre-auth key:** A one-time token generated by `wirescale-control`,
   delivered out-of-band (e.g., via `kubectl wirescale generate-key`).
   The external peer presents this token during initial registration.

2. **Key exchange:** The external peer's WireGuard public key is
   registered with control's peer registry.

3. **Admin approval:** Control requires explicit approval before the
   external peer is authorized to establish sessions with mesh nodes.

4. **Ongoing auth:** After initial admission, the external peer is
   authenticated on every packet by its WireGuard key. No session tokens
   or cookies needed.

---

## 12. Audit and Observability

### Connection Logging

The eBPF enforcement program emits audit events via a BPF ring buffer.
The `wirescale-agent` reads from the ring buffer and writes structured logs:

```json
{
  "timestamp": "2026-03-02T14:23:45.123Z",
  "node": "worker-3",
  "action": "allow",
  "src": {
    "ip": "fd00:1d:1::5",
    "pod": "web-frontend-abc",
    "namespace": "production",
    "serviceAccount": "web-sa",
    "labels": {"app": "web", "version": "v3"},
    "node": "worker-1",
    "cluster": "us-east-1"
  },
  "dst": {
    "ip": "fd00:1d:3::12",
    "pod": "api-server-xyz",
    "namespace": "production",
    "serviceAccount": "api-sa",
    "labels": {"app": "api", "version": "v2"},
    "node": "worker-3",
    "cluster": "us-east-1"
  },
  "protocol": "TCP",
  "dstPort": 8080,
  "policyId": "allow-web-to-api",
  "policyGeneration": 42,
  "identitySource": "cache",
  "crossCluster": false
}
```

### Control-Plane Audit Events

`wirescale-control` emits structured audit logs for all control-plane
operations:

```json
{
  "timestamp": "2026-03-02T14:23:44.001Z",
  "component": "wirescale-control",
  "event": "peer_authorized",
  "requestor": "worker-1",
  "target": "worker-3",
  "details": {
    "public_key_fingerprint": "Xk3p...",
    "allowed_ips": ["fd00:1d:3::/64"],
    "authorization_latency_ms": 2
  }
}
```

```json
{
  "timestamp": "2026-03-02T14:23:44.500Z",
  "component": "wirescale-control",
  "event": "cross_cluster_identity_resolved",
  "requestor_cluster": "us-east-1",
  "target_cluster": "eu-west-1",
  "details": {
    "ip": "3fff:c2:3::7",
    "identity": "production/api-sa",
    "resolution_latency_ms": 45,
    "cached": false
  }
}
```

| Control-Plane Event | Logged | Notes |
|---------------------|--------|-------|
| Node authenticated | Always | mTLS handshake result, node identity |
| Node authentication failed | Always | Source IP, presented identity, failure reason |
| Peer authorized | Always | Requestor, target, allowed IPs |
| Peer authorization denied | Always | Requestor, target, denial reason |
| Identity query served | Configurable | IP queried, identity returned, cache status |
| Policy compiled and pushed | Always | Affected nodes, generation, rule count |
| Node admitted | Always | Node name, public key fingerprint |
| Node revoked | Always | Node name, revocation reason, active peer count |
| Access grant approved/expired | Always | Grant name, requestor, target, duration |
| Rate limit triggered | Always | Source node, query type, current rate |
| Cross-cluster query | Always | Source cluster, target cluster, query type |
| Cluster registered/revoked | Always | Cluster ID, action, operator identity |
| Identity invalidation pushed | Configurable | Target IP, affected nodes count |

### Data-Plane Audit Events

| Event | Logged By Default | Configurable |
|-------|------------------|-------------|
| Connection denied (policy drop) | Yes | Always on |
| Connection allowed (new flow) | No | Per-policy `audit: true` flag |
| Identity cache miss | Yes | Always on |
| Identity cache refresh (TTL) | No | Configurable |
| Policy update applied | Yes | Always on |
| WireGuard handshake failure | Yes | Always on |
| Cross-cluster flow | Yes | Always on |

### Prometheus Metrics

The `wirescale-agent` exposes metrics at `:9090/metrics`:

```
# WireGuard
wirescale_wireguard_peers_total{node="worker-3"} 15
wirescale_wireguard_rx_bytes_total{peer="worker-1"} 1073741824
wirescale_wireguard_tx_bytes_total{peer="worker-1"} 2147483648
wirescale_wireguard_last_handshake_seconds{peer="worker-1"} 45
wirescale_wireguard_handshake_failures_total{peer="worker-1"} 0

# Policy
wirescale_policy_generation{node="worker-3"} 42
wirescale_policy_rules_total{node="worker-3"} 1523
wirescale_policy_decisions_total{node="worker-3", action="allow"} 98234
wirescale_policy_decisions_total{node="worker-3", action="deny"} 127
wirescale_policy_update_latency_seconds{quantile="0.99"} 0.8

# Identity Cache
wirescale_identity_cache_size{node="worker-3"} 234
wirescale_identity_cache_hits_total{node="worker-3"} 987654
wirescale_identity_cache_misses_total{node="worker-3"} 42
wirescale_identity_cache_evictions_total{node="worker-3"} 18
wirescale_identity_cache_ttl_refreshes_total{node="worker-3"} 567
wirescale_identity_cache_invalidations_total{node="worker-3"} 12

# Peer Cache
wirescale_peer_cache_size{node="worker-3"} 15
wirescale_peer_cache_gc_total{node="worker-3"} 3
wirescale_peer_establishment_latency_seconds{quantile="0.99"} 0.012

# Control-Plane gRPC
wirescale_control_grpc_requests_total{method="GetIdentity"} 4523
wirescale_control_grpc_requests_total{method="GetPeerInfo"} 187
wirescale_control_grpc_requests_total{method="RegisterPod"} 234
wirescale_control_grpc_latency_seconds{method="GetIdentity", quantile="0.99"} 0.008
wirescale_control_grpc_errors_total{method="GetIdentity"} 0

# Cross-Cluster
wirescale_cross_cluster_queries_total{remote_cluster="eu-west-1"} 456
wirescale_cross_cluster_latency_seconds{remote_cluster="eu-west-1", quantile="0.99"} 0.045
wirescale_cross_cluster_errors_total{remote_cluster="eu-west-1"} 2

# NAT64
wirescale_nat64_translations_total{direction="v6_to_v4"} 45123
wirescale_nat64_translations_total{direction="v4_to_v6"} 44987
```

`wirescale-control` exposes metrics at `:9091/metrics`:

```
# Control operations
wirescale_control_nodes_registered{} 150
wirescale_control_identities_total{} 12345
wirescale_control_policy_compilations_total{} 890
wirescale_control_peer_authorizations_total{} 5678
wirescale_control_peer_authorization_denials_total{} 12
wirescale_control_identity_queries_total{} 45230
wirescale_control_policy_generation{} 42

# Cross-cluster operations
wirescale_control_cross_cluster_queries_total{remote_cluster="eu-west-1"} 456
wirescale_control_cross_cluster_identity_cache_size{} 1234
wirescale_control_cross_cluster_identity_cache_hits_total{} 3456
wirescale_control_federated_clusters_total{} 5

# gRPC server
wirescale_control_grpc_connections_active{} 150
wirescale_control_grpc_requests_total{method="GetIdentity"} 45230
wirescale_control_grpc_latency_seconds{method="GetIdentity", quantile="0.99"} 0.005

# Global directory
wirescale_directory_clusters_registered{} 5
wirescale_directory_queries_total{} 12345
wirescale_directory_ca_verifications_total{} 890
```

### Network Flow Visualization

The audit logs can be consumed by standard tools:

- **Hubble** (Cilium's flow observability) -- compatible log format
- **Grafana** -- dashboards for policy decisions, throughput, peer health,
  cache hit rates, control-plane latency, cross-cluster flows
- **Elasticsearch/Loki** -- searchable connection logs with identity attribution
- **kubectl wirescale flows** -- CLI for real-time flow watching:

```bash
$ kubectl wirescale flows -n production --from app=web --to app=api
TIMESTAMP           ACTION  SRC                 DST                 PORT  POLICY
14:23:45.123  ALLOW   web-frontend-abc    api-server-xyz      8080  allow-web-to-api
14:23:45.456  ALLOW   web-frontend-def    api-server-xyz      8080  allow-web-to-api
14:23:46.789  DENY    unknown-pod-ghi     api-server-xyz      8080  default-deny

$ kubectl wirescale flows --cross-cluster
TIMESTAMP           ACTION  SRC_CLUSTER  SRC                DST_CLUSTER  DST                PORT
14:24:01.123  ALLOW   us-east-1    web-frontend-abc   eu-west-1    api-server-xyz     8080
14:24:02.456  DENY    us-east-1    rogue-pod-xyz      eu-west-1    api-server-xyz     8080
```

---

## 13. Threat Model and Mitigations

### Threats and Responses

| # | Threat | Impact | Mitigation |
|---|--------|--------|-----------|
| T1 | Eavesdropping on inter-node traffic | Data exfiltration | WireGuard encryption (always on, ChaCha20-Poly1305) |
| T2 | Rogue node joins mesh | Unauthorized access to pods on peered nodes | Node admission via control (mTLS + Kubernetes API validation + optional attestation) |
| T3 | Compromised node | Full access to pods on that node + can impersonate them | Key revocation via control; blast radius limited to that node's pods; inter-node traffic from other nodes is still encrypted |
| T4 | API server compromise | Can modify policies, CRDs | Data plane traffic still encrypted (no private keys in API). Attacker can weaken policies but cannot passively decrypt. |
| T5 | wirescale-control compromise (T-CONTROL) | Can authorize fraudulent peers, serve wrong identities, weaken policies | Control has no private keys; cannot decrypt data-plane traffic. mTLS to nodes limits impersonation. Rate limiting and audit logging detect anomalies. See expanded analysis below. |
| T6 | Pod breakout (container escape) | Access to host network namespace | WireGuard encrypts cross-node traffic; attacker can only see traffic to/from pods on the same node. eBPF policies still enforce at the veth level. |
| T7 | DNS poisoning | Traffic misdirection | Harden resolver path and DNS integrity checks (design target). NAT64 prefix mapping remains deterministic when used. |
| T8 | DDoS against WireGuard endpoint | Service disruption | Rate limiting on handshake processing (WireGuard built-in cookie mechanism). XDP early drop on physical NIC. |
| T9 | Key exfiltration from node memory | Impersonation | Keys are ephemeral (auto-rotated). Forward secrecy per-session. Process memory is not persisted. |
| T10 | Replay attack | Traffic replay | WireGuard uses monotonic counters per session. Replayed packets are rejected. |
| T11 | Policy bypass via IP spoofing | Unauthorized access | WireGuard's cryptokey routing drops packets whose source doesn't match AllowedIPs. Node-level IPAM ensures only authorized CIDRs are routable. |
| T12 | Lateral movement after pod compromise | Escalation | Deny-by-default policy. Compromised pod can only reach explicitly allowed destinations. WirescaleAccessGrant provides time-limited escalation. |
| T13 | Identity cache poisoning (T-CACHE-POISON) | Wrong identity for IP, policy bypass | Short TTL on cached entries. Identity responses signed by control. Agent can cross-verify identity against node's WireGuard key (IP must come from correct node CIDR). See expanded analysis below. |
| T14 | DDoS against wirescale-control (T-CONTROL-DOS) | Nodes cannot establish new peers or resolve new identities | Cached peers and identities continue working. Stale entries remain usable during outage. Existing WireGuard sessions independent of control. Graceful degradation by design. See expanded analysis below. |
| T15 | Global directory compromise (T-DIRECTORY) | Fraudulent cluster entries, cross-cluster MITM | Certificate pinning for known clusters. Out-of-band CA verification. Audit logging on all directory operations. Intra-cluster operations unaffected. See expanded analysis below. |
| T16 | Cross-cluster identity forgery | Remote cluster serves fake identity | Dual-side policy enforcement (both clusters must allow). Short TTL on cross-cluster cache. Controller validates remote identity against known prefix allocation. |
| T17 | Cluster CA compromise | All nodes/pods in that cluster can be impersonated | Blast radius limited to the compromised cluster. Global directory can revoke the cluster. Other clusters are unaffected. CA rotation procedure restores trust. |

### Expanded Threat Analysis

**T-CONTROL: wirescale-control compromise**

If an attacker gains control of `wirescale-control`:

- **Can do:** Authorize fraudulent peer connections; serve incorrect identity
  mappings; weaken or modify compiled policies; deny service to legitimate
  nodes.
- **Cannot do:** Decrypt any data-plane traffic (no private keys in control);
  inject packets into existing WireGuard sessions (no session keys);
  impersonate a node to another node (WireGuard mutual auth is independent
  of control once the handshake completes).
- **Mitigations:**
  - Control runs as an HA deployment (stateless replicas) with restricted RBAC
  - mTLS between control and every agent limits blast radius
  - Rate limiting on peer authorization and identity queries
  - All control operations are audit-logged
  - Anomaly detection SHOULD alert on: mass peer authorizations, identity
    changes for stable pods, policy generation spikes
  - Recovery: rotate control's serving certificates, restart agents
    (new mTLS handshake), agents re-register with new control instance

**T-CACHE-POISON: Identity cache poisoning**

If an attacker can cause control to serve wrong identity for an IP:

- **Attack:** Compromised control returns identity-B for IP-A, allowing
  traffic that should be denied.
- **Mitigations:**
  - Short TTL on cache entries (configurable, default 60s) limits the
    window of exposure
  - Identity responses SHOULD be signed by control; agents MAY verify
    signatures before caching
  - Agents can cross-verify: the IP prefix MUST belong to the node CIDR
    that the WireGuard peer is authorized for. If control says IP fd00:1d:3::7
    belongs to a pod on node-1, but the packet arrived via node-3's
    WireGuard tunnel, the agent MUST reject the mapping.
  - Generation counters detect stale or replayed identity data

**T-CONTROL-DOS: DDoS against wirescale-control**

If control becomes unavailable:

- **Impact:** New peer establishment fails. New identity resolution fails.
  Policy updates stop.
- **What continues working:**
  - Existing WireGuard sessions are unaffected (sessions are independent
    of control after handshake)
  - Cached identities continue to resolve packets (stale entries used
    beyond TTL during outage)
  - Last-known policy continues to be enforced
  - Intra-node pod communication is unaffected
- **Degradation behavior:**
  - Agents MUST NOT remove cached entries when control is unreachable
  - Agents SHOULD extend TTL on existing entries during control outage
  - Agents MUST log control unavailability and expose it as a metric
  - New pods can still communicate with pods on the same node
  - New cross-node communication is delayed until control recovers

**T-DIRECTORY: Global directory compromise**

If an attacker gains control of the global directory:

- **Can do:** Register fraudulent clusters; serve wrong CA certificates for
  existing clusters; enable man-in-the-middle attacks on cross-cluster
  connections; deny cross-cluster connectivity.
- **Cannot do:** Affect intra-cluster operations (each cluster's CA and
  controller operate independently); decrypt any traffic (the directory
  only stores public CA certificates); directly control any cluster's
  nodes or pods.
- **Mitigations:**
  - Certificate pinning: clusters MAY pin known remote cluster CAs locally,
    detecting if the directory serves a different CA
  - Out-of-band verification: operators can verify cluster CA fingerprints
    through a side channel
  - Audit logging on all directory operations
  - The directory's data set is small and changes infrequently, making
    anomalies easier to detect
  - Recovery: restore directory from backup (small data set), re-verify
    all cluster CA entries

### Defense in Depth Stack

```
Attack surface reduced by:

1. IPv6-only underlay
   - No IPv4 attack surface on the wire
   - External IPv4 only reachable via controlled NAT64 path

2. Hierarchical trust (Layer 0)
   - Three-tier CA hierarchy limits blast radius
   - Cluster CA compromise affects only that cluster
   - Global directory compromise does not affect intra-cluster

3. Central authentication (Layer 1)
   - Every node authenticated via mTLS to control
   - Control validates against Kubernetes API
   - Unauthenticated nodes cannot join the mesh

4. WireGuard encryption (Layer 2)
   - All cross-node traffic authenticated + encrypted
   - Unknown keys silently dropped (no information leak)

5. Identity-based policy (Layer 3)
   - Pod identity, not IP, determines access
   - Survives pod restart, rescheduling, IP changes
   - Pull-based: minimal state, no global broadcast

6. Time-bounded access grants
   - Temporary access automatically expires
   - No forgotten firewall rules

7. Automatic key rotation
   - Limits window of compromise
   - No long-lived static credentials
   - Hierarchical: node keys, cluster CA, global CA

8. Graceful degradation
   - Control outage does not disrupt existing traffic
   - Cached state provides continuity
   - Data plane is self-sustaining once established

9. Cross-cluster isolation
   - Dual-side policy enforcement
   - Cluster revocation does not affect other clusters
   - Each cluster is an independent trust domain

10. Audit trail
    - Every denied connection logged
    - Every policy change logged
    - Every control-plane operation logged
    - Every cross-cluster operation logged
    - Attribution to pod identity, not just IP
```

---

## 14. Implementation Details

### Implementation Phases

This document covers the security design for hyperscale operation with
central authentication and authorization. The implementation order reflects
the transition from the push-based model to the pull-based model with
the three-tier control hierarchy.

**Phase 3a: wirescale-control Core**
- [ ] `wirescale-control` gRPC service (HA, stateless replicas)
- [ ] Cluster CA management (key generation, certificate issuance)
- [ ] Node authentication (mTLS with cluster CA certificates)
- [ ] Node authentication (projected ServiceAccount tokens)
- [ ] Identity service: pod registration and query API
- [ ] Peer broker: peer authorization and info serving
- [ ] Control-plane audit logging

**Phase 3b: Pull-Based Identity and Caching**
- [ ] BPF map architecture (identity_cache with TTL, peer_cache)
- [ ] TC eBPF program for pod veth (ingress + egress)
- [ ] Agent: identity cache with TTL-based eviction
- [ ] Agent: cache miss handling (gRPC query to control)
- [ ] Agent: background TTL refresh
- [ ] Agent: targeted invalidation event handling
- [ ] Agent: peer-on-demand establishment via control

**Phase 3c: Pull-Based Policy Enforcement**
- [ ] Control: policy compiler (NetworkPolicy -> BPF rules)
- [ ] Control: per-node policy scoping (only local pod rules)
- [ ] Control: on-demand policy evaluation for remote identity pairs
- [ ] Control: gRPC policy stream to subscribed agents
- [ ] Agent: gRPC policy subscription and BPF map update
- [ ] Atomic map swap for zero-downtime policy updates
- [ ] Graceful degradation during control outage

**Phase 3d: Extended Policy (WirescalePolicy CRD)**
- [ ] WirescalePolicy CRD definition and validation
- [ ] ServiceAccount selector support
- [ ] External peer selector support
- [ ] Cross-cluster selector support (`clusterSelector`)
- [ ] FQDN-based egress control (with DNS snooping for IP resolution)
- [ ] Time-bounded schedule support

**Phase 3e: Dynamic Access Grants**
- [ ] WirescaleAccessGrant CRD
- [ ] Approval workflow (status subresource)
- [ ] Automatic expiry (control reconciliation loop)
- [ ] CLI: `kubectl wirescale grant`

**Phase 3f: Audit and Observability**
- [ ] BPF ring buffer for connection events
- [ ] Agent: structured log output (JSON)
- [ ] Control: structured audit log output (JSON)
- [ ] Prometheus metrics exporter (agent and control)
- [ ] Cross-cluster audit events
- [ ] CLI: `kubectl wirescale flows`

**Phase 3g: Hardened Mode**
- [ ] Node attestation at control (TPM-based, pluggable)
- [ ] Key rotation schedule enforcement via control
- [ ] Anomaly detection (mass policy change alerting, identity churn)
- [ ] Rate limiting on control APIs
- [ ] Identity response signing
- [ ] Certificate pinning for cross-cluster connections

**Phase 3h: Global Directory and Cross-Cluster**
- [ ] `wirescale-directory` service (globally replicated)
- [ ] Global directory: cluster registration and CA management
- [ ] Global directory: prefix allocation management
- [ ] Control-to-control mTLS federation (via global directory)
- [ ] Cross-cluster identity resolution (controller-to-controller)
- [ ] Cross-cluster peer authorization (dual-side enforcement)
- [ ] Cross-cluster WireGuard tunnel establishment
- [ ] Cluster revocation via global directory
- [ ] Cluster CA rotation procedure

### RBAC Configuration

```yaml
# wirescale-agent ServiceAccount permissions (minimal scope)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wirescale-agent
rules:
  # Watch local pods for identity registration
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  # No CRD access needed -- all identity/policy/peer operations
  # go through wirescale-control via gRPC

---
# wirescale-control permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wirescale-control
rules:
  # Full access to wirescale CRDs
  - apiGroups: ["wirescale.io"]
    resources: ["*"]
    verbs: ["*"]
  # Read pods, namespaces, nodes for identity and policy compilation
  - apiGroups: [""]
    resources: ["pods", "namespaces", "nodes"]
    verbs: ["get", "list", "watch"]
  # Read network policies
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch"]
  # TokenReview for SA token validation
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
  # Manage cluster CA secret
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "update"]
    resourceNames: ["wirescale-cluster-ca"]
```

### Resource Overhead

| Component | CPU (idle) | CPU (1000 pods) | Memory |
|-----------|-----------|-----------------|--------|
| eBPF per-pod program | 0 | ~50 ns/packet | ~4 KB per veth |
| Identity cache (BPF) | 0 | 0 | ~128 bytes/entry |
| Policy map (BPF) | 0 | 0 | ~64 bytes/rule |
| Peer cache (BPF) | 0 | 0 | ~48 bytes/peer |
| Agent (gRPC client) | ~10 mcpu | ~50 mcpu | ~30 MB |
| Audit ring buffer | 0 | ~5 mcpu | 256 KB/node |
| Total agent overhead | ~15 mcpu | ~80 mcpu | ~40 MB |
| Control (per replica) | ~50 mcpu | ~200 mcpu | ~200 MB |
| Global directory | ~10 mcpu | N/A | ~50 MB |

The agent's resource footprint is minimal because it uses the pull-based
model: no CRD watches, no global identity distribution, no full policy
set. The agent only caches identities and rules for active flows.

The control replicas handle the global view and scale horizontally. Their
resource usage scales with cluster size, not per-node.

The global directory is lightweight because it only stores per-cluster
metadata (not per-pod or per-node state).
