# Wirescale: Network Security and Dynamic Access Control

> Zero-trust network security with identity-aware dynamic access control,
> inspired by Tailscale's ACL model and adapted for Kubernetes-native
> policy enforcement.

---

## Table of Contents

1. [Security Philosophy](#1-security-philosophy)
2. [Identity Model](#2-identity-model)
3. [Cryptographic Trust Chain](#3-cryptographic-trust-chain)
4. [Dynamic Access Control Architecture](#4-dynamic-access-control-architecture)
5. [Policy Language and CRDs](#5-policy-language-and-crds)
6. [Enforcement Engine](#6-enforcement-engine)
7. [Node Admission and Revocation](#7-node-admission-and-revocation)
8. [Mutual Authentication](#8-mutual-authentication)
9. [Key Lifecycle Management](#9-key-lifecycle-management)
10. [Audit and Observability](#10-audit-and-observability)
11. [Threat Model and Mitigations](#11-threat-model-and-mitigations)
12. [Implementation Details](#12-implementation-details)

---

## 1. Security Philosophy

### Zero-Trust, Enforced at Every Hop

Traditional network security draws a perimeter and trusts everything inside.
Wirescale follows the zero-trust model:

- **Every inter-node packet is encrypted** -- WireGuard provides
  authenticated encryption (ChaCha20-Poly1305) for all traffic leaving a
  node. There is no "trusted zone."
- **Identity is cryptographic, not network-based** -- a pod's identity
  derives from its Kubernetes ServiceAccount, namespace, and labels, bound
  to the WireGuard key of the node it runs on. IP addresses are ephemeral
  identifiers, not trust anchors.
- **Policy is deny-by-default** -- no pod can communicate with another pod
  unless an explicit policy permits it. The default posture is full isolation.
- **Enforcement is distributed** -- every node enforces policy locally via
  eBPF. There is no central chokepoint that can be bypassed.
- **Control plane compromise doesn't expose data plane** -- the control
  plane (CRDs, controller) only sees public keys and metadata. Private keys
  never leave node memory. A compromised API server cannot decrypt mesh
  traffic.

### Layered Defense

```
Layer 1: WireGuard Encryption (always on, non-negotiable)
         - All inter-node traffic encrypted
         - Cryptokey routing: only known peers can send/receive
         - Unknown sources silently dropped

Layer 2: eBPF Policy Enforcement (per-pod, per-packet)
         - L3/L4 filtering based on identity labels
         - Applied at the pod's veth interface
         - Deny-by-default posture

Layer 3: Dynamic Access Control (identity-aware)
         - Kubernetes-native identity (SA, namespace, labels)
         - Time-bounded access grants
         - Automatic policy recomputation on pod lifecycle events

Layer 4: Audit Trail (non-repudiation)
         - Connection logging with identity attribution
         - Policy decision logging
         - Key lifecycle events
```

---

## 2. Identity Model

### What Is an Identity in Wirescale?

A Wirescale identity is the tuple:

```
(namespace, serviceAccount, labels, node)
```

This maps naturally to Kubernetes:
- **Namespace** -- isolation boundary
- **ServiceAccount** -- the pod's authenticated identity within RBAC
- **Labels** -- the pod's declared role (e.g., `app=frontend`, `tier=web`)
- **Node** -- the physical host, identified by its WireGuard public key

### Identity Resolution

When a packet arrives at a node's WireGuard interface, the identity
resolution chain is:

```
Encrypted UDP datagram from [3fff::3]:51820
  |
  | WireGuard decrypts using peer's public key
  | (peer = node-3, verified cryptographically)
  v
Inner packet: src = fd00:ws:3::7
  |
  | wirescale-agent's identity cache:
  | fd00:ws:3::7 -> pod "api-server-xyz" in namespace "production"
  |                 serviceAccount: "api-sa"
  |                 labels: {app: api, tier: backend, version: v2}
  v
Identity resolved: production/api-sa [app=api, tier=backend]
  |
  | eBPF policy lookup against destination pod's allowed sources
  v
ALLOW or DROP
```

The identity cache is populated by watching Pod objects via the Kubernetes
API. When a pod is scheduled, its IP and identity are propagated to all
nodes within milliseconds via the informer/watch mechanism.

### Identity Propagation

```
Pod created on node-3:
  1. CNI assigns fd00:ws:3::7
  2. wirescale-agent on node-3 sees pod via kubelet watch
  3. Agent updates WirescaleIdentity map (BPF map on node-3)
  4. Agent updates WirescaleNode CRD with pod identity entry
  5. Controller sees CRD update, recompiles per-node policy
  6. All remote agents receive updated policy ConfigMaps
  7. Remote agents update their local BPF maps

Time from pod creation to policy enforcement: < 2 seconds
```

### Identity vs IP Address

Policies reference identities (labels, namespaces, service accounts), not
IP addresses. This is essential because:

- Pod IPs are ephemeral and change on restart
- IP-based policies break during rolling deployments
- CLAT IPv4 addresses add a second address per pod
- NAT64 makes external IPv4 addresses appear as IPv6

The eBPF enforcement engine maintains a **reverse map** from IP to identity,
updated in real-time as pods come and go.

---

## 3. Cryptographic Trust Chain

### Layer 1: Node-Level (WireGuard)

```
Node keypair (generated at boot, ephemeral):
  Private key: /dev/urandom -> memory-only (never persisted)
  Public key:  -> WirescaleNode CRD -> distributed to all peers

Trust anchor: Kubernetes RBAC
  - Only authenticated nodes with the wirescale-agent ServiceAccount
    can create/update WirescaleNode CRDs
  - RBAC policy: agents can only write their own node's CRD
  - Controller validates CRD updates (e.g., rejects key changes
    from a different node IP than expected)
```

### Layer 2: Pod-Level (Identity Binding)

```
Pod identity is established by:
  1. Kubernetes scheduler assigns pod to node
  2. kubelet creates pod with projected ServiceAccount token
  3. CNI assigns IP from node's allocated CIDR
  4. wirescale-agent binds: IP <-> (namespace, SA, labels, node)

The binding is authoritative because:
  - Only kubelet on node-N can create pods with IPs from node-N's CIDR
  - WireGuard guarantees packets from node-N's CIDR come from node-N
  - Therefore: src IP -> node (WireGuard) -> pod identity (agent)
```

### Layer 3: Policy Authority

```
Policy source of truth: Kubernetes API server
  - NetworkPolicy and WirescalePolicy CRDs
  - Protected by Kubernetes RBAC (who can write policies)
  - Controller compiles policies into per-node enforcement rules
  - Agent applies rules to BPF maps

Trust chain: API server RBAC -> Controller -> BPF maps -> packet decision
```

---

## 4. Dynamic Access Control Architecture

### Overview

Static firewall rules are insufficient for Kubernetes. Pods are ephemeral,
deployments scale up/down, canary releases shift traffic. Wirescale
implements **dynamic access control** that recomputes enforcement rules
in real-time as the cluster state changes.

### Architecture

```
+---------------------------------------------------+
|            wirescale-controller                    |
|                                                   |
|  Policy Compiler                                  |
|    |                                              |
|    | Watches:                                     |
|    |   - WirescalePolicy CRDs                     |
|    |   - NetworkPolicy objects                    |
|    |   - Pod objects (labels, SA, namespace)       |
|    |   - Namespace objects (labels)               |
|    |   - WirescaleNode CRDs (pod identity maps)   |
|    |                                              |
|    | On any change:                               |
|    |   1. Recompile all policies                  |
|    |   2. Generate per-node rule sets             |
|    |   3. Write to ConfigMap per node             |
|    |   4. Increment policy generation counter     |
+---------------------------------------------------+
                    |
        ConfigMap update (one per node)
                    |
+---------------------------------------------------+
|            wirescale-agent (per node)              |
|                                                   |
|  Policy Enforcer                                  |
|    |                                              |
|    | Watches own ConfigMap                         |
|    |                                              |
|    | On update:                                   |
|    |   1. Parse compiled rule set                 |
|    |   2. Update BPF maps atomically             |
|    |   3. New packets see new rules immediately   |
|    |   4. Report generation ack to controller     |
+---------------------------------------------------+
```

### Compilation Model

Policies are compiled from high-level identity-based rules into low-level
IP-based BPF map entries. This compilation happens in the controller, not
in the agent, for three reasons:

1. **Global view:** The controller sees all pods across all nodes. It can
   resolve `podSelector` and `namespaceSelector` against the full cluster.
2. **Atomicity:** A compiled rule set is applied as a single BPF map swap
   (see [Enforcement Engine](#6-enforcement-engine)). No partial updates.
3. **Auditability:** The compiled rules (ConfigMap) are a Kubernetes object
   with version history, enabling policy diff and audit.

### Recompilation Triggers

| Event | What Changes | Latency Target |
|-------|-------------|---------------|
| Pod created | New IP -> identity mapping; policies selecting this pod's labels update | < 2s |
| Pod deleted | IP -> identity removed; allow rules for this IP removed | < 2s |
| Pod labels changed | Identity changes; all policies re-evaluated against new labels | < 2s |
| Namespace labels changed | All namespace-scoped selectors re-evaluated | < 5s |
| WirescalePolicy created/updated/deleted | Full recompilation of affected rule sets | < 5s |
| NetworkPolicy created/updated/deleted | Full recompilation of affected rule sets | < 5s |
| Node joined/left | Peer list updated; WireGuard AllowedIPs reconfigured | < 10s |

### Consistency Guarantees

- **Eventually consistent:** Policy changes propagate within the latency
  targets above. During propagation, some nodes may enforce the old policy
  while others enforce the new one. This is acceptable because:
  - The old policy was already secure (deny-by-default)
  - The new policy only adds or removes allow rules
  - At no point is a pod "unprotected"
- **Generation counter:** Each compiled policy set carries a monotonically
  increasing generation number. Agents report the generation they're
  enforcing. The controller can detect and alert on stale agents.
- **Atomic BPF map swap:** BPF map updates on each agent are performed by
  writing to a shadow map and then atomically swapping the active map
  pointer. No packet ever sees a half-updated rule set.

---

## 5. Policy Language and CRDs

### Kubernetes NetworkPolicy (Native Support)

Wirescale fully implements the standard Kubernetes NetworkPolicy API.
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
# Deny all ingress/egress for the namespace (applied first)
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

The controller watches `WirescaleAccessGrant` objects and:
1. Validates the time bounds
2. Checks approval status
3. Compiles a temporary allow rule and distributes to agents
4. Automatically revokes the rule at expiry (no human action needed)
5. Updates the status to `expired`

---

## 6. Enforcement Engine

### BPF Map Architecture

The enforcement engine uses several BPF maps per node:

```
Map 1: identity_map (LPM trie, per-node)
  Key:   IP prefix (e.g., fd00:ws:3::7/128)
  Value: identity_id (u32, index into identity table)

Map 2: identity_table (array, per-node)
  Key:   identity_id (u32)
  Value: {
    namespace_id: u16,
    serviceaccount_id: u16,
    label_hash: u64,       // precomputed hash of label set
    node_id: u16,
    flags: u16             // external_peer, system_pod, etc.
  }

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

Map 4: policy_map_shadow (same structure as policy_map)
  Used for atomic swap during policy updates.

Map 5: active_map_selector (array, 1 entry)
  Key:   0
  Value: 0 or 1 (which policy_map is active)

Map 6: connection_log (ringbuf, per-node)
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

    // 3. Look up source identity
    struct identity *src_id = bpf_map_lookup_elem(&identity_map, &src_ip);
    if (!src_id)
        return TC_ACT_SHOT;  // Unknown source = drop

    // 4. Look up destination identity (this pod)
    __u128 dst_ip = ip6 ? ip6->daddr : map_v4_to_v6(ip4->daddr);
    struct identity *dst_id = bpf_map_lookup_elem(&identity_map, &dst_ip);

    // 5. Check policy
    int active = bpf_map_lookup_elem(&active_map_selector, &zero);
    struct policy_map *pmap = active ? &policy_map : &policy_map_shadow;

    struct policy_key key = {
        .src_identity = src_id->id,
        .dst_identity = dst_id->id,
        .dst_port = dst_port,
        .protocol = protocol,
    };

    struct policy_value *decision = bpf_map_lookup_elem(pmap, &key);

    // 6. Default deny
    if (!decision || decision->action == DROP) {
        // Log drop event to ringbuf
        emit_audit_event(skb, src_id, dst_id, DENY);
        return TC_ACT_SHOT;
    }

    // 7. Allow (with optional audit)
    if (decision->flags & AUDIT)
        emit_audit_event(skb, src_id, dst_id, ALLOW);

    return TC_ACT_OK;
}
```

### Atomic Policy Update

When the agent receives a new compiled policy set:

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
| Identity lookup (LPM trie) | O(log prefix_len) ~30 ns | LPM trie for CIDR matching |
| Policy lookup (hash) | O(1) ~20 ns | BPF hash map, pre-hashed key |
| Total per-packet overhead | ~50-80 ns | << WireGuard crypto cost |
| Map update (full swap) | ~1 ms for 10,000 entries | Non-blocking to packet path |

The policy enforcement overhead is negligible compared to WireGuard
encryption (~150-300 ns amortized). It does not affect line-rate
performance.

---

## 7. Node Admission and Revocation

### Node Admission

A new node joins the mesh through this sequence:

```
1. Node boots, kubelet registers with API server
2. wirescale-agent starts (DaemonSet)
3. Agent generates WireGuard keypair
4. Agent creates WirescaleNode CRD:
   - Requires RBAC: wirescale-agent ServiceAccount
   - CRD name must match hostname (enforced by webhook)
   - Public key, endpoint, status fields set

5. Controller validates the CRD:
   - Is the node object registered in Kubernetes?
   - Does the CRD name match a real Node?
   - Is the node's IP in the expected range?
   - Passes admission webhook? (optional: node attestation)

6. Controller allocates pod CIDRs, updates CRD

7. All other agents see the new CRD via watch:
   - Add WireGuard peer with the new public key
   - Add routes for the new node's pod CIDRs

8. New node is now part of the mesh
```

### Node Revocation

When a node must be removed (compromised, decommissioned):

```
Option A: Graceful removal
  1. kubectl delete node <name>
  2. Controller deletes WirescaleNode CRD (owner reference cascade)
  3. All agents remove the peer from WireGuard
  4. Traffic to/from that node drops immediately

Option B: Emergency revocation
  1. kubectl delete wirescalenode <name>
  2. All agents remove the peer within seconds (watch latency)
  3. Node's private key is useless -- no peer accepts it
  4. Even cached WireGuard sessions time out (2 min handshake timeout)

Option C: Key rotation (suspected partial compromise)
  1. Agent on the suspect node generates new keypair
  2. Updates WirescaleNode CRD with new public key
  3. All peers update to the new key
  4. Old key immediately invalid (WireGuard rejects handshakes)
```

### Admission Webhook (Optional, Hardened Mode)

For high-security environments, a validating admission webhook can enforce
additional checks before a node joins:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: wirescale-node-admission
webhooks:
  - name: node-admission.wirescale.io
    rules:
      - apiGroups: ["wirescale.io"]
        resources: ["wirescalenodes"]
        operations: ["CREATE", "UPDATE"]
    clientConfig:
      service:
        name: wirescale-controller
        namespace: wirescale-system
        path: /validate-node
```

The webhook can enforce:
- Node attestation (TPM-based, or signed kubelet certificates)
- Key rotation frequency (reject if key age > threshold)
- Endpoint IP validation (must be in known subnet)
- Rate limiting (max 1 key change per hour to prevent abuse)

---

## 8. Mutual Authentication

### WireGuard's Built-In Mutual Auth

Every WireGuard handshake is mutually authenticated:

```
Initiator (node A) -> Responder (node B):

1. A encrypts (A's static pubkey) with B's static pubkey
   B decrypts and learns A's identity

2. B encrypts (B's static pubkey, ephemeral pubkey) with A's static pubkey
   A decrypts and confirms B's identity

3. Both derive session keys from the shared secret

Result: Both sides prove they hold the private key
        corresponding to the public key registered in the CRD
```

No certificates, no certificate authorities, no revocation lists. The
CRD is the key registry. Key removal from the CRD = revocation.

### Pod-Level Authentication

WireGuard authenticates nodes, not pods. Pod-level authentication is
provided by the identity system:

```
Pod A sends packet to Pod B:
  1. WireGuard guarantees the packet came from node-A
     (cryptographic proof via decryption)
  2. Node-A guarantees Pod A has IP fd00:ws:1::5
     (only kubelet on node-A can assign this IP)
  3. wirescale-agent guarantees fd00:ws:1::5 = pod "web-xyz"
     with identity (production, web-sa, app=web)
  4. Policy engine checks: is (production, web-sa, app=web) allowed
     to reach Pod B on this port?

This is a transitive trust chain:
  WireGuard key -> Node -> kubelet -> Pod -> Identity -> Policy
```

### External Peer Authentication

External peers (non-Kubernetes nodes) authenticate via:

1. **Pre-auth key:** A one-time token generated by the controller,
   delivered out-of-band (e.g., via `kubectl wirescale generate-key`).
   The external peer presents this token during initial registration.

2. **Key exchange:** The external peer's WireGuard public key is
   recorded in a `WirescaleExternalPeer` CRD.

3. **Admin approval:** The CRD's `status.approved` field must be set
   to `true` by an authorized user before the peer is added to the mesh.

4. **Ongoing auth:** After initial admission, the external peer is
   authenticated on every packet by its WireGuard key. No session tokens
   or cookies needed.

---

## 9. Key Lifecycle Management

### Key Generation

```
Event: Agent starts on node-N
  - Read /dev/urandom (256 bits)
  - Derive Curve25519 keypair
  - Private key: stored in agent process memory only
  - Public key: written to WirescaleNode CRD

Properties:
  - Private key survives agent restarts ONLY if the agent process
    stays alive (memory-only)
  - Agent restart = new keypair = brief handshake interruption
  - DaemonSet restart policy: Always (Kubernetes restarts crashed agents)
```

### Automatic Key Rotation

The agent rotates keys on a configurable schedule (default: 24 hours):

```
1. Agent generates new keypair
2. Agent updates WirescaleNode CRD with new public key
   (old key remains in "previousKeys" list for 5 minutes)
3. Controller distributes update to all agents
4. Remote agents update their WireGuard peer config:
   - Add new key
   - Keep old key for grace period (handles in-flight handshakes)
5. After grace period: remove old key from all peers
6. Old key is permanently invalid

Timeline:
  T+0s:   New key generated, CRD updated
  T+2s:   Most peers have new key (watch latency)
  T+5s:   All peers have new key
  T+300s: Old key removed from all peers (grace period)
```

### Emergency Key Revocation

```bash
# Revoke a node immediately
kubectl delete wirescalenode compromised-node

# Revoke an external peer
kubectl delete wirescaleexternalpeer compromised-laptop

# Effect: Within seconds, all agents remove the peer.
# The revoked key can no longer establish WireGuard handshakes.
# Existing sessions time out within 2 minutes (WireGuard rekey timer).
```

### Key Escrow

**There is no key escrow.** Private keys exist only in process memory.
This is a deliberate security decision:
- No backup of private keys = no risk of key exfiltration from backups
- Lost key = generate new key (the agent does this automatically on restart)
- No master key that can decrypt all traffic (forward secrecy via
  WireGuard's ephemeral keys per session)

---

## 10. Audit and Observability

### Connection Logging

The eBPF enforcement program emits audit events via a BPF ring buffer.
The wirescale-agent reads from the ring buffer and writes structured logs:

```json
{
  "timestamp": "2026-03-02T14:23:45.123Z",
  "node": "worker-3",
  "action": "allow",
  "src": {
    "ip": "fd00:ws:1::5",
    "pod": "web-frontend-abc",
    "namespace": "production",
    "serviceAccount": "web-sa",
    "labels": {"app": "web", "version": "v3"},
    "node": "worker-1"
  },
  "dst": {
    "ip": "fd00:ws:3::12",
    "pod": "api-server-xyz",
    "namespace": "production",
    "serviceAccount": "api-sa",
    "labels": {"app": "api", "version": "v2"},
    "node": "worker-3"
  },
  "protocol": "TCP",
  "dstPort": 8080,
  "policyId": "allow-web-to-api",
  "policyGeneration": 42
}
```

### What Gets Logged

| Event | Logged By Default | Configurable |
|-------|------------------|-------------|
| Connection denied (policy drop) | Yes | Always on |
| Connection allowed (new flow) | No | Per-policy `audit: true` flag |
| Policy update applied | Yes | Always on |
| Node admission/removal | Yes | Always on |
| Key rotation | Yes | Always on |
| WirescaleAccessGrant approval/expiry | Yes | Always on |
| WireGuard handshake failure | Yes | Always on |

### Prometheus Metrics

The wirescale-agent exposes metrics at `:9090/metrics`:

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

# NAT64
wirescale_nat64_translations_total{direction="v6_to_v4"} 45123
wirescale_nat64_translations_total{direction="v4_to_v6"} 44987

# Identity
wirescale_identity_cache_size{node="worker-3"} 234
wirescale_identity_cache_updates_total{node="worker-3"} 567
```

### Network Flow Visualization

The audit logs can be consumed by standard tools:

- **Hubble** (Cilium's flow observability) -- compatible log format
- **Grafana** -- dashboards for policy decisions, throughput, peer health
- **Elasticsearch/Loki** -- searchable connection logs with identity attribution
- **kubectl wirescale flows** -- CLI for real-time flow watching:

```bash
$ kubectl wirescale flows -n production --from app=web --to app=api
TIMESTAMP           ACTION  SRC                 DST                 PORT  POLICY
14:23:45.123  ALLOW   web-frontend-abc    api-server-xyz      8080  allow-web-to-api
14:23:45.456  ALLOW   web-frontend-def    api-server-xyz      8080  allow-web-to-api
14:23:46.789  DENY    unknown-pod-ghi     api-server-xyz      8080  default-deny
```

---

## 11. Threat Model and Mitigations

### Threats and Responses

| # | Threat | Impact | Mitigation |
|---|--------|--------|-----------|
| T1 | Eavesdropping on inter-node traffic | Data exfiltration | WireGuard encryption (always on, ChaCha20-Poly1305) |
| T2 | Rogue node joins mesh | Unauthorized access to all pods | Node admission via RBAC + optional webhook attestation |
| T3 | Compromised node | Full access to pods on that node + mesh traffic | Key revocation (CRD delete); blast radius limited to that node's pods; inter-node traffic from other nodes is still encrypted |
| T4 | API server compromise | Can modify policies, CRDs | Data plane traffic still encrypted (no private keys in API). Attacker can weaken policies but cannot passively decrypt. |
| T5 | wirescale-controller compromise | Can weaken policies, redirect traffic | Controller has no private keys. Agents validate CRD consistency. Anomaly detection alerts on mass policy changes. |
| T6 | Pod breakout (container escape) | Access to host network namespace | WireGuard encrypts cross-node traffic; attacker can only see traffic to/from pods on the same node. eBPF policies still enforce at the veth level. |
| T7 | DNS poisoning | Traffic misdirection | MagicDNS responses are signed by the control plane. External DNS validated by DNSSEC where available. NAT64 prefix is hardcoded, not DNS-dependent. |
| T8 | DDoS against WireGuard endpoint | Service disruption | Rate limiting on handshake processing (WireGuard built-in cookie mechanism). XDP early drop on physical NIC. |
| T9 | Key exfiltration from node memory | Impersonation | Keys are ephemeral (auto-rotated). Forward secrecy per-session. Process memory is not persisted. |
| T10 | Replay attack | Traffic replay | WireGuard uses monotonic counters per session. Replayed packets are rejected. |
| T11 | Policy bypass via IP spoofing | Unauthorized access | WireGuard's cryptokey routing drops packets whose source doesn't match AllowedIPs. Node-level IPAM ensures only authorized CIDRs are routable. |
| T12 | Lateral movement after pod compromise | Escalation | Deny-by-default policy. Compromised pod can only reach explicitly allowed destinations. WirescaleAccessGrant provides time-limited escalation. |

### Defense in Depth Stack

```
Attack surface reduced by:

1. IPv6-only underlay
   - No IPv4 attack surface on the wire
   - External IPv4 only reachable via controlled NAT64 path

2. WireGuard encryption (Layer 3)
   - All cross-node traffic authenticated + encrypted
   - Unknown keys silently dropped (no information leak)

3. Identity-based policy (Layer 4)
   - Pod identity, not IP, determines access
   - Survives pod restart, rescheduling, IP changes

4. Time-bounded access grants
   - Temporary access automatically expires
   - No forgotten firewall rules

5. Automatic key rotation
   - Limits window of compromise
   - No long-lived static credentials

6. Audit trail
   - Every denied connection logged
   - Every policy change logged
   - Attribution to pod identity, not just IP
```

---

## 12. Implementation Details

### Phase 3 Deliverables (from ARCHITECTURE.md)

This document covers the design for Phase 3 (Policy and Security) and
Phase 4 (External Connectivity access control). The implementation order:

**3a: Basic Policy Enforcement**
- [ ] BPF map architecture (identity_map, policy_map)
- [ ] TC eBPF program for pod veth (ingress + egress)
- [ ] Agent: identity cache from Pod watch
- [ ] Agent: policy ConfigMap watcher + BPF map updater
- [ ] Controller: policy compiler (NetworkPolicy -> BPF rules)
- [ ] Atomic map swap for zero-downtime policy updates

**3b: Extended Policy (WirescalePolicy CRD)**
- [ ] WirescalePolicy CRD definition and validation
- [ ] ServiceAccount selector support
- [ ] External peer selector support
- [ ] FQDN-based egress control (with DNS snooping for IP resolution)
- [ ] Time-bounded schedule support

**3c: Dynamic Access Grants**
- [ ] WirescaleAccessGrant CRD
- [ ] Approval workflow (status subresource)
- [ ] Automatic expiry (controller reconciliation loop)
- [ ] CLI: `kubectl wirescale grant`

**3d: Audit and Observability**
- [ ] BPF ring buffer for connection events
- [ ] Agent: structured log output (JSON)
- [ ] Prometheus metrics exporter
- [ ] CLI: `kubectl wirescale flows`

**3e: Hardened Mode**
- [ ] Validating admission webhook for WirescaleNode
- [ ] Key rotation schedule enforcement
- [ ] Anomaly detection (mass policy change alerting)
- [ ] Node attestation support (pluggable)

### RBAC Configuration

```yaml
# wirescale-agent ServiceAccount permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wirescale-agent
rules:
  # Own node's CRD
  - apiGroups: ["wirescale.io"]
    resources: ["wirescalenodes"]
    verbs: ["get", "list", "watch", "create", "update"]
  # Read all peer CRDs
  - apiGroups: ["wirescale.io"]
    resources: ["wirescalenodes", "wirescaleexternalpeers"]
    verbs: ["get", "list", "watch"]
  # Read pods for identity resolution
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  # Read policy ConfigMaps
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "watch"]
    resourceNames: ["wirescale-policy-*"]

---
# wirescale-controller permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wirescale-controller
rules:
  # Full access to wirescale CRDs
  - apiGroups: ["wirescale.io"]
    resources: ["*"]
    verbs: ["*"]
  # Read pods, namespaces, nodes for policy compilation
  - apiGroups: [""]
    resources: ["pods", "namespaces", "nodes"]
    verbs: ["get", "list", "watch"]
  # Read network policies
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch"]
  # Write policy ConfigMaps
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["create", "update", "delete"]
```

### Resource Overhead

| Component | CPU (idle) | CPU (1000 pods) | Memory |
|-----------|-----------|-----------------|--------|
| eBPF per-pod program | 0 | ~50 ns/packet | ~4 KB per veth |
| Identity map (BPF) | 0 | 0 | ~100 bytes/pod |
| Policy map (BPF) | 0 | 0 | ~64 bytes/rule |
| Policy compiler | ~10 mcpu | ~50 mcpu | ~50 MB |
| Audit ring buffer | 0 | ~5 mcpu | 256 KB/node |
| Total agent overhead | ~20 mcpu | ~100 mcpu | ~50 MB |
