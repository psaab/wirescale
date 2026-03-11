# Wirescale: Operations Guide

> Procedures and guidance for upgrading, sizing, monitoring, and recovering
> a Wirescale deployment across single-cluster and federated multi-cluster
> topologies.
>
> Status: operational guidance. Numeric thresholds should be treated as
> recommended starting points; operators SHOULD tune them for their
> environment.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

**See also:**
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Core architecture (three-tier hierarchy, on-demand peering)
- [PERFORMANCE.md](PERFORMANCE.md) -- Line-rate performance engineering
- [SECURITY.md](SECURITY.md) -- Network security, identity model, Prometheus metrics (Section 12)
- [ROUTABLE-PREFIX.md](ROUTABLE-PREFIX.md) -- GUA routable-prefix design
  (Section 2.5 defines the preflight safety gates that Section 6 below
  operationalizes)
- [SECURITY.md](SECURITY.md) -- Network security, identity model, CA hierarchy (Section 4),
  Prometheus metrics (Section 12)

---

## Table of Contents

1. [Upgrade and Migration Strategy](#1-upgrade-and-migration-strategy)
2. [Capacity Planning](#2-capacity-planning)
3. [Monitoring and Alerting](#3-monitoring-and-alerting)
4. [Backup and Disaster Recovery](#4-backup-and-disaster-recovery)
   - [4.6 Certificate Rotation Procedures](#46-certificate-rotation-procedures)
   - [4.7 Emergency CA Compromise Response](#47-emergency-ca-compromise-response)
5. [Testing Strategy](#5-testing-strategy)
6. [GUA Mode Preflight Checklist](#6-gua-mode-preflight-checklist)

---

## 1. Upgrade and Migration Strategy

### 1.1 Rolling Agent Upgrades

The `wirescale-agent` DaemonSet MUST use a `RollingUpdate` strategy with
`maxUnavailable: 1`. Update sequence per node:

1. The agent receives `SIGTERM` and begins graceful shutdown. Existing
   WireGuard peers remain active in the kernel (`wg0` is owned by the
   network namespace, not the process). TC/XDP BPF programs persist
   across process exit. The agent flushes pending `connection_log` events.
2. The old pod exits. In-flight traffic continues through kernel-resident
   WireGuard sessions and BPF programs.
3. The new agent pod starts, generates a new keypair (memory-only),
   registers with `wirescale-control`, re-establishes gRPC (mTLS), and
   reconciles WireGuard peers against control.
4. Remote nodes receive a key-update notification and re-handshake
   (< 100 ms). The 300 s grace period for the old key prevents packet loss.

**In-flight connections:** Because sessions and BPF programs are
kernel-resident, active flows experience at most a brief re-handshake
(< 2 s worst case). Connections MUST NOT be dropped solely due to an
agent upgrade.

### 1.2 Control Plane Upgrades

`wirescale-control` upgrades MUST use `RollingUpdate` with
`maxUnavailable: 0`, `maxSurge: 1` to maintain full replica count.

- Write operations (IPAM, CRD updates) use Kubernetes lease-based leader
  election. If the leader is terminated, re-election completes in < 5 s.
- Read operations (identity resolution, peer lookup) are served by all
  replicas and are unaffected by leader transitions.

**Directory upgrade:** Upgrade one Raft member at a time. Verify quorum
between each member. The directory MUST maintain a majority of members
throughout the upgrade. The directory is a discovery service and does NOT
hold CA private keys; upgrading the directory does NOT affect the
certificate trust hierarchy.

### 1.3 CRD Schema Migration

| Version | Stability | Compatibility Guarantee |
|---------|-----------|------------------------|
| `v1alpha1` | Experimental | Breaking changes permitted between releases |
| `v1beta1` | Pre-stable | Backward-compatible only; deprecation requires one release cycle |
| `v1` | Stable | No breaking changes within a major version |

When multiple versions coexist, `wirescale-control` MUST serve a
conversion webhook that translates losslessly between versions, populates
new fields with safe defaults, and uses proper OpenAPI schema pruning.

**Migration procedure:** Deploy updated control with webhook support,
apply CRD manifest with both versions (`served: true`), set
`storage: true` on the new version, run storage migration to rewrite
all objects, then retire the old version.

### 1.4 Migration Paths

**Cilium-only to Cilium + Wirescale (additive):** Lowest risk. Cilium
retains intra-cluster ownership. Deploy Wirescale CRDs, control, and
agent alongside Cilium. The agent creates `wg0` alongside Cilium
interfaces. Configure WirescaleMesh with the cluster prefix (e.g.,
`3fff:1234:0001::/48`), register with the directory. Intra-cluster traffic
stays on Cilium; cross-cluster routes through WireGuard.

**Standalone Wirescale to Cilium + Wirescale:** Install Cilium in
native-routing mode with existing pod CIDRs. Migrate NetworkPolicy to
CiliumNetworkPolicy. Reconfigure agent to delegate intra-cluster
encryption to Cilium's WireGuard mode or retain Wirescale for all
inter-node encryption. Validate with `kubectl wirescale flows` and Hubble.

**Wirescale v1 to v2 (major version):** Deploy v2 control alongside v1
using separate Deployments. Migrate CRDs via conversion webhooks
(Section 1.3). Roll out v2 agents via canary (Section 1.5). After full
migration, decommission v1 control. Upgrade directory last.

### 1.5 Canary Deployments

1. Label canary nodes: `wirescale.io/upgrade-group: canary`.
2. Apply updated DaemonSet targeting canary nodes.
3. Monitor for 15-30 min. Key signals: handshake failures, peer
   establishment p99, gRPC errors, identity cache miss rate.
4. **Rollback triggers** -- halt and revert if:
   - WireGuard handshake failure rate > 1% of peers
   - Peer establishment p99 > 500 ms
   - Control gRPC error rate > 5%
   - Any node reports `controlPlaneConnected: false` for > 60 s

### 1.6 Version Skew Policy

| Component Pair | Maximum Skew | Notes |
|----------------|-------------|-------|
| Agent <-> Controller | 2 minor versions | Controller MUST be >= agent version |
| Controller <-> Directory | 2 minor versions | Directory MUST be >= controller version |
| Agent <-> Agent (cross-node) | 3 minor versions | WireGuard is version-agnostic; skew limit is for BPF/gRPC compat |
| CRD schema <-> Controller | 1 storage version | Conversion webhooks bridge the gap |

**Upgrade order:** Directory first, then controllers, then agents.

---

## 2. Capacity Planning

### 2.1 Controller Sizing

| Cluster Size | Replicas | CPU/Replica | Memory/Replica | Notes |
|-------------|----------|------------|----------------|-------|
| <= 100 nodes | 1 | 0.5 cores | 256 MB | Single replica for non-production |
| <= 500 nodes | 3 | 1 core | 512 MB | HA minimum |
| <= 1,000 nodes | 3 | 2 cores | 1 GB | |
| <= 5,000 nodes | 5 | 4 cores | 4 GB | Leader election critical |
| <= 10,000 nodes | 5-7 | 8 cores | 8 GB | Dedicated control-plane node pool |

**Memory estimate:** `base (128 MB) + nodes * 2 KB + pods * 0.5 KB +
identity_index * 0.1 KB`. A 5K-node cluster with 100 pods/node requires
~440 MB per replica (allocate 1 GB with headroom).

### 2.2 Agent Resource Requirements

Agent resource usage is bounded by active peer count, not cluster size
(see PERFORMANCE.md Section 7).

| Resource | Base | Per Active Peer | Per Cached Identity |
|----------|------|----------------|---------------------|
| Memory | ~50 MB | ~2 KB (WireGuard + BPF) | ~100 bytes |
| CPU (control) | < 0.1 cores | Negligible | Negligible |

**XDP CPU budget:**

| Link Speed | XDP Cores (worst case) | Notes |
|-----------|----------------------|-------|
| 1 Gbps | < 0.5 | Single core handles wire rate |
| 10 Gbps | 1-2 | Packet size dependent |
| 25 Gbps | 2-4 | GRO/GSO batching critical |
| 100 Gbps | 4-8 | Multi-queue RSS required |

### 2.3 Directory Sizing

| Federation Size | etcd Members | Storage | Memory/Member | IOPS |
|----------------|-------------|---------|---------------|------|
| <= 50 clusters | 3 | < 10 MB | 256 MB | < 100 |
| <= 500 clusters | 3-5 | < 100 MB | 512 MB | < 500 |
| <= 5,000 clusters | 5 | < 1 GB | 1 GB | < 2,000 |

Read:write ratio is ~1000:1. Storage per cluster: ~2 KB (cluster ID,
endpoints, prefix allocation, intermediate CA certificate, CRL reference,
metadata). The federation trust bundle adds ~1 KB per cluster
intermediate CA plus ~1 KB for the root CA certificate and CRL.

### 2.4 BPF Map Sizing

Maps MUST be sized at agent startup (no live resize without BPF reload).

| Map | Recommended Max Entries | Memory/Node |
|-----|------------------------|-------------|
| `identity_cache` (LPM trie) | 16,384 | ~576 KB |
| `identity_table` (array) | 16,384 | ~256 KB |
| `policy_map` (hash) | 65,536 | ~1.3 MB |
| `policy_map_shadow` (hash) | 65,536 | ~1.3 MB |
| `peer_cache` (hash) | 4,096 | ~144 KB |
| `connection_log` (ring buffer) | 8 MB ring | 8 MB |
| **Total** | | **~11.6 MB** |

### 2.5 Gateway Sizing (Signaling and Relay)

Gateway nodes serve two roles: signaling (cross-cluster peer resolution) and
relay (data forwarding for nodes without mutual reachability). Sizing depends
on which role dominates.

**Signaling-only sizing** (all nodes have mutual reachability):

| Clusters | Peak Resolutions/sec | Recommended Gateways | CPU/Gateway | Memory/Gateway |
|---------|---------------------|---------------------|-------------|----------------|
| 5-10 | ~500 | 2-3 | 0.5 cores | 256 MB |
| 10-50 | ~5K | 3-5 | 1 core | 512 MB |
| 50-200 | ~20K | 5-10 | 2 cores | 1 GB |

**Relay-capable sizing** (some nodes behind NAT/firewall):

| Expected Relay % | Aggregate Relay BW | Recommended Gateways | NIC Speed | CPU/Gateway | Memory/Gateway |
|-----------------|-------------------|---------------------|-----------|-------------|----------------|
| < 5% | < 1 Gbps | 2-3 | 10 Gbps | 2 cores | 512 MB |
| 5-15% | 1-10 Gbps | 3-5 | 25 Gbps | 4-8 cores | 1 GB |
| 30-60% | 10-50 Gbps | 5-10 | 25-100 Gbps | 8-16 cores | 2 GB |
| 100% (all relay) | Matches cross-cluster BW | 10+ | 100 Gbps | 16+ cores | 4 GB |

**Memory estimate for relay:** `base (128 MB) + relay_sessions * 4 KB`.
At 10,000 concurrent relay sessions, relay state requires ~40 MB.

Operators MUST monitor `wirescale_relay_utilization_ratio` on each gateway
node. Sustained utilization above 70% indicates the need for additional
relay capacity.

### 2.6 Scaling Decision Table

| Signal | Threshold | Action |
|--------|----------|--------|
| Control gRPC p99 > 50 ms | Sustained 5 min | Add controller replicas |
| Controller CPU > 80% | Sustained 10 min | Scale up or increase limits |
| Cluster approaching 10K nodes | Planning horizon | Split cluster; use federation |
| `identity_cache_evictions` rate rising | Sustained 30 min | Increase `identityCache.maxEntries` |
| Any BPF map > 80% full | Any occurrence | Increase map size, redeploy agents |
| Cross-cluster query p99 > 200 ms | Sustained 5 min | Add directory replicas, check network |
| Relay utilization > 70% | Sustained 10 min | Add relay gateway nodes or increase NIC speed |
| Relay sessions > 80% of max | Any occurrence | Increase `relay.maxSessionsPerNode` or add gateways |
| Relay-to-direct promotion rate < 50% | Sustained 1 hour | Investigate NAT/firewall; likely permanent relay needed |
| `wirescale_relay_rejected_sessions_total` rising | Any sustained rate | Add relay gateways; capacity exhausted |

---

## 3. Monitoring and Alerting

### 3.1 Prometheus Metrics Reference

Metrics are exposed at three endpoints (see [SECURITY.md Section 12](SECURITY.md#12-audit-and-observability)):

- **`wirescale-agent`** at `:9090/metrics` -- WireGuard peers, policy
  decisions, identity cache, peer cache, NAT64, cross-cluster flows,
  peer mode (direct vs relay), relay promotion attempts.
- **`wirescale-control`** at `:9091/metrics` -- nodes, identities, policy
  compilations, peer authorizations, gRPC server, directory health,
  relay session allocation.
- **`wirescale-gateway`** at `:9090/metrics` (on gateway nodes) -- relay
  active sessions, bytes relayed, utilization ratio, rejected sessions,
  per-source relay bandwidth.

### 3.2 Health Thresholds

| Metric | Healthy | Degraded | Critical |
|--------|---------|----------|----------|
| Peer setup p99 | < 15 ms | 15-100 ms | > 100 ms |
| Identity cache hit rate | > 95% | 85-95% | < 85% |
| Control gRPC error rate | < 0.1% | 0.1-1% | > 1% |
| WireGuard handshake failures | 0% | < 1% | > 1% |
| Policy update p99 | < 1 s | 1-5 s | > 5 s |
| BPF map utilization | < 60% | 60-80% | > 80% |
| Directory query p99 | < 50 ms | 50-200 ms | > 200 ms |
| Relay utilization ratio | < 50% | 50-70% | > 70% |
| Relay session count (% of max) | < 60% | 60-80% | > 80% |
| Relay-to-direct promotion rate | > 80% | 50-80% | < 50% |
| Relay latency overhead | < 1 ms | 1-2 ms | > 2 ms |
| Relayed peer fraction (per node) | < 10% | 10-30% | > 30% |

### 3.3 Recommended Alerts

| Alert | Condition | Severity |
|-------|----------|----------|
| PeerLatencyHigh | `peer_establishment_latency_seconds` p99 > 100 ms for 5 min | warning |
| IdentityCacheMissRate | miss / (hit + miss) > 10% for 10 min | warning |
| ControlPlaneErrors | gRPC error rate > 1% for 5 min | critical |
| HandshakeFailures | `handshake_failures_total` rate > 0 for 5 min | warning |
| BPFMapNearFull | `identity_cache_size` / max > 80% or `policy_rules_total` / max > 80% | warning |
| CertExpiringSoon | `certificate_expiry_seconds` < 7 days | warning |
| AuthzExpiredDuringOutage | `wirescale_authz_expired_during_outage_total` rate > 0 for 5 min | warning |
| AgentDegradedMode | `wirescale_agent_degraded_mode{reason="control_unreachable"}` == 1 for 2 min | critical |
| RelayUtilizationHigh | `wirescale_relay_utilization_ratio` > 0.7 for 10 min | warning |
| RelayUtilizationCritical | `wirescale_relay_utilization_ratio` > 0.9 for 5 min | critical |
| RelaySessionsNearMax | `wirescale_relay_active_sessions` / max > 80% for 5 min | warning |
| RelaySessionsRejected | `wirescale_relay_rejected_sessions_total` rate > 0 for 5 min | critical |
| RelayPromotionLow | promotion success / attempts < 50% for 1 hour | warning |
| HighRelayedPeerFraction | `wirescale_peer_mode{mode="relay"}` / total peers > 30% for 30 min | warning |
| RelayGatewayDown | Gateway node with relay sessions becomes unreachable | critical |
| IntermediateCAExpiring | `wirescale_intermediate_ca_expiry_seconds` < 90 days | warning |
| RootCAExpiring | `wirescale_root_ca_expiry_seconds` < 365 days | warning |
| TrustBundleStale | `wirescale_trust_bundle_age_seconds` > 3600 | warning |

### 3.4 Troubleshooting Runbook

#### Elevated Cold-Path Latency

Peer establishment p99 or identity cache miss rate alerts firing.

| Step | Action |
|------|--------|
| 1 | Check control pod health: `kubectl -n wirescale-system get pods -l app=wirescale-control` |
| 2 | Verify gRPC: `grpcurl wirescale-control:9443 grpc.health.v1.Health/Check` |
| 3 | Check identity cache: `curl localhost:9090/metrics \| grep identity_cache` |
| 4 | Check leader lease: `kubectl get lease wirescale-control-leader -o yaml` |

**Resolution:** If control is OOM, increase memory. If cache hit rate is
low, increase `identityCache.ttl` or `maxEntries`. If leader election
flaps, check etcd health behind the Kubernetes API.

#### Packet Drops at XDP

| Step | Action |
|------|--------|
| 1 | Check policy decisions: `grep policy_decisions` in agent metrics |
| 2 | Check identity misses (unknown source = drop) |
| 3 | Inspect BPF map capacity: `bpftool map show` |
| 4 | Check audit logs: `grep '"action":"deny"'` in agent logs |

**Resolution:** Verify WirescalePolicy allows intended traffic. If BPF
maps are near capacity, increase sizes and redeploy (Section 2.4). If
identity misses cause drops, check controller health.

#### WireGuard Handshake Failures

| Step | Action |
|------|--------|
| 1 | Check certificate validity: `openssl x509 -in tls.crt -noout -dates` |
| 2 | Verify key registration: `kubectl get wirescalenode <node> -o jsonpath='{.spec.publicKey}'` |
| 3 | Check UDP 51820 reachability to peer |
| 4 | Inspect interface: `wg show wg0` |

**Resolution:** Rotate certs if expired (`kubectl wirescale rotate-certs`).
Restart agent to force peer re-establishment if keys are stale. Verify
cloud security groups allow bidirectional UDP on `listenPort`.

#### High Relay Utilization or Relay Session Rejections

Relay utilization alerts or session rejection counters firing.

| Step | Action |
|------|--------|
| 1 | Check relay gateway health: `kubectl -n wirescale-system get pods -l wirescale.io/gateway=true` |
| 2 | Check relay metrics: `curl <gateway-ip>:9090/metrics \| grep wirescale_relay` |
| 3 | Identify top relay consumers: check `wirescale_relay_per_source_bytes` for hotspots |
| 4 | Check if relay-to-direct promotion is working: `curl <agent-ip>:9090/metrics \| grep relay_promotion` |
| 5 | Verify per-source rate limits are configured: check WirescaleMesh `.spec.gateways.relay.perSourceRateLimitBps` |

**Resolution:** If utilization is high, add relay gateway nodes or increase
NIC speed. If a single source dominates, investigate why it cannot establish
direct tunnels (check NAT type, firewall rules, VPC peering). If promotion
rate is low, the NAT/firewall condition may be permanent -- size relay
capacity accordingly.

#### Nodes Stuck in Relay Mode

Nodes that should be able to establish direct tunnels are relaying instead.

| Step | Action |
|------|--------|
| 1 | Check node NAT type: `kubectl get wirescalenode <node> -o jsonpath='{.status.natType}'` |
| 2 | Verify UDP 51820 reachability between nodes: `nc -u -z <remote-endpoint> 51820` |
| 3 | Check relay promotion attempts: `curl <agent-ip>:9090/metrics \| grep relay_promotion` |
| 4 | Check for asymmetric firewall rules blocking inbound UDP |
| 5 | Check cloud security groups / VPC peering configuration |

**Resolution:** If the NAT type is "symmetric" or "unknown", direct tunnels
may not be possible -- relay is the correct behavior. If the NAT type is
"full-cone" or "restricted" but direct tunnels still fail, check for
firewall rules or security groups blocking bidirectional UDP on the
WireGuard port. Fix the network path or accept relay as the steady state
and provision relay capacity accordingly.

#### Relay Gateway Failover

A relay gateway node has failed and relayed sessions need reassignment.

| Step | Action |
|------|--------|
| 1 | Verify gateway pod status: `kubectl -n wirescale-system get pods -l wirescale.io/gateway=true` |
| 2 | Check if control is reassigning sessions: `kubectl logs -n wirescale-system deploy/wirescale-control \| grep relay` |
| 3 | Check affected nodes: `kubectl get wirescalenodes -o json \| jq '.items[] \| select(.status.relayedPeers > 0)'` |
| 4 | Verify remaining gateways have capacity: check `wirescale_relay_utilization_ratio` on surviving gateways |

**Resolution:** If control is reassigning sessions automatically, wait for
completion (< 10s). If reassignment is stuck, restart the control pod. If
all relay gateways are down, relayed sessions are unavailable until at least
one gateway recovers -- direct sessions are unaffected.

#### Cross-Cluster Connectivity Loss

| Step | Action |
|------|--------|
| 1 | Check directory: `wirescale-directory status` |
| 2 | Verify registration: `wirescale-directory list-clusters` |
| 3 | Check cross-cluster metrics and aggregate routes (`ip -6 route show \| grep 3fff:1234`) |
| 4 | Check gateway node health and firewall rules |

**Resolution:** If directory is unreachable, cached connectivity hint
registrations remain valid (TTL extended). Cross-cluster authorization
state follows fail-closed semantics on TTL expiry. If gateways are
unhealthy, verify labels and pods. If aggregate routes are missing,
restart the agent.

#### Authorization Expiry During Control Outage

`AuthzExpiredDuringOutage` or `AgentDegradedMode` alerts firing.

| Step | Action |
|------|--------|
| 1 | Check control pod health: `kubectl -n wirescale-system get pods -l app=wirescale-control` |
| 2 | Check `wirescale_authz_expired_during_outage_total` in agent metrics |
| 3 | Check `wirescale_authz_grant_rules_active` -- if 0, all grants have expired |
| 4 | Verify control is reachable: `grpcurl wirescale-control:9443 grpc.health.v1.Health/Check` |

**Resolution:** This is expected behavior -- authorization state fails
closed on TTL expiry to preserve revocation semantics. Restore control
connectivity to reissue access grants. If access grants are critical
during the outage, operators MUST restore control availability rather
than attempt to extend grant lifetimes. The agent will automatically
revalidate authorization state once control is reachable.
**Resolution:** If directory is unreachable, cached registrations remain
valid for the heartbeat TTL (60 s). If gateways are unhealthy, verify
labels and pods. If aggregate routes are missing, restart the agent. For
nodes using relay mode, also check relay gateway health and capacity --
relay gateway failure disrupts relayed sessions but not direct tunnels.

---

## 4. Backup and Disaster Recovery

### 4.1 State Classification

| Category | Examples | Loss Impact |
|----------|---------|-------------|
| **Critical (offline)** | Offline federation root CA private key (HSM-backed) | Federation-wide trust compromise; requires full re-keying ceremony |
| **Critical (per-cluster)** | Per-cluster intermediate CA private keys, CRD definitions | Cluster-wide certificate issuance failure; requires re-issuance from offline root |
| **Critical (federation)** | Directory data (cluster registry, prefix allocations, trust bundles, CRLs) | Cross-cluster discovery outage (intra-cluster operations unaffected) |
| **Derived** | Controller in-memory cache (pod/identity index, compiled policies) | ~30 s rebuild from Kubernetes API on restart |
| **Ephemeral -- Connectivity Hints** | Peer endpoints, WireGuard public keys, allowed CIDRs, routes, identity-to-IP mappings, cluster topology | Peers re-established on demand within seconds. Safe to restore from disk. |
| **Ephemeral -- Authorization State** | WirescaleAccessGrant validity, revocation status, peer authorization tokens, policy generation numbers | MUST NOT be restored from disk. Requires fresh control-plane validation. |
| **Ephemeral -- Other** | WireGuard private keys, BPF map runtime state | Regenerated on agent startup; never persisted |

> **Important:** The distinction between connectivity hints and
> authorization state is critical for security. Connectivity hints are
> safe to cache and restore because staleness only causes routing
> failures that self-heal. Authorization state MUST fail closed on
> expiry because staleness can extend access beyond intended bounds or
> mask revocations. See [SECURITY.md: Cached State
> Classification](SECURITY.md#cached-state-classification) for normative
> requirements.

### 4.2 Backup Procedures

**Offline federation root CA:** The root CA private key resides on an
air-gapped HSM. Backup MUST follow the HSM vendor's key backup procedure
(typically M-of-N key shares stored in physically separate secure
locations). The root CA public certificate and CRL SHOULD be backed up
alongside directory data. Root CA backup verification SHOULD be performed
at least annually during a planned ceremony.

**Per-cluster intermediate CA:** The cluster intermediate CA private key
is the one exception to the no-escrow policy for node keys. Back up the
intermediate CA secret encrypted at rest:
```bash
kubectl -n wirescale-system get secret wirescale-cluster-ca -o yaml | \
  gpg --encrypt --recipient ops-team@example.com > /backup/cluster-ca-$(date +%Y%m%d).yaml.gpg
```
Store intermediate CA backups separately from the cluster they protect.
In the event of total cluster loss, the intermediate CA backup allows
re-bootstrapping the cluster without a new offline root CA ceremony.

**Directory etcd:** Take snapshots at least every 4 hours:
```bash
ETCDCTL_API=3 etcdctl snapshot save /backup/directory-$(date +%Y%m%d).snap \
  --endpoints=https://etcd-1.directory.example.com:2379 \
  --cacert=/etc/etcd/ca.crt --cert=/etc/etcd/client.crt --key=/etc/etcd/client.key
```

**Trust bundles and CRLs:** The directory stores trust bundles and CRLs.
These are included in the directory etcd snapshot. Additionally, the
current trust bundle SHOULD be exported and archived independently:
```bash
wirescale-directory export-trust-bundle > /backup/trust-bundle-$(date +%Y%m%d).pem
wirescale-directory export-crl > /backup/federation-crl-$(date +%Y%m%d).pem
```

**CRDs:** Include all Wirescale CRDs (WirescaleMesh, WirescaleNode,
WirescalePolicy, WirescaleCluster, WirescaleExternalPeer,
WirescaleAccessGrant, WirescaleServiceExport/Import) in Velero backups
or etcd snapshots.

### 4.3 Recovery Procedures

**Offline root CA:** If the root CA HSM is lost or destroyed, restore from
the M-of-N key share backup. If the root CA private key is suspected
compromised, initiate a full root CA rotation ceremony (see Section 4.7).
During root CA recovery, existing clusters continue operating normally
with their cached trust bundles; only new cluster admissions and
intermediate CA re-signing are blocked.

**Per-cluster intermediate CA:** Restore the encrypted intermediate CA
backup. Re-deploy the secret to the cluster:
```bash
gpg --decrypt /backup/cluster-ca-YYYYMMDD.yaml.gpg | \
  kubectl -n wirescale-system apply -f -
```
Restart `wirescale-control` to pick up the restored CA. If the
intermediate CA is suspected compromised, request revocation via the
offline root CRL and provision a new intermediate CA (see Section 4.6).

**Directory:** Stop all members, restore etcd snapshot, restart members,
verify quorum. Verify the trust bundle and CRL integrity after restore.
Controllers re-register on their next heartbeat (60 s). During the outage,
intra-cluster operations are unaffected; only new cross-cluster peer
establishment and trust bundle refresh are blocked.

**Controller:** Kubernetes restarts failed pods automatically. On start,
the controller rebuilds its index from the API server (~30 s for 10K
nodes). Leader election re-establishes in ~5 s. No manual intervention
unless the API server itself is down.

**Agent:** Kubernetes restarts the pod. The new agent generates a fresh
keypair, registers with control, and repopulates caches on demand.
Kernel-resident WireGuard sessions and BPF programs are unaffected
during restart. On startup the agent restores **connectivity hints**
(peer endpoints, public keys, routes, identity cache) from the
persisted peer cache at `/var/lib/wirescale/peer-cache.json`, marks
them stale, and refreshes them within 30 seconds. **Authorization
state** (access grant rules, peer authorization tokens, revocation
status) is NOT restored from disk -- the agent obtains fresh
authorization state from `wirescale-control` before granting access
to authorization-gated resources. If control is unreachable at startup,
the agent operates in degraded mode: existing WireGuard sessions
continue (authenticated by WireGuard rekey), but new
authorization-gated operations are denied until control is reachable.

### 4.4 RPO/RTO Targets

| Component | RPO | RTO | Notes |
|-----------|-----|-----|-------|
| Offline root CA (HSM) | 0 (HSM backup) | <= 4 hours | M-of-N key share recovery ceremony |
| Cluster intermediate CA | <= 24 hours | <= 1 hour | Encrypted backup restore |
| Directory (etcd) | <= 4 hours | <= 30 min | Snapshot restore + quorum |
| Trust bundle / CRLs | <= 4 hours | <= 30 min | Restored with directory; independent archive optional |
| Controller | 0 (stateless) | <= 2 min | Pod restart + cache rebuild |
| Agent (connectivity hints) | 0 (ephemeral) | <= 30 s | Pod restart + disk restore + stale refresh |
| Agent (authorization state) | 0 (not persisted) | <= 30 s | Fresh validation from control required; fail closed until available |
| CA keys | <= 24 hours | <= 1 hour | Encrypted backup restore |
| Agent | 0 (ephemeral) | <= 30 s | Pod restart + key registration |
| CRDs (Velero) | <= 1 hour | <= 15 min | Velero restore |

### 4.5 Multi-Region Directory: Quorum and Split-Brain

Deploy directory etcd across an odd number of regions (3 or 5).

**Quorum loss:** If quorum is lost, the directory rejects writes.
Controllers fall back to cached connectivity hints (cluster topology,
gateway endpoints, prefix allocations). Authorization state for
cross-cluster operations (cluster revocation status, cross-cluster
peer authorization tokens) MUST NOT be extended beyond its signed TTL.
Intra-cluster operations continue. Restore quorum by recovering members
or `etcdctl member add`.

**Split-brain prevention:** etcd Raft ensures only the majority
partition elects a leader. The minority partition returns errors.
Controllers in the minority partition use cached connectivity hints for
directory data. Cross-cluster authorization state follows fail-closed
semantics on TTL expiry.
On partition heal, etcd reconciles automatically.

**Recommended topology:**
```
Region A (us-east-1):  2 members
Region B (eu-west-1):  2 members
Region C (ap-south-1): 1 member
Total: 5 members, tolerates loss of any 2
```

### 4.6 Certificate Rotation Procedures

The certificate hierarchy has three rotation cadences: node certificates
(frequent, automated), cluster intermediate CAs (periodic, semi-automated),
and the offline federation root CA (rare, planned ceremony).

#### Node Certificate Rotation (Automated)

Node certificates are short-lived (default: 24 hours) and MUST be
renewed automatically by `wirescale-control`.

```
Cadence: every 24 hours (configurable via WirescaleMesh CRD)
Trigger: automatic, ~50% of certificate lifetime remaining
Process:
  1. Agent detects certificate approaching renewal threshold
  2. Agent generates a new CSR and submits to wirescale-control
  3. Control signs the CSR with the cluster intermediate CA
  4. Agent installs the new certificate and re-establishes mTLS
  5. Old certificate remains valid until its original expiry

Monitoring:
  - Alert: wirescale_certificate_expiry_seconds < 7200 (2 hours)
  - Metric: wirescale_certificate_renewals_total
  - Metric: wirescale_certificate_renewal_failures_total
```

No manual intervention is required. Certificate renewal failure MUST
trigger a critical alert.

#### Cluster Intermediate CA Rotation (Semi-Automated)

Intermediate CAs have a longer lifetime (default: 1 year) and require
a pre-signing ceremony with the offline root CA.

```
Cadence: every 12 months (RECOMMENDED: initiate at 9 months)
Trigger: automated monitoring alert at 75% of intermediate CA lifetime

Phase 1: Offline ceremony (requires physical access to root CA HSM)
  1. Generate new intermediate CA keypair for the cluster
  2. Create CSR with the same cluster identity constraints
  3. Sign CSR with the offline federation root CA on the air-gapped HSM
  4. Verify the certificate chain: new intermediate CA -> root CA
  5. Deliver signed certificate to the cluster operator
  Duration: SHOULD complete within 1 business day

Phase 2: Online rotation (automated by wirescale-control)
  6. Upload new intermediate CA certificate to wirescale-control:
     kubectl -n wirescale-system create secret tls wirescale-cluster-ca-next \
       --cert=new-intermediate.crt --key=new-intermediate.key
  7. Control detects the new CA and begins dual-CA mode:
     - Both old and new intermediate CAs are trusted
     - New node certificates are signed by the new intermediate CA
  8. Control publishes the new intermediate CA to the global directory
  9. All agents renew their certificates within one rotation cycle (24h)
 10. After all agents hold certificates from the new CA:
     - Old intermediate CA is removed from the trust bundle
     - Old intermediate CA MAY be added to the root CRL for defense
       in depth

Grace period: both CAs MUST be trusted for at least 48 hours to allow
all agents to renew. The grace period SHOULD be configurable.

Monitoring:
  - Alert: wirescale_intermediate_ca_expiry_seconds < 90 days
  - Metric: wirescale_intermediate_ca_rotation_state
    (values: normal, dual_ca, completing)
```

#### Offline Root CA Rotation (Rare, Planned Ceremony)

Root CA rotation is a rare event that SHOULD occur only when the root CA
is approaching expiry (default lifetime: 10 years) or when a compromise
is suspected.

```
Cadence: every 10 years, or upon suspected compromise
Planning lead time: MUST be at least 60 days

Ceremony steps:
  1. Generate new root CA keypair on the air-gapped HSM
  2. Cross-sign: new root signs old root, old root signs new root
     (creates a trust bridge for the transition period)
  3. Re-sign all existing cluster intermediate CAs with the new root
     (requires one air-gapped ceremony per cluster, or batch signing)
  4. Package new trust bundle:
     - New root CA cert
     - Old root CA cert (for trust bridge)
     - All re-signed intermediate CA certs
     - Updated root CRL signed by new root
  5. Upload trust bundle to the global directory
  6. Verify: all cluster controllers refresh their trust bundles
  7. Grace period: minimum 30 days with both roots trusted
  8. Remove old root CA from the trust bundle
  9. Securely destroy old root CA key material on the HSM

Post-ceremony verification:
  - All clusters report successful trust bundle refresh
  - Cross-cluster mTLS handshakes succeed with new chain
  - No certificate validation errors in any cluster

Monitoring:
  - Alert: wirescale_root_ca_expiry_seconds < 365 days (1 year)
  - Metric: wirescale_trust_bundle_version (monotonically increasing)
```

### 4.7 Emergency CA Compromise Response

#### Cluster Intermediate CA Compromise

If a cluster's intermediate CA private key is suspected compromised:

```
Immediate actions (within 1 hour):
  1. Revoke the compromised intermediate CA:
     - Request root CA operator to add the intermediate to the root CRL
     - Publish updated CRL to the global directory
  2. Isolate the affected cluster:
     - Remove the cluster entry from the global directory
     - This prevents cross-cluster connections to/from the cluster

Re-establishment (within 24 hours):
  3. Generate a new intermediate CA keypair for the cluster
  4. Sign with the offline root CA (emergency air-gapped ceremony)
  5. Deploy the new intermediate CA to wirescale-control
  6. All agents in the cluster renew certificates automatically
  7. Re-register the cluster with the global directory
  8. Cross-cluster peers re-establish via trust bundle refresh

Impact: The compromised cluster experiences a brief cross-cluster
outage (hours). Intra-cluster operations continue if the new
intermediate CA is deployed promptly. Other clusters are unaffected.
```

#### Offline Root CA Compromise

If the federation root CA is suspected compromised, this is a
critical security event requiring full re-keying:

```
Immediate actions:
  1. Activate incident response
  2. Generate a new root CA on a fresh, verified HSM
  3. Re-sign ALL cluster intermediate CAs with the new root
     (this is the most time-consuming step)
  4. Distribute new trust bundles to all directory replicas
  5. All controllers refresh trust bundles
  6. Securely destroy the compromised root CA key material

Impact: Federation-wide re-keying ceremony. Each cluster must
participate in the intermediate CA re-signing. Total duration
depends on the number of clusters and the speed of the air-gapped
ceremonies. Intra-cluster operations continue throughout.

Prevention: The root CA MUST be stored on a FIPS 140-2 Level 3+
HSM, air-gapped, with multi-party authorization. Root CA compromise
requires physical access to the HSM and collusion of M-of-N key
holders.
```

---

## 5. Testing Strategy

### 5.1 Conformance Test Suite

A conformance suite MUST validate before any production release:
- Intra-cluster peer establishment within p99 latency budget (< 15 ms)
- Peer GC after configured `idleTimeout`
- WirescalePolicy enforcement for intra-cluster, cross-cluster, and
  external-peer traffic
- Identity cache miss triggers control query; cached identity used within TTL
- Cross-cluster connectivity: pods in `3fff:1234:0001::/48` reach pods in
  `3fff:1234:0002::/48` via on-demand WireGuard tunnels
- Agent restart does not drop in-flight connections
- Agent restart restores connectivity hints from disk and refreshes within 30 s
- Agent restart does NOT restore authorization state from disk
- WirescaleAccessGrant rules expire on schedule during control outage (fail closed)
- Agent enters degraded mode when control is unreachable at startup
- Cross-cluster connectivity (direct mode): pods in `3fff:1234:0001::/48`
  reach pods in `3fff:1234:0002::/48` via on-demand direct WireGuard tunnels
- Cross-cluster connectivity (relay mode): pods behind simulated NAT reach
  remote-cluster pods via relay gateway with end-to-end encryption preserved
- Relay-to-direct promotion: when direct reachability is restored, agent
  upgrades from relay to direct within the configured promotion interval
- Relay failover: when a relay gateway fails, affected sessions are
  reassigned to a surviving gateway within 10 s
- Agent restart does not drop in-flight connections (direct or relayed)
- Controller failover within 10 s
- 24-hour key rotation without handshake failures
- NAT64/CLAT translation over IPv6-only underlay

### 5.2 Integration Test Framework

Use `kind` or `k3d` for ephemeral multi-cluster environments. Test
scenarios: same-node and cross-node pod connectivity, cross-cluster
federation, policy enforcement (default-deny, allow-by-label,
cross-cluster), agent restart under load, controller failover, key
rotation cycles.

### 5.3 Performance Regression Tests

| Metric | Baseline | CI Gate |
|--------|---------|---------|
| Intra-cluster peer setup p99 | < 15 ms | Fail if > 20 ms |
| Identity resolution (miss) p99 | < 10 ms | Fail if > 15 ms |
| XDP throughput (64B packets) | > 5 Mpps | Fail if < 4 Mpps |
| WireGuard throughput (1400B, single flow, direct) | > 5 Gbps | Fail if < 4 Gbps |
| WireGuard throughput (1400B, single flow, relay) | > 4 Gbps | Fail if < 3 Gbps |
| Relay latency overhead (per hop) | < 1 ms | Fail if > 2 ms |
| Relay session establishment | < 50 ms | Fail if > 100 ms |
| Relay-to-direct promotion latency | < 65 s (1 cycle) | Fail if > 120 s |
| Relay failover (session reassignment) | < 10 s | Fail if > 15 s |
| Agent memory (100 peers) | < 80 MB | Fail if > 120 MB |
| Policy propagation p99 | < 1 s | Fail if > 2 s |

### 5.4 Chaos Testing

| Scenario | Expected Behavior |
|----------|-------------------|
| Agent-to-controller network partition | Connectivity hints preserved (TTL extended). Authorization state fails closed on TTL expiry. New establishment denied. Auto-recovery on heal. |
| Controller pod kill | Leader re-election < 5 s. Agents fail over. No data-plane impact. |
| Node failure | Peers time out at WireGuard rekey (~2 min). Remote agents GC stale peers. No cascade. |
| Certificate expiry | Handshake failures detected. Alert fires. Manual or auto-rotation restores connectivity. |
| Directory quorum loss | Intra-cluster unaffected. Cross-cluster new peers blocked. Cached connectivity hints continue. |
| Certificate expiry | Handshake failures detected. Alert fires. Automatic node cert rotation restores connectivity. |
| Intermediate CA rotation | Dual-CA mode activated. All agents renew within 24h. Cross-cluster partners accept new CA via trust bundle refresh. |
| Directory quorum loss | Intra-cluster unaffected. Cross-cluster new peers blocked. Cached peers continue. |
| BPF map exhaustion | New lookups fail. Agent logs map-full. Alert fires. Increase map size and redeploy. |
| Access grant expiry during control outage | Grant rules removed from BPF policy map at `expiresAt`. Access denied. `wirescale_authz_expired_during_outage_total` increments. Access restored only after control reconnect and fresh grant issuance. |
| Agent restart with stale peer cache | Connectivity hints restored, marked stale, refreshed within 30 s. Authorization state NOT restored from disk. Agent enters degraded mode if control is unreachable. |
| GUA preflight gate regression | `GUABaselineDegraded` alert fires. New external ingress rules blocked. Existing traffic unaffected. Remediate and re-verify. |

---

## 6. GUA Mode Preflight Checklist

> GUA routable-prefix mode is an **advanced configuration** where every
> pod receives a globally routable IPv6 address. Before enabling GUA
> mode, operators MUST complete the preflight checklist below.
> `wirescale-control` enforces these gates programmatically, but
> operators SHOULD also perform the manual verification steps to confirm
> end-to-end correctness.
>
> **ULA overlay (`fd00::/8`) is the RECOMMENDED default.** Only proceed
> with GUA enablement after the security posture is validated. See
> [ROUTABLE-PREFIX.md Section 2.5](ROUTABLE-PREFIX.md#25-prerequisites-and-safety-gates-for-gua-mode)
> for the normative gate definitions and
> [SECURITY.md](SECURITY.md#gua-routable-prefix-mode-advanced-security-posture)
> for the threat model context.

### 6.1 Pre-Enablement Checklist

Complete **every** item before setting `addressing.mode: gua` in the
`WirescaleMesh` resource.

#### Gate 1: Default-Deny Ingress Baseline

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 1.1 | Verify cluster-scoped default-deny policy exists | `kubectl get wirescalepolicy wirescale-default-deny-ingress -o yaml` | Policy exists with `podSelector: {}`, `policyTypes: ["Ingress"]`, no ingress rules |
| 1.2 | OR verify per-namespace coverage | `kubectl get networkpolicy -A -o json \| jq '[.items[] \| select(.spec.policyTypes \| index("Ingress"))] \| length'` | Count equals total namespace count (every namespace covered) |
| 1.3 | Verify no blanket allow-all ingress rules exist | `kubectl get wirescalepolicy -A -o json \| jq '.items[] \| select(.spec.ingress[]?.from[]?.ipBlock?.cidr == "::/0")'` | No results (or only in namespaces with `wirescale.io/external-reachable: "true"`) |
| 1.4 | Confirm controller reports gate passed | `kubectl get wirescalemesh default -o jsonpath='{.status.conditions[?(@.type=="GUAPreflightPassed")].status}'` | `True` |

#### Gate 2: XDP Ingress Firewall Health

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 2.1 | Verify all nodes report XDP healthy | `kubectl get wirescalenodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.xdpFirewallStatus}{"\n"}{end}'` | Every node shows `healthy` |
| 2.2 | Verify XDP program hash matches known-good | `kubectl wirescale xdp-status --verify-hash` | `OK: all nodes match expected hash` |
| 2.3 | Verify default XDP action is DROP | On each node: `bpftool prog show \| grep wirescale_ingress_firewall` and verify the `external_ingress_map` default is DROP | Program loaded, default action = DROP |
| 2.4 | Check firewall health ratio | `curl -s :9091/metrics \| grep wirescale_xdp_firewall_healthy_nodes` | `wirescale_xdp_firewall_healthy_nodes / wirescale_total_gua_nodes == 1.0` |

#### Gate 3: Route Advertisement Scope

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 3.1 | Verify `routeAdvertisement.scope` is set | `kubectl get wirescalemesh default -o jsonpath='{.spec.routeAdvertisement.scope}'` | `fabric-only` (RECOMMENDED), `site`, or `global` |
| 3.2 | If scope is `global`, verify acknowledgment | `kubectl get wirescalemesh default -o jsonpath='{.spec.routeAdvertisement.acknowledgeGlobalExposure}'` | `true` |
| 3.3 | Verify /64 routes do NOT leak beyond fabric | Check fabric BGP looking glass or route monitoring tool | Per-host /64 routes visible only within cluster fabric; only the aggregate /48 visible at site border or upstream |
| 3.4 | Verify aggregate /48 is correctly announced | `ip -6 route show \| grep <cluster-prefix>` on a border router or peer | Single /48 aggregate present |

#### Gate 4: Namespace Opt-In

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 4.1 | List namespaces opted in for external reachability | `kubectl get ns -l wirescale.io/external-reachable=true` | Only namespaces that intentionally host internet-facing services |
| 4.2 | Verify non-opted-in namespaces have no external ingress rules | `kubectl get wirescalepolicy -A -o json \| jq '.items[] \| select(.spec.ingress[]?.from[]?.ipBlock?) \| .metadata.namespace' \| sort -u` | All listed namespaces are in the opted-in set from 4.1 |
| 4.3 | Verify controller rejects external ingress for non-opted-in namespaces | Create a test `WirescalePolicy` with `ipBlock.cidr: "::/0"` in a non-opted-in namespace | Rejected with `NamespaceNotExternalReachable` event |

#### Gate 5: Controller Preflight Aggregation

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 5.1 | Verify all gates pass in controller status | `kubectl get wirescalemesh default -o jsonpath='{.status.conditions[?(@.type=="GUAPreflightPassed")]}'` | `status: "True"`, `reason: "AllGatesPassed"` |
| 5.2 | Check controller logs for preflight summary | `kubectl logs -n wirescale-system -l app=wirescale-control \| grep PREFLIGHT` | All five gates show `PASS` |
| 5.3 | Verify no `GUAPreflightFailed` events | `kubectl get events -n wirescale-system --field-selector reason=GUAPreflightFailed` | No events |

### 6.2 Post-Enablement Verification

After setting `addressing.mode: gua` and confirming the preflight
passes:

| # | Step | Command / Verification | Expected Result |
|---|------|----------------------|-----------------|
| 6.1 | Verify pods receive GUA addresses | `kubectl get pods -A -o wide \| grep 3fff:` | Pods show GUA addresses from the cluster prefix |
| 6.2 | Verify intra-cluster connectivity | `kubectl exec -it test-pod -- ping6 -c 3 <pod-on-another-node>` | 0% packet loss |
| 6.3 | Verify external inbound is blocked by default | From an external host: `nc -6 -z <pod-gua-address> 8080` | Connection refused or timeout (XDP drops) |
| 6.4 | Verify opted-in namespace allows external ingress | Create `WirescalePolicy` allowing `::/0` on port 443 in an opted-in namespace, then connect from external host | Connection succeeds on port 443 only |
| 6.5 | Verify non-opted-in namespace blocks external ingress | From an external host: `nc -6 -z <pod-in-non-opted-ns> 443` | Connection refused or timeout |
| 6.6 | Verify outbound IPv6 works without SNAT | `kubectl exec -it test-pod -- curl -6 -s https://ipv6.icanhazip.com` | Returns the pod's GUA address |

### 6.3 Ongoing Monitoring for GUA Mode

The following alerts MUST be configured when GUA mode is active, in
addition to the standard alerts in Section 3.3:

| Alert | Condition | Severity | Action |
|-------|----------|----------|--------|
| `GUABaselineDegraded` | Default-deny ingress policy removed or weakened | critical | Restore baseline immediately; new external ingress rules blocked until resolved |
| `XDPFirewallUnhealthy` | Any GUA node reports `xdpFirewallStatus != healthy` | critical | Investigate node; controller will not allocate new GUA prefixes to unhealthy nodes |
| `GUAPreflightFailed` | Controller preflight check fails on reconciliation | warning | Identify failing gate from controller logs; remediate before next node addition |
| `RouteLeakDetected` | Per-host /64 routes observed outside cluster fabric (requires external route monitoring integration) | critical | Withdraw leaked routes immediately; verify fabric BGP filters |
| `UnauthorizedExternalIngress` | External ingress policy compiled for a namespace without `wirescale.io/external-reachable` label | warning | Should not occur if controller enforcement is working; investigate controller state |

### 6.4 Rollback: GUA to ULA

If GUA mode must be disabled (security incident, misconfiguration, or
operational decision):

| Step | Action | Impact |
|------|--------|--------|
| 1 | Update `WirescaleMesh`: set `addressing.mode: ula` | Controller stops allocating GUA prefixes for new pods |
| 2 | Cordon and drain nodes one at a time | Pods are rescheduled with ULA addresses; existing GUA pods continue until drained |
| 3 | Verify no GUA pods remain | `kubectl get pods -A -o wide \| grep 3fff:` returns no results |
| 4 | Withdraw GUA aggregate from BGP | Remove /48 announcement from site border routers |
| 5 | Verify ULA connectivity | Intra-cluster: pods use `fd00:1234:` addresses; cross-cluster: WireGuard tunnels |

Rolling back does NOT require cluster downtime. The drain process
migrates pods incrementally. Cross-cluster connectivity is maintained
through WireGuard tunnels using ULA addressing throughout the
rollback.
| Relay gateway failure | Control reassigns relayed sessions to surviving gateways (< 10 s). Direct sessions unaffected. |
| All relay gateways fail | Relayed sessions disrupted. Direct sessions unaffected. Manual intervention to restore relay capacity. |
| Relay-to-direct network change | Agent detects direct reachability on next promotion cycle (60 s). Upgrades to direct mode automatically. |
| Relay gateway overload | Per-source rate limits enforce fairness. Excess sessions rejected with backpressure. Agent retries on alternate gateway. |
