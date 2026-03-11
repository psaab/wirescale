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

---

## Table of Contents

1. [Upgrade and Migration Strategy](#1-upgrade-and-migration-strategy)
2. [Capacity Planning](#2-capacity-planning)
3. [Monitoring and Alerting](#3-monitoring-and-alerting)
4. [Backup and Disaster Recovery](#4-backup-and-disaster-recovery)
5. [Testing Strategy](#5-testing-strategy)

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
throughout the upgrade.

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

Read:write ratio is ~1000:1. Storage per cluster: ~1 KB (cluster ID,
endpoints, prefix allocation, CA fingerprint, metadata).

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

### 2.5 Scaling Decision Table

| Signal | Threshold | Action |
|--------|----------|--------|
| Control gRPC p99 > 50 ms | Sustained 5 min | Add controller replicas |
| Controller CPU > 80% | Sustained 10 min | Scale up or increase limits |
| Cluster approaching 10K nodes | Planning horizon | Split cluster; use federation |
| `identity_cache_evictions` rate rising | Sustained 30 min | Increase `identityCache.maxEntries` |
| Any BPF map > 80% full | Any occurrence | Increase map size, redeploy agents |
| Cross-cluster query p99 > 200 ms | Sustained 5 min | Add directory replicas, check network |

---

## 3. Monitoring and Alerting

### 3.1 Prometheus Metrics Reference

Metrics are exposed at two endpoints (see [SECURITY.md Section 12](SECURITY.md#12-audit-and-observability)):

- **`wirescale-agent`** at `:9090/metrics` -- WireGuard peers, policy
  decisions, identity cache, peer cache, NAT64, cross-cluster flows.
- **`wirescale-control`** at `:9091/metrics` -- nodes, identities, policy
  compilations, peer authorizations, gRPC server, directory health.

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

---

## 4. Backup and Disaster Recovery

### 4.1 State Classification

| Category | Examples | Loss Impact |
|----------|---------|-------------|
| **Critical** | Directory data (cluster registry, prefix allocations), CA private keys, CRD definitions | Federation-wide outage or security compromise |
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

**Directory etcd:** Take snapshots at least every 4 hours:
```bash
ETCDCTL_API=3 etcdctl snapshot save /backup/directory-$(date +%Y%m%d).snap \
  --endpoints=https://etcd-1.directory.example.com:2379 \
  --cacert=/etc/etcd/ca.crt --cert=/etc/etcd/client.crt --key=/etc/etcd/client.key
```

**CRDs:** Include all Wirescale CRDs (WirescaleMesh, WirescaleNode,
WirescalePolicy, WirescaleCluster, WirescaleExternalPeer,
WirescaleAccessGrant, WirescaleServiceExport/Import) in Velero backups
or etcd snapshots.

**CA key escrow:** The cluster CA is the one exception to the no-escrow
policy for node keys. Back up the CA secret encrypted at rest:
```bash
kubectl -n wirescale-system get secret wirescale-ca -o yaml | \
  gpg --encrypt --recipient ops-team@example.com > /backup/ca-$(date +%Y%m%d).yaml.gpg
```

### 4.3 Recovery Procedures

**Directory:** Stop all members, restore etcd snapshot, restart members,
verify quorum. Controllers re-register on their next heartbeat (60 s).
During the outage, intra-cluster operations are unaffected; only new
cross-cluster peer establishment is blocked.

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
| Directory (etcd) | <= 4 hours | <= 30 min | Snapshot restore + quorum |
| Controller | 0 (stateless) | <= 2 min | Pod restart + cache rebuild |
| Agent (connectivity hints) | 0 (ephemeral) | <= 30 s | Pod restart + disk restore + stale refresh |
| Agent (authorization state) | 0 (not persisted) | <= 30 s | Fresh validation from control required; fail closed until available |
| CA keys | <= 24 hours | <= 1 hour | Encrypted backup restore |
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
| WireGuard throughput (1400B, single flow) | > 5 Gbps | Fail if < 4 Gbps |
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
| BPF map exhaustion | New lookups fail. Agent logs map-full. Alert fires. Increase map size and redeploy. |
| Access grant expiry during control outage | Grant rules removed from BPF policy map at `expiresAt`. Access denied. `wirescale_authz_expired_during_outage_total` increments. Access restored only after control reconnect and fresh grant issuance. |
| Agent restart with stale peer cache | Connectivity hints restored, marked stale, refreshed within 30 s. Authorization state NOT restored from disk. Agent enters degraded mode if control is unreachable. |
