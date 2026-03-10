### 8.6 Cross-Cluster IPv4 Address Collisions

> This subsection belongs in Section 8 "IPv4 in an IPv6-Only World" of
> ARCHITECTURE.md, after Section 8.5 "IPv4 Within the Mesh".

#### The Problem

The CLAT mapping `100.64.N.P <--> 3fff:1d:CCCC:N::P` embeds the node
index `N` and pod index `P` but not the cluster index `CCCC`.  Two pods
on identically-indexed nodes in different clusters receive the same IPv4
address:

```
Cluster 1, Node 3, Pod 7:  100.64.3.7  <-->  3fff:1d:0001:0003::7
Cluster 2, Node 3, Pod 7:  100.64.3.7  <-->  3fff:1d:0002:0003::7
```

Both pods believe they own `100.64.3.7`.  Within a single cluster this
is unambiguous because CLAT resolves the IPv4 address against the local
cluster's IPv6 prefix.  Across clusters, the same IPv4 address maps to
two distinct IPv6 endpoints and the reverse translation is ambiguous.

#### Design Decision: IPv4 Is Intra-Cluster Only

Cross-cluster pod-to-pod traffic MUST use IPv6 addresses.  The CGNAT
`100.64.0.0/10` address space is scoped to the originating cluster and
MUST NOT be routed across cluster boundaries.

Rationale:

1. **Ambiguous reverse mapping.**  A destination of `100.64.3.7` cannot
   be translated to a unique IPv6 address without knowing the target
   cluster -- information that is absent from the IPv4 packet.
2. **Address space exhaustion.**  `100.64.0.0/10` provides ~4 million
   addresses.  Partitioning it across clusters (e.g., `/16` per cluster)
   severely limits per-cluster pod capacity and introduces fragile
   coordination between the global directory and CLAT configuration.
3. **IPv6 is the primary address family.**  Wirescale is an IPv6-native
   architecture.  Cross-cluster connectivity (Section 7) operates on
   hierarchical IPv6 prefixes with route aggregation; IPv4 is a
   compatibility layer for legacy applications, not a routable fabric.

#### Enforcement

The wirescale-agent MUST NOT install CLAT reverse-translation routes
for remote clusters.  Specifically:

- The `100.64.0.0/10` route on each node MUST point only to the local
  CLAT translation path, never to a WireGuard peer in another cluster.
- Cross-cluster aggregate routes (`3fff:1d:CCCC::/32` for remote
  clusters) MUST NOT have corresponding IPv4 CGNAT routes.
- If a pod attempts to reach an IPv4 address that maps to a remote
  cluster's IPv6 prefix, the packet MUST be dropped and the agent
  SHOULD log a diagnostic message.

#### Operator Guidance

Applications that require cross-cluster communication MUST use IPv6
addresses or DNS names that resolve to IPv6 (AAAA records).  The
cross-cluster DNS system (Section 9) returns AAAA records for remote
pods; operators SHOULD NOT configure A record synthesis for cross-cluster
names.

For legacy applications that cannot use IPv6 socket APIs, operators MAY
deploy an application-layer proxy (e.g., Envoy, HAProxy) within the
local cluster that accepts IPv4 connections and forwards to the remote
pod's IPv6 address.

```
Legacy IPv4 app -> 100.64.N.P (local proxy pod)
  -> proxy opens IPv6 connection to 3fff:1d:CCCC:H::Q (remote pod)
  -> cross-cluster WireGuard tunnel (IPv6)
  -> remote pod receives IPv6 connection
```

This preserves the deterministic CLAT model within each cluster while
providing a clear upgrade path for cross-cluster IPv4 consumers.
