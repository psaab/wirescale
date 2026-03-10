### 9.1 StatefulSet Stable Network Identities

> This subsection belongs in Section 9 "DNS Architecture" of
> ARCHITECTURE.md, after the "DNS Query Flow" subsection.

#### The Challenge

Kubernetes StatefulSets provide stable DNS names via headless Services:
`web-0.web.<ns>.svc.cluster.local` survives rescheduling.  The IP
address behind that name does not.

In Wirescale, pod IPs derive from the hosting node's /64 prefix
(`3fff:1d:CCCC:HHHH::P`).  When a StatefulSet pod moves to a different
node, `HHHH` changes:

```
web-0 on node-3:  3fff:1d:0001:0003::1 / 100.64.3.1
web-0 on node-7:  3fff:1d:0001:0007::1 / 100.64.7.1  (after reschedule)
```

This is consistent with standard Kubernetes -- pod IPs are always
ephemeral -- but certain patterns are sensitive to it:

- **IP caching:** Connection pools or gRPC channels that resolve once
  and hold the IP for the lifetime of the connection.
- **Ordinal discovery:** Patterns like "connect to `web-{0..N-1}`" that
  resolve all peers at startup and cache the results.
- **Storage affinity:** PVs with node affinity constrain rescheduling,
  reducing IP changes in practice but not eliminating them.

#### Interaction with Wirescale DNS

Both Kubernetes DNS and Wirescale DNS (`*.ws.cluster.internal`) MUST
return the current pod IP after rescheduling:

```
web-0.web.default.svc.cluster.local   -> AAAA 3fff:1d:0001:0007::1
web-0.web.default.ws.cluster.internal -> AAAA 3fff:1d:0001:0007::1
```

The wirescale-agent MUST update its in-memory name-to-IP map within 5
seconds of receiving a pod relocation event from wirescale-control.
CoreDNS cache TTL (default 30s, per Section 8.3) bounds how quickly
downstream clients observe the change.

#### Stable IPs Are a Non-Goal

Wirescale does NOT provide node-independent stable IPs for StatefulSet
pods.  A reserved /128 pool would require:

- Addresses outside the /64-per-host model, breaking hierarchical
  prefix aggregation (Section 5).
- Per-pod /128 routes on every node, regressing routing state from
  O(hosts) to O(statefulset_pods).
- Scheduler-to-allocator coordination to ensure the /128 is routable
  regardless of placement.

This contradicts the design principles in Section 2 (hierarchical
aggregation, minimal per-node state).

#### Operator Guidance

1. **Use DNS names, not IPs.**  All StatefulSet peer communication
   MUST go through DNS.  Applications SHOULD re-resolve on reconnect
   rather than caching addresses indefinitely.

2. **Lower DNS TTLs for latency-sensitive workloads.**  Operators MAY
   reduce the CoreDNS cache TTL for faster convergence:
   ```
   cache 5   # 5-second TTL
   ```

3. **Retry with re-resolution.**  Applications SHOULD trigger a fresh
   DNS lookup on connection failure rather than retrying a cached IP.

4. **Topology constraints.**  Use `topologySpreadConstraints` or node
   affinity to reduce cross-node rescheduling frequency where stable
   placement is operationally important.

5. **ClusterIP for stable VIPs.**  When a fixed address is needed
   (e.g., a database primary), use a ClusterIP Service instead of a
   headless Service.  The VIP is allocated from the Service CIDR
   (`3fff:1d:CCCC:ffff::/108`) and is placement-independent.
