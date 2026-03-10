## Multicast and Neighbor Discovery Through WireGuard

> Cross-cutting concern for ARCHITECTURE.md (ULA overlay mode) and
> ROUTABLE-PREFIX.md (selective / `always` encryption mode).

### Background

IPv6 NDP (RFC 4861) relies on link-local multicast -- solicited-node
multicast `ff02::1:ffXX:XXXX` -- to resolve addresses to link-layer
addresses.  WireGuard is Layer 3 point-to-point: it carries routed
unicast and does not forward link-local multicast.

### When NDP Works Natively

**Routable-prefix mode with unencrypted forwarding** (ROUTABLE-PREFIX.md
Section 7, encryption policy = `default` or `cross-cluster-only`):

- Intra-cluster traffic traverses the physical L2 segment.
- NDP operates on `eth0` against the rack /64 as usual.
- Cross-node traffic within the same L2 domain resolves the next-hop
  (ToR gateway) via standard NDP on `eth0`.

No Wirescale-specific handling is required in this mode.

### When NDP Needs Help

**ULA overlay mode** (ARCHITECTURE.md Section 6) and **routable-prefix
with `always` encryption** (ROUTABLE-PREFIX.md Section 8):

All inter-node pod traffic goes through `wg0`, which has no link-layer
address resolution.  NDP solicitations sent into `wg0` have no
meaningful recipient.

| Scenario | Interface | NDP Status |
|----------|-----------|------------|
| Same node | `cni0` bridge / veth | Works (local L2) |
| Cross-node, overlay/always-encrypt | `wg0` | Broken (L3 P2P) |
| Pod-to-external, overlay | `wg0` -> physical | Broken on `wg0` leg |
| Host NDP on physical NIC | `eth0` | Works (native L2) |

### Solution: NDP Suppression on Overlay Paths

The wirescale-agent MUST suppress NDP on WireGuard paths and rely on
explicit routing entries from the control plane:

1. **Explicit /64 routes.**  When the agent installs a WireGuard peer,
   it programs the remote node's entire /64 via the `wg0` nexthop.
   Individual pod /128s within that /64 are resolved by the remote node
   after decryption -- no local neighbor resolution is needed.

2. **Static neighbor entries for local pods.**  The agent MUST install
   static or proxy neighbor entries on `cni0` for each local pod's
   link-local and global addresses, ensuring intra-node NDP succeeds
   without multicast.

3. **eBPF NDP interception.**  The agent SHOULD attach a TC/XDP program
   on `wg0` that drops NDP Neighbor Solicitation packets, preventing
   unresolvable solicitations from wasting tunnel bandwidth.

```
Pod A (node-1) -> Pod B (node-2), overlay mode:

  Pod A sends to 3fff:1d:0001:0002::b
    -> host routing: 3fff:1d:0001:0002::/64 via wg0 peer=node-2
    -> NO NDP: route is explicit, nexthop is the WireGuard peer
    -> wg0 encrypts, sends to node-2
    -> node-2 decrypts, routes to Pod B via local veth (local bridge)
```

### Multicast Applications (mDNS, MLD)

General IPv6 multicast (`ff02::/16`, `ff05::/16`) does not traverse
WireGuard.  Implications:

- **mDNS / DNS-SD** (`ff02::fb`): MUST NOT be relied upon for
  cross-node discovery.  Use Wirescale DNS (ARCHITECTURE.md Section 9).
- **MLD:** Unaffected in routable-prefix native mode.  In overlay mode,
  MLD is confined to the local node's bridge.
- **Application multicast:** Workloads needing cross-node multicast
  MUST be adapted to unicast or use an external multicast overlay.

The agent SHOULD log a warning when multicast traffic is destined for
`wg0`.

### Summary

| Traffic Type | Native/Routable Mode | Overlay / Always-Encrypt Mode |
|-------------|---------------------|-------------------------------|
| NDP (same node) | Works | Works (local bridge) |
| NDP (cross-node) | Works (physical L2) | Suppressed; explicit routes |
| Solicited-node multicast | Works | Dropped on `wg0` |
| mDNS / DNS-SD | Works on L2 segment | Use Wirescale DNS |
| Application multicast | Works on L2 segment | Not available cross-node |
