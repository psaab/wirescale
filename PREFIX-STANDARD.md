# Wirescale: Canonical Example Prefix Standard

All documentation examples MUST use the prefixes defined below.
GUA examples use `3fff::/20` per RFC 9637. Never use `2001:db8::/32`.

---

## 1. Canonical Prefixes

| Role | Prefix | Notes |
|------|--------|-------|
| **GUA org prefix** | `3fff:1234::/32` | Organization-level allocation from `3fff::/20` |
| **GUA per-cluster** | `3fff:1234:CCCC::/48` | /48 per cluster; C = cluster index |
| **GUA per-host** | `3fff:1234:CCCC:HHHH::/64` | /64 per host; H = host index |
| **GUA pod address** | `3fff:1234:CCCC:HHHH::P/128` | P = pod index within host |
| **GUA service CIDR** | `3fff:1234:CCCC:ffff::/108` | Per-cluster service VIPs |
| **GUA rack prefix** | `3fff:1234:CCCC:ffNN::/64` | NN = rack index; shared L2 segment |
| **GUA rack range** | `3fff:1234:CCCC:ff00::/56` | Reserved for rack /64s within each cluster |
| **ULA org prefix** | `fd00:1234::/32` | Matches GUA structure at /32 |
| **ULA per-cluster** | `fd00:1234:CCCC::/48` | /48 per cluster (matches GUA) |
| **ULA per-host** | `fd00:1234:CCCC:HHHH::/64` | /64 per host |
| **ULA pod address** | `fd00:1234:CCCC:HHHH::P/128` | Pod within host |
| **CGNAT IPv4** | `100.64.0.0/10` | Per-node: `100.64.N.0/24` |
| **NAT64 prefix** | `64:ff9b::/96` | Well-known, RFC 6052 |

### Prefix length justification: /48 per cluster for both GUA and ULA

ROUTABLE-PREFIX.md already uses /48 per cluster for GUA. ARCHITECTURE.md uses
/32 per cluster, which wastes address bits and diverges from standard practice
(RIRs allocate /48 to sites). Using /48 everywhere:

- Gives 65,536 hosts per cluster (sufficient for any single cluster).
- Gives 65,536 clusters per /32 org prefix (sufficient for any organization).
- Keeps ULA and GUA structures identical, simplifying dual-mode addressing.
- Matches the convention in ROUTABLE-PREFIX.md, which has the most detailed
  routing examples.

The /32 scheme in ARCHITECTURE.md gave 2^32 hosts per cluster but only
4,096 clusters per /20 -- an unnecessary tradeoff.

### Node underlay (WireGuard endpoint) addresses

Node underlay addresses are on the physical network, not the overlay.
In examples, use the host's rack address for endpoints:
`[3fff:1234:CCCC:ffNN::HH]:51820`

For cross-cluster examples where a short form is needed, use
`[3fff:1234:CCCC:ff01::HH]:51820` (rack 1 of that cluster).

### External peers

External peers use a dedicated cluster index (e.g., `00ff`):
`3fff:1234:00ff::/48` (GUA) or `fd00:1234:00ff::/48` (ULA).

---

## 2. Per-Document Change Mapping

### ARCHITECTURE.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `3fff:1d::/20` (federation pfx) | `3fff:1234::/32` (org pfx) | Prefix and length |
| `3fff:1d:0001::/32` (cluster) | `3fff:1234:0001::/48` | Prefix and length |
| `3fff:1d:CCCC:HHHH::/64` | `3fff:1234:CCCC:HHHH::/64` | Prefix only |
| `3fff:1d:CCCC:ffff::/108` (svc) | `3fff:1234:CCCC:ffff::/108` | Prefix only |
| `3fff:1d:e1:1::/64` (external) | `3fff:1234:00ff:0001::/64` | Use dedicated cluster index |
| `3fff::2a`, `3fff::6b` etc. (endpoints) | `3fff:1234:0001:ff01::2a` etc. | Use rack addresses |
| `3fff:0f01::1`, `3fff:0e01::1` (fed endpoints) | `3fff:1234:00ff:ff01::1` | Use external peer rack addr |
| `3fff:aa:0001::N` (gateway) | `3fff:1234:0001:ff01::N` | Gateways use rack addresses |
| `3fff:c2::2` (remote node) | `3fff:1234:0002:ff01::2` | Use rack address in cluster 2 |

### ROUTABLE-PREFIX.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `3fff:1234::/32` (org) | `3fff:1234::/32` | No change (already canonical) |
| `3fff:1234:CCCC::/48` (cluster) | `3fff:1234:CCCC::/48` | No change |
| `3fff:1234:CCCC:HHHH::/64` (host) | `3fff:1234:CCCC:HHHH::/64` | No change |
| `3fff:1234:CCCC:ffNN::/64` (rack) | `3fff:1234:CCCC:ffNN::/64` | No change |
| `fd00:1d::/16` (ULA org) | `fd00:1234::/32` | Prefix and length |
| `fd00:1d:0001::/32` (ULA cluster) | `fd00:1234:0001::/48` | Prefix and length |
| `fd00:1d:0001:HHHH::/64` (ULA host) | `fd00:1234:0001:HHHH::/64` | Prefix only |
| `fd00:1d:00ff::/32` (ULA external) | `fd00:1234:00ff::/48` | Prefix and length |

### PERFORMANCE.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `fd00:1d::/32` (fleet) | `fd00:1234::/32` | Prefix only |
| `3fff:1::/32` (GUA fleet) | `3fff:1234::/32` | Prefix only |
| `fd00:1d:0::/48` (cluster A) | `fd00:1234:0001::/48` | Prefix; use explicit cluster index |
| `fd00:1d:N::/48` (cluster) | `fd00:1234:CCCC::/48` | Prefix only |
| `fd00:1d:N:H::/64` (host) | `fd00:1234:CCCC:HHHH::/64` | Prefix only |
| `fd00:1d:1::5` etc. (pod) | `fd00:1234:0001:0001::5` | Use 4-hextet form consistently |

### CILIUM-INTEGRATION.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `3fff:0a00::/48` (site) | `3fff:1234:0001::/48` | Align to canonical cluster prefix |
| `3fff:0a00:ff01::/64` (rack) | `3fff:1234:0001:ff01::/64` | Align to canonical |
| `3fff:0a00:0001::/64` (host) | `3fff:1234:0001:0001::/64` | Align to canonical |
| `3fff:0a00:ff01::11` (rack addr) | `3fff:1234:0001:ff01::11` | Align to canonical |

### SECURITY.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `3fff:c1::/48` (cluster 1) | `3fff:1234:0001::/48` | Align to canonical |
| `3fff:c2:3::7` (pod in cluster 2) | `3fff:1234:0002:0003::7` | Align to canonical |
| `fd00:1d:1::5` etc. (ULA pod) | `fd00:1234:0001:0001::5` | Use 4-hextet form |
| `fd00:1d:3::12` (ULA pod) | `fd00:1234:0003:0001::12` | Use 4-hextet form |

### CILIUM-SECURITY-GAPS.md

| Current | Canonical | What changes |
|---------|-----------|--------------|
| `3fff:1234:0001:0001::a` (pod) | No change | Already canonical |
| `3fff:0e01::1` (endpoint) | `3fff:1234:00ff:ff01::1` | Use external peer convention |
| `3fff:1d:e1:1::1` (external) | `3fff:1234:00ff:0001::1` | Use external peer convention |

---

## 3. Summary of Structural Changes

1. **Cluster prefix length:** `/32` -> `/48` everywhere (ARCHITECTURE.md, SECURITY.md).
2. **GUA org prefix:** Standardize on `3fff:1234::/32` (not `3fff:1d::/20` or `3fff:0a00::`).
3. **ULA org prefix:** Standardize on `fd00:1234::/32` (not `fd00:1d::/16` or `fd00:1d::/32`).
4. **ULA cluster length:** `/32` -> `/48` to match GUA (affects ARCHITECTURE.md, ROUTABLE-PREFIX.md).
5. **Underlay endpoints:** Use rack addresses (`CCCC:ffNN::HH`) instead of ad-hoc short forms.
6. **External peers:** Use cluster index `00ff` instead of `e1` or other ad-hoc values.
