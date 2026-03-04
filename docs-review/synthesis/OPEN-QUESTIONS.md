# Open Questions and Unverifiable Premises

These questions should be answered before finalizing architectural claims.

## Architecture and Routing

1. Is the canonical cross-site design worker-level WireGuard, gateway-only WireGuard transit, or both as separate modes?
2. What is the authoritative prefix-allocation strategy for production (real provider-allocated GUA examples)?
3. Should `.local` be avoided entirely for internal service naming in this design?

## Security

1. Which controls in `SECURITY.md` are implemented today vs planned?
2. Is default-deny installed automatically, or is policy opt-in?
3. What is the exact RBAC boundary for node-scoped writes and how is ownership enforced?
4. Are logs tamper-evident or simply observational?

## Performance

1. What kernel versions and NIC families are considered baseline support targets?
2. Which published throughput/latency values have reproducible benchmark artifacts?
3. What is the canonical NAT64/CLAT hookpoint model used in implementation?
4. What is the authoritative MTU/MSS table by underlay and mode?

## Translation and Ingress

1. For IPv4-client -> IPv6-pod ingress, which mechanism is intended: NAT46, SIIT-DC, reverse proxy, or multiple patterns?
2. If multiple edge patterns are supported, how is policy and source attribution normalized across them?
