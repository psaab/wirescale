# Regulatory Compliance Mapping

> Standalone section for SECURITY.md.
>
> Maps regulatory and framework requirements to specific Wirescale
> capabilities. This document is informational guidance, not legal advice.
> Operators MUST perform their own compliance assessment with qualified
> auditors.
>
> Normative language: MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be
> interpreted as described in RFC 2119 and RFC 8174 when shown in all caps.

## PCI-DSS v4.0

| Control | Requirement | Wirescale Capability | Notes |
|---------|-------------|---------------------|-------|
| 1.2 | Network segmentation controls | WireGuard full-mesh encryption isolates inter-node traffic; eBPF deny-by-default policy enforces microsegmentation at the pod level. Cryptokey routing ensures only authorized peers exchange traffic. | Segmentation is cryptographic, not VLAN-based. |
| 1.3 | Restrict inbound/outbound access to CDE | WirescalePolicy CRDs and NetworkPolicy define explicit allow rules per identity. Deny-by-default posture blocks all traffic not explicitly permitted. | Policies reference Kubernetes identity (ServiceAccount, namespace, labels), not IP addresses. |
| 1.4 | Controls between trusted and untrusted networks | Cross-cluster federation requires dual-side policy enforcement: both the source and destination cluster MUST authorize the flow. External peer access requires explicit WirescaleExternalPeer resources. | Untrusted boundary is enforced at the WireGuard peer layer. |
| 2.2 | Secure system configuration standards | Agent runs with read-only root filesystem, minimal capabilities (CAP_BPF, CAP_NET_ADMIN only), no key escrow, memory-only private keys. Control runs as stateless HA replicas with restricted RBAC. | Container hardening follows CIS Kubernetes Benchmark. |
| 4.1 | Strong cryptography for transmission | All inter-node traffic encrypted via WireGuard (ChaCha20-Poly1305, Curve25519 key exchange). Control-plane traffic protected by mTLS. No plaintext inter-node path exists. | Encryption is non-negotiable and always on. |
| 7.1 | Least privilege access | Identity-based policy grants access only to explicitly permitted (identity, port, protocol) tuples. WirescaleAccessGrant provides time-bounded privilege escalation that automatically expires. | Access is scoped to Kubernetes ServiceAccount identity. |
| 8.3 | Strong authentication mechanisms | Node admission requires mTLS with X.509 certificates from the cluster intermediate CA. Three-tier CA hierarchy (offline federation root CA, per-cluster intermediate CA, node certificate) provides layered authentication. | No shared secrets for node authentication; each node holds a unique keypair. Offline root CA is HSM-backed and air-gapped. |
| 10.1 | Audit trail mechanisms | eBPF ring buffer emits per-connection audit events with full identity attribution (pod, namespace, ServiceAccount, labels, node, cluster). Control-plane operations (peer authorization, identity queries, policy changes, revocations) are logged with timestamps. | Logs include identity, not just IP, enabling attribution across pod rescheduling. |
| 11.5 | IDS/IPS and change detection | eBPF enforcement logs all denied connections. Anomaly detection SHOULD alert on mass peer authorizations, identity changes for stable pods, and policy generation spikes. eBPF program hash verification detects tampering with enforcement code. | Runtime BPF audit via `bpftool` detects modified enforcement programs. |

## HIPAA (Security Rule, 45 CFR Part 164)

| Provision | Requirement | Wirescale Capability | Notes |
|-----------|-------------|---------------------|-------|
| 164.312(a)(1) | Access Control: allow access only to authorized persons/software | Deny-by-default eBPF policy. Identity-based access control tied to Kubernetes ServiceAccount. WirescaleAccessGrant for time-bounded exceptions. Pull-based model ensures nodes only learn identities for active flows. | Technical safeguard: unique identity per workload. |
| 164.312(a)(2)(i) | Unique User Identification | Each pod inherits a unique identity tuple: (cluster, namespace, ServiceAccount, labels, node). Numeric identity assigned by controller. Node identity bound to unique Curve25519 keypair. | Identity is cryptographically verifiable via WireGuard handshake. |
| 164.312(a)(2)(iii) | Automatic Logoff | WirescaleAccessGrant resources carry an explicit TTL. Expired grants are automatically removed. WireGuard sessions rekey every 2 minutes; revoked peers cannot complete rekey. Idle peer garbage collection removes stale peer state. | No persistent standing access beyond policy-defined grants. |
| 164.312(b) | Audit Controls: record and examine activity | Per-connection audit events via eBPF ring buffer with identity attribution. Control-plane audit log covers all authentication, authorization, policy, and revocation events. Prometheus metrics for operational monitoring. | Audit events include both allow and deny decisions (deny always logged; allow configurable per policy). |
| 164.312(c)(1) | Integrity: protect ePHI from improper alteration | WireGuard Poly1305 MAC authenticates every packet. Tampered packets are rejected before decryption. eBPF program hash verification ensures enforcement code integrity. Image signing prevents supply-chain tampering. | Integrity protection is per-packet, not per-session. |
| 164.312(e)(1) | Transmission Security: guard against unauthorized access during transmission | WireGuard ChaCha20-Poly1305 encryption on all inter-node traffic. mTLS on all control-plane channels. No unencrypted inter-node path. Unknown WireGuard peers are silently dropped (no information leak). | Encryption covers both east-west (pod-to-pod) and control-plane traffic. |
| 164.312(e)(2)(ii) | Encryption mechanism | ChaCha20-Poly1305 (256-bit symmetric), Curve25519 (ECDH key exchange), BLAKE2s (hashing). PSK option available for post-quantum defense in depth (see post-quantum migration roadmap). | NIST-equivalent security levels. PSK SHOULD be enabled for environments with long data retention requirements. |

## SOC 2 Type II (Trust Services Criteria)

| Criterion | Requirement | Wirescale Capability | Notes |
|-----------|-------------|---------------------|-------|
| CC6.1 | Logical Access Security | Three-tier CA hierarchy authenticates all participants. mTLS for control-plane access. WireGuard cryptokey routing restricts data-plane access to authorized peers. Identity-based policy enforced in eBPF at every node. | Logical access is identity-based and cryptographically enforced. |
| CC6.6 | System Boundaries | WireGuard full-mesh defines an explicit cryptographic boundary: only nodes with authorized key pairs participate. Cross-cluster flows require federation through the global directory and dual-side policy approval. External peers require explicit WirescaleExternalPeer resources. | Boundary is defined by cryptographic peer authorization, not network topology. |
| CC6.7 | Transmission Integrity and Security | All inter-node transmission encrypted (ChaCha20-Poly1305) and authenticated (Poly1305 MAC, Curve25519 mutual auth). Control-plane protected by mTLS. Key rotation every 24 hours (configurable); WireGuard rekeys every 2 minutes for forward secrecy. | No unencrypted transmission path between nodes. |
| CC7.2 | System Monitoring | eBPF audit events for all denied connections. Prometheus metrics for peer health, policy generation, cache performance, handshake failures, and cross-cluster operations. Control-plane audit log for all authentication, authorization, and revocation events. Alerting on anomalous patterns (mass peer auth, identity changes). | Monitoring covers both data plane (eBPF events) and control plane (gRPC audit log). |

## Cross-Framework Summary

The following table maps Wirescale architectural properties to the
controls they satisfy across all three frameworks.

| Wirescale Property | PCI-DSS v4.0 | HIPAA | SOC 2 Type II |
|--------------------|-------------|-------|---------------|
| WireGuard always-on encryption | 4.1 | 164.312(e) | CC6.7 |
| Deny-by-default eBPF policy | 1.2, 1.3, 7.1 | 164.312(a) | CC6.1 |
| Identity-based access control | 1.3, 7.1 | 164.312(a) | CC6.1 |
| Three-tier CA hierarchy | 8.3 | 164.312(a)(2)(i) | CC6.1 |
| Per-connection audit logging | 10.1, 11.5 | 164.312(b) | CC7.2 |
| Time-bounded access grants | 7.1 | 164.312(a)(2)(iii) | CC6.1 |
| Cryptographic peer boundary | 1.2, 1.4 | 164.312(e) | CC6.6 |
| Key rotation and forward secrecy | 4.1, 8.3 | 164.312(e)(2)(ii) | CC6.7 |
| eBPF program integrity verification | 2.2, 11.5 | 164.312(c) | CC7.2 |
| Container hardening (read-only FS, minimal caps) | 2.2 | 164.312(c) | CC6.1 |

## Auditor Guidance

Operators preparing for compliance audits SHOULD:

- Enable per-connection audit logging (`audit: true` on relevant
  WirescalePolicy resources) for workloads in the compliance scope.
- Verify PSK is enabled on all peer pairs within the compliance boundary
  (required for environments where HNDL is a concern under HIPAA
  164.312(e)(2)(ii)).
- Collect `wirescale_policy_generation` metrics to demonstrate that
  policy enforcement is current and not stale.
- Retain control-plane audit logs for the period required by the
  applicable framework (PCI-DSS: 12 months online, HIPAA: 6 years,
  SOC 2: per auditor agreement).
- Document the deny-by-default posture by showing that no
  WirescalePolicy or NetworkPolicy exists granting blanket allow-all
  within the compliance scope.
