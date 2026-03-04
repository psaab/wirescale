# Source Index

Primary references used during claim validation across all four documents.

## WireGuard

- https://www.wireguard.com/
- https://www.wireguard.com/protocol/
- https://www.wireguard.com/install/
- https://www.wireguard.com/xplatform/
- https://man7.org/linux/man-pages/man8/wg.8.html
- https://man7.org/linux/man-pages/man8/wg-quick.8.html
- https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/messages.h
- https://github.com/WireGuard/wireguard-go

## IETF RFCs and IANA Registries

- RFC 7748 (X25519): https://www.rfc-editor.org/rfc/rfc7748
- RFC 8439 (ChaCha20-Poly1305): https://www.rfc-editor.org/rfc/rfc8439
- RFC 4291 (IPv6 Addressing): https://datatracker.ietf.org/doc/html/rfc4291
- RFC 4861 (NDP): https://datatracker.ietf.org/doc/html/rfc4861
- RFC 4862 (SLAAC): https://datatracker.ietf.org/doc/html/rfc4862
- RFC 7421 (/64 boundary analysis): https://datatracker.ietf.org/doc/html/rfc7421
- RFC 6052 (Well-known NAT64 prefix): https://datatracker.ietf.org/doc/html/rfc6052
- RFC 6146 (Stateful NAT64): https://datatracker.ietf.org/doc/html/rfc6146
- RFC 6147 (DNS64): https://datatracker.ietf.org/doc/html/rfc6147
- RFC 6598 (100.64.0.0/10): https://datatracker.ietf.org/doc/html/rfc6598
- RFC 6877 (464XLAT): https://datatracker.ietf.org/doc/html/rfc6877
- RFC 7915 (SIIT): https://datatracker.ietf.org/doc/html/rfc7915
- RFC 8201 (IPv6 PMTUD): https://datatracker.ietf.org/doc/html/rfc8201
- RFC 8215 (Local-use NAT64 prefix): https://datatracker.ietf.org/doc/html/rfc8215
- RFC 6762 (`.local` special-use): https://datatracker.ietf.org/doc/html/rfc6762
- RFC 9637 (documentation prefixes): https://datatracker.ietf.org/doc/rfc9637/
- IANA IPv6 special registry: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
- IANA IPv6 unicast assignments: https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml

## Linux Kernel / eBPF / Networking

- NAPI docs: https://docs.kernel.org/networking/napi.html
- Linux scaling (RSS/RPS/RFS): https://docs.kernel.org/networking/scaling.html
- AF_XDP docs: https://docs.kernel.org/networking/af_xdp.html
- Linux net sysctls: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html
- Linux IP sysctls: https://docs.kernel.org/networking/ip-sysctl.html
- Capabilities: https://man7.org/linux/man-pages/man7/capabilities.7.html
- `ip-link` man page: https://man7.org/linux/man-pages/man8/ip-link.8.html
- BPF helpers man page: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
- `bpf_skb_change_proto` helper: https://docs.ebpf.io/linux/helper-function/bpf_skb_change_proto/
- BPF hash map semantics: https://docs.kernel.org/bpf/map_hash.html
- BPF LPM trie: https://docs.kernel.org/bpf/map_lpm_trie.html
- BPF ring buffer: https://www.kernel.org/doc/html/next/bpf/ringbuf.html
- nftables conntrack metadata: https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation
- nftables packet mangling: https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers
- ethtool man page: https://man7.org/linux/man-pages/man8/ethtool.8.html

## Kubernetes

- Dual-stack and single-stack behavior: https://kubernetes.io/docs/concepts/services-networking/dual-stack/
- Network plugins / CNI model: https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/
- Cluster networking concepts: https://kubernetes.io/docs/concepts/cluster-administration/networking/
- NetworkPolicy semantics: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- NetworkPolicy API type (`NetworkPolicyPeer`): https://pkg.go.dev/k8s.io/api/networking/v1
- RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Admission controllers: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- Access control overview: https://kubernetes.io/docs/concepts/security/controlling-access/

## CNI / CoreDNS / Ecosystem / Cloud

- CNI spec: https://github.com/containernetworking/cni/blob/main/SPEC.md
- CoreDNS `dns64` plugin: https://coredns.io/plugins/dns64/
- Cilium WireGuard docs: https://docs.cilium.io/en/stable/security/network/encryption-wireguard.html
- Cilium routing docs: https://docs.cilium.io/en/stable/network/concepts/routing/
- Calico IPv6 docs: https://docs.tigera.io/calico/latest/networking/ipam/ipv6
- Calico WireGuard docs: https://docs.tigera.io/calico/latest/security/encrypt-cluster-pod-traffic
- Kilo introduction: https://kilo.squat.ai/docs/introduction/
- Tailscale Kubernetes operator: https://tailscale.com/docs/features/kubernetes-operator/
- AWS public IPv4 charge note: https://aws.amazon.com/blogs/aws/new-aws-public-ipv4-address-charge-public-ip-insights/
- NRO IPv4 depletion notice: https://www.nro.net/ipv4-free-pool-depleted/
- AWS prefix delegation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html
- AWS MTU guidance: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html
- GCP subnet docs: https://cloud.google.com/vpc/docs/subnets
- GCP IPv6 VM docs: https://cloud.google.com/compute/docs/ip-addresses/configure-ipv6-address

## Performance Research References Cited in Raw Reports

- WireGuard GRO/GSO patch thread: https://lore.kernel.org/netdev/20190809021355.17431-1-Jason@zx2c4.com/
- Netdev WireGuard Inline session: https://netdevconf.info/0x18/sessions/wireguard-inline-optimizations-for-networking-stack-bypassing.html
- Netdev performance patch discussion: https://www.spinics.net/lists/netdev/msg1036260.html
- Netdev threading/NAPI discussion: https://www.spinics.net/lists/netdev/msg1118848.html
- Red Hat network tuning guide: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/tuning-the-network-performance_monitoring-and-managing-system-status-and-performance
