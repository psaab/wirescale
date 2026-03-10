### NUMA-Aware Packet Processing

> Extends: PERFORMANCE.md Section 12 (Kernel Tuning)

Section 12 documents RSS/RPS configuration for distributing WireGuard
UDP flows across CPU cores. At 40-100 Gbps link speeds, multi-core
distribution alone is insufficient -- cross-NUMA memory accesses add
~70-100 ns of latency per cache-line miss and reduce effective memory
bandwidth by 30-50%. Wirescale deployments at these speeds MUST ensure
NUMA-local affinity for all components of the packet processing pipeline.

#### NUMA Locality Requirements

The following components participate in per-packet processing and MUST
be co-located on the same NUMA node as the physical NIC:

1. **NIC interrupt handlers (hardirq).** IRQ affinity MUST pin NIC
   receive interrupts to CPUs on the NUMA node local to the NIC's PCIe
   slot.
2. **NAPI poll / softirq threads.** These run on the CPU that received
   the interrupt and inherit its NUMA placement from IRQ affinity.
3. **XDP programs on the physical NIC.** XDP runs in softirq context
   on the interrupt CPU; correct IRQ affinity ensures NUMA locality.
4. **WireGuard kthreads (threaded NAPI on wg0).** After decryption,
   threaded NAPI kthreads SHOULD be affined to the same NUMA node via
   `taskset` or cgroup cpuset. The scheduler MAY migrate them otherwise.
5. **BPF map memory.** Maps used in the hot path (identity_cache,
   policy_map, peer_cache) SHOULD be allocated on NUMA-local memory.

#### IRQ Affinity Configuration

The wirescale-agent MUST configure NIC IRQ affinity at startup. For a
NIC on NUMA node 0 with CPUs 0-15:

```bash
# Identify NUMA node for the NIC
NIC_NUMA=$(cat /sys/class/net/eth0/device/numa_node)
# Get CPU list for that NUMA node
NUMA_CPUS=$(cat /sys/devices/system/node/node${NIC_NUMA}/cpulist)

# Pin each NIC IRQ to NUMA-local CPUs
for irq in $(grep eth0 /proc/interrupts | awk -F: '{print $1}'); do
    echo "$NUMA_CPUS" > /proc/irq/${irq}/smp_affinity_list
done
```

When RPS is used (software steering), the `rps_cpus` mask documented in
Section 12 MUST be restricted to NUMA-local CPUs rather than set to
`ffffffff`. Steering packets to a remote NUMA node for softirq processing
negates the benefit of multi-core distribution.

#### WireGuard kthread Affinity

Threaded NAPI kthreads for `wg0` appear as `napi/wg0-<N>` in the
process table. The agent SHOULD pin these to the NIC-local NUMA node:

```bash
for pid in $(pgrep -f 'napi/wg0'); do
    taskset -pc "$NUMA_CPUS" "$pid"
done
```

If the system has multiple NICs on different NUMA nodes (e.g., bonded
interfaces), the agent MUST identify which physical NIC carries WireGuard
traffic and pin kthreads to that NIC's NUMA node.

#### BPF Map NUMA Allocation

BPF maps are allocated from the CPU that calls `bpf_map_create`. The
agent MUST ensure that map creation runs on a NUMA-local CPU so the
backing pages are allocated from local memory. For the hot-path maps
(identity_cache, policy_map, peer_cache), this avoids cross-NUMA
lookups on every packet.

```bash
# Run BPF loader pinned to NUMA-local CPUs
numactl --cpunodebind=$NIC_NUMA --membind=$NIC_NUMA \
    wirescale-agent load-bpf
```

Alternatively, the agent MAY use `set_mempolicy(MPOL_BIND)` before map
creation to force NUMA-local allocation programmatically.

#### XDP Redirect and NUMA Boundaries

`bpf_redirect_map` and `bpf_redirect` transmit packets on the target
device's TX queue. If the target NIC is on a different NUMA node than
the source NIC, the redirect crosses a NUMA boundary. This scenario
arises when NAT64 redirects from a `nat64` dummy interface to a physical
NIC on a different NUMA node.

Deployments MUST ensure the physical NIC used for WireGuard egress is
on the same NUMA node as the NIC used for WireGuard ingress. On systems
with a single NIC this is automatic. On multi-NIC systems, the agent
SHOULD log a warning if NUMA mismatch is detected.

#### Monitoring

Operators SHOULD use the following tools to verify NUMA-local operation:

| Tool | Purpose |
|------|---------|
| `numastat -p $(pgrep wirescale)` | Per-node memory allocation for the agent |
| `numastat -m` | System-wide NUMA memory distribution |
| `perf stat -e node-load-misses` | Cross-NUMA cache-line transfers |
| `cat /proc/interrupts` | Verify IRQ distribution across CPUs |
| `lstopo` (hwloc) | Visualize NIC-to-NUMA topology |

A sustained `node-load-misses` rate above 5% of total memory accesses
during packet processing indicates NUMA misconfiguration. The agent
SHOULD expose `wirescale_numa_cross_node_redirects_total` as a
Prometheus metric when redirect targets cross NUMA boundaries.
