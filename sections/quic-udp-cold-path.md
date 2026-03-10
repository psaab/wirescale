### QUIC and UDP Protocols Through Cold Paths

> Extends: PERFORMANCE.md Section 5 (On-Demand Peering Performance)

Section 5 documents the cold-path interaction with TCP, noting that the
TCP SYN retransmit timer (~1s default) provides ample budget for the
7-15 ms intra-cluster establishment latency. UDP-based protocols have
fundamentally different retry semantics and MUST be handled explicitly.

#### The UDP Cold-Path Problem

When a packet triggers the cold path and no WireGuard peer exists, the
kernel has no transport-layer state to hold the packet. Unlike TCP, where
the SYN sits in the socket's retransmit queue, UDP packets are
fire-and-forget at the transport layer. If the agent drops or fails to
queue the triggering packet, recovery depends entirely on the
application-layer protocol -- or does not happen at all.

#### Agent Queuing for UDP

The wirescale-agent MUST maintain a per-destination packet queue for
cold-path establishment. When egress eBPF detects a missing peer, it
MUST redirect the packet to a userspace capture ring (via
`bpf_ringbuf_output` or `BPF_MAP_TYPE_QUEUE`) rather than silently
dropping it. The agent replays queued packets once the WireGuard peer
is established.

Queue parameters:
- **Capacity:** 64 packets per destination (configurable via
  `WirescaleAgent` CRD field `coldPathQueueSize`).
- **Timeout:** Queued packets MUST be dropped if peer establishment
  does not complete within 5 seconds (configurable via
  `coldPathQueueTimeout`).
- **Memory bound:** Total cold-path queue memory MUST NOT exceed 16 MB
  per node to prevent resource exhaustion from scanning or port sweeps.

This queuing mechanism benefits all UDP protocols equally: DNS, QUIC,
gaming, VoIP, and any custom UDP application.

#### QUIC-Specific Considerations

QUIC (RFC 9000) uses UDP and manages its own connection establishment,
loss detection, and retry logic. Several QUIC behaviors interact with
cold-path latency:

**Initial handshake.** QUIC clients send an Initial packet containing a
CRYPTO frame. If the WireGuard peer is not yet established, the agent's
packet queue holds this Initial packet. QUIC's Probe Timeout (PTO,
typically ~1s initial value per RFC 9002 Section 6.2) provides
sufficient budget for intra-cluster cold paths (~7-15 ms). Cross-cluster
cold paths (~30-150 ms) also complete well within a single PTO.

**0-RTT early data.** QUIC clients with cached session tickets MAY send
0-RTT data in the same flight as the Initial packet. This early data
is not retransmittable by QUIC's loss recovery if it was never
acknowledged. The agent's cold-path queue MUST capture 0-RTT packets
alongside the Initial packet so they are delivered intact after peer
establishment. Without queuing, 0-RTT data is irrecoverably lost and
the connection falls back to 1-RTT, adding one RTT of latency.

**Retry packets.** QUIC servers MAY respond with a Retry packet for
address validation. Retry interactions add one additional RTT before
the handshake proceeds. The cold-path queue MUST be bidirectional:
if the responding server's node also needs to establish a return peer,
the Retry packet is queued on that side as well.

#### Protocols Without Application-Layer Retry

Certain UDP protocols lack any retry mechanism:

| Protocol | Retry Behavior | Cold-Path Risk |
|----------|---------------|----------------|
| DNS (stub) | Client retries after 1-5s | Low: queue covers the gap |
| DNS (iterative) | Resolver retries after ~2s | Low |
| QUIC | PTO-based, ~1s initial | Low with queuing |
| NTP | Poll interval 64-1024s | Negligible |
| syslog (UDP) | No retry | Loss acceptable |
| Gaming/VoIP (RTP) | No retry, tolerates loss | First 7-150 ms of media lost |

For latency-sensitive real-time protocols (VoIP, gaming), applications
SHOULD pre-warm the WireGuard peer path by sending an initial probe
packet during connection setup. The warm-path latency (~0.1 ms) is
documented in Section 5 and imposes no ongoing penalty.

#### Guidance for Operators

1. Applications using QUIC through Wirescale SHOULD NOT disable 0-RTT
   solely due to cold-path concerns. The agent's packet queue preserves
   0-RTT data during peer establishment.
2. Operators running latency-sensitive UDP workloads (sub-millisecond
   budgets) SHOULD configure pre-warming via the `WirescaleAgent` CRD
   field `preWarmDestinations` to avoid first-packet cold-path delays.
3. The agent SHOULD expose `wirescale_cold_path_queue_drops_total` and
   `wirescale_cold_path_queue_depth` metrics per node for observability.
