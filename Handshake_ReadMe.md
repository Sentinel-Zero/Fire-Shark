## TCP Handshake-Based Scan Classification (TCP only)

**Updated:** 2025-10-30

This branch focuses on classifying scans by **TCP handshake outcomes** only. It observes `SYN / SYN+ACK / ACK / RST` sequences and excludes non-handshake techniques (e.g., FIN/NULL/XMAS, ACK-only, UDP, ICMP).

### Handshake Outcome Table

| Observed Sequence | Likely Meaning / Classification | Default Action |
|---|---|---|
| `SYN → SYN+ACK → ACK` | Full 3-way handshake — legitimate connection or **connect() scan** (completed handshake). | Track volume (no per-flow alert) |
| `SYN → SYN+ACK → RST` | **SYN (half-open) scan** — client resets after SYN+ACK to avoid completing handshake. | **Alert** (high signal) |
| `SYN → RST` | **Closed port** (server refused immediately). Common during scanning but not a scan type by itself. | Log / count; alert only in bulk |
| `SYN → (no reply / timeout)` | **Filtered / silently dropped** (firewall) or loss. Suspicious if repeated across many ports. | Log; correlate over time |
| `SYN → SYN+ACK → (no client reply)` | Possible loss, IDS interference, or scanner not following through. Suspicious in bulk. | Log; correlate over time |

> Implementation note: treat SYN retransmits as duplicates (same 4-tuple within a short round trip time RTT window).

### Out of Scope for This Branch (to handle in separate detectors)
- Timeline (digging up a pcap with mutliple scans at dif times)
- FIN/NULL/XMAS scans (non-handshake flag probes)
- ACK-only firewall probes
- UDP scans (ICMP Port Unreachable behavior)
- ICMP ping sweeps and host discovery
- Distributed/slow-rate meta-detections (aggregate across sources/long windows)
