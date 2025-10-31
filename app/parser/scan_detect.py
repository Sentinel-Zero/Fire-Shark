from collections import defaultdict
from typing import Any, Dict, List, Tuple
from scapy.all import TCP, IP, IPv6


def scan_detect(
    packets: List[Any],
    handshake_timeout: float = 5.0,
    include_aux: bool = False,
) -> List[Dict[str, Any]]:
    """
    Classify TCP handshake-based scan sequences.

    Primary (for timeline):
      - full_handshake:        SYN -> SYN+ACK -> ACK
      - half_open_rst:         SYN -> SYN+ACK -> RST
      - half_open_silent:      SYN -> SYN+ACK -> (no client reply by timeout)

    Auxiliary (context only; disabled unless include_aux=True):
      - syn_rst:               SYN -> RST                (closed port)
      - syn_timeout:           SYN -> (no reply/timeout) (filtered / silent drop)

    Returns a list of events:
      {
        "type": "<classification>",
        "src": <client ip>, "sport": <client port>,
        "dst": <server ip>, "dport": <server port>,
        "start_time": <float>, "end_time": <float>,
        "evidence": ["SYN","SYN+ACK","ACK" | "RST" | "no-reply"],
      }
    """
    # Per-flow state keyed so that the SYN sender is always "client"
    flows: Dict[Tuple[str, int, str, int], Dict[str, Any]] = defaultdict(
        lambda: {"events": [], "first_ts": None, "last_ts": None}
    )

    def l3(pkt):
        return pkt.getlayer(IP) or pkt.getlayer(IPv6)

    # 1) Collect events
    for pkt in packets:
        if TCP not in pkt:
            continue
        ip = l3(pkt)
        if not ip:
            continue

        src, dst = ip.src, ip.dst
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
        ts = float(pkt.time)

        is_syn = bool(flags & 0x02)
        is_ackbit = bool(flags & 0x10)
        is_rst = bool(flags & 0x04)
        is_synack = is_syn and is_ackbit

        # Normalize key so the client (SYN sender) is first
        if is_syn and not is_synack:
            key = (src, sport, dst, dport)  # client -> server
        elif is_synack:
            key = (dst, dport, src, sport)  # reply from server
        else:
            k1 = (src, sport, dst, dport)
            k2 = (dst, dport, src, sport)
            key = k1 if k1 in flows else k2

        st = flows[key]
        if st["first_ts"] is None:
            st["first_ts"] = ts
        st["last_ts"] = ts

        if is_syn and not is_synack:
            st["events"].append(("SYN", ts))
        elif is_synack:
            st["events"].append(("SYN+ACK", ts))
        elif is_rst:
            st["events"].append(("RST", ts))
        elif is_ackbit:
            st["events"].append(("ACK", ts))
        else:
            # Not strictly needed for this classifier
            st["events"].append(("OTHER", ts))

    # 2) Classify per-flow
    results: List[Dict[str, Any]] = []
    for (c_ip, c_port, s_ip, s_port), st in flows.items():
        # Compress to unique sequence order-wise (ignore duplicate retransmits)
        seq = []
        for e, _t in st["events"]:
            if not seq or seq[-1] != e:
                seq.append(e)

        evset = set(seq)
        start, end = st["first_ts"], st["last_ts"]

        saw_syn = "SYN" in evset
        saw_synack = "SYN+ACK" in evset
        saw_ack = "ACK" in evset
        saw_rst = "RST" in evset

        def emit(_type: str, evidence: List[str]):
            results.append(
                {
                    "type": _type,
                    "src": c_ip,
                    "sport": c_port,
                    "dst": s_ip,
                    "dport": s_port,
                    "start_time": start,
                    "end_time": end,
                    "evidence": evidence,
                }
            )

        # Primary classes (for your timeline)
        if saw_syn and saw_synack and saw_ack:
            emit("full_handshake", ["SYN", "SYN+ACK", "ACK"])
            continue

        if saw_syn and saw_synack and saw_rst:
            emit("half_open_rst", ["SYN", "SYN+ACK", "RST"])
            continue

        if saw_syn and saw_synack and not (saw_ack or saw_rst):
            # No client follow-up. Require the last event to be older than timeout.
            if (end - start) >= handshake_timeout:
                emit("half_open_silent", ["SYN", "SYN+ACK", "no-reply"])
            # else still in-flight; skip classification for now
            continue

        # Auxiliary context (closed/filtered), optional
        if include_aux:
            if saw_syn and saw_rst and not saw_synack:
                emit("syn_rst", ["SYN", "RST"])
                continue
            if (
                saw_syn
                and not (saw_synack or saw_ack or saw_rst)
                and (end - start) >= handshake_timeout
            ):
                emit("syn_timeout", ["SYN", "no-reply"])
                continue

    return results


"""
How the Handshake-Based Scan Detection Works:

1. Collect TCP handshake events per flow:
   - For each TCP packet, extract the 4-tuple (client IP/port, server IP/port) and TCP flags.
   - Normalize flows so the SYN sender is always the client.
   - Record the sequence of handshake-relevant events (SYN, SYN+ACK, ACK, RST) with timestamps.

2. Classify each flow by handshake outcome:
   - If the flow contains SYN → SYN+ACK → ACK, classify as a full TCP handshake (connect scan or legitimate connection).
   - If the flow contains SYN → SYN+ACK → RST, classify as a half-open SYN scan (client resets after SYN+ACK).
   - If the flow contains SYN → SYN+ACK and no client reply within the timeout, classify as half-open silent (possible scan, no follow-up).
   - Optionally, if enabled, also classify SYN → RST (closed port) and SYN → (no reply/timeout) as auxiliary context.

3. Report results:
   - For each detected scan or handshake outcome, output the classification, flow details, timing, and the observed handshake sequence as evidence.
   - This enables timeline and statistical analysis of scan types and connection attempts.
"""
