# app/parsers/pcap_parser.py
from collections import Counter, defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from typing import Dict, Any
import os
from .scan_detect import scan_detect


def summarize_pcap(pcap_path: str, max_packets: int = 250000) -> Dict[str, Any]:
    """
    Stream-parse a PCAP for summary stats without loading into memory.
    Returns: overall counts, protocol mix, top talkers, common ports, rough timeline.
    """
    total = 0
    proto_counts = Counter()
    talkers = Counter()  # ("src->dst") flow-ish
    src_counts = Counter()
    dst_counts = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    timeline = defaultdict(int)  # second bucket -> packet count

    first_ts = None

    # Stream read
    packets = []
    with PcapReader(pcap_path) as pr:
        # for each packet in the capture
        for i, pkt in enumerate(pr):
            if i >= max_packets:
                break
            packets.append(pkt)
            total += 1

            # Timestamp bucketing (per-second)
            if hasattr(pkt, "time"):
                if first_ts is None:
                    first_ts = int(pkt.time)
                bucket = int(pkt.time) - first_ts
                timeline[bucket] += 1

            # L3 address extraction
            src = dst = None

            l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)

            if l3:
                src = l3.src
                dst = l3.dst
                src_counts[src] += 1
                dst_counts[dst] += 1
                if src and dst:
                    talkers[f"{src} → {dst}"] += 1

            # L4/protocol
            if TCP in pkt:
                proto_counts["TCP"] += 1
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport:
                    tcp_ports[dport] += 1
                if sport:
                    tcp_ports[sport] += 1
            elif UDP in pkt:
                proto_counts["UDP"] += 1
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if dport:
                    udp_ports[dport] += 1
                if sport:
                    udp_ports[sport] += 1
            else:
                # Best-effort protocol label
                if l3:
                    proto_counts[l3.name] += 1
                else:
                    proto_counts["OTHER"] += 1

    # Format top items
    def top(counter, n=10):
        return [{"value": k, "count": v} for k, v in counter.most_common(n)]

    # Timeline as sorted list of {t: second_since_start, count}
    timeline_list = [{"t": k, "count": timeline[k]} for k in sorted(timeline.keys())]
    scan_events = scan_detect(packets, include_aux=True)

    return {
        "file": os.path.basename(pcap_path),
        "total_packets": total,
        "protocols": [{"name": k, "count": v} for k, v in proto_counts.most_common()],
        "top_talkers": top(talkers, 10),
        "top_sources": top(src_counts, 10),
        "top_destinations": top(dst_counts, 10),
        "top_tcp_ports": top(tcp_ports, 10),
        "top_udp_ports": top(udp_ports, 10),
        "timeline": timeline_list,
        "truncated": total >= max_packets,
        "scans": scan_events,
    }
