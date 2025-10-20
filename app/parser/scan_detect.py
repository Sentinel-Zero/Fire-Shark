from collections import defaultdict
from typing import List, Dict, Any
from scapy.all import TCP, IP, IPv6


def detect_scans(
    packets: List[Any], syn_threshold: int = 10, window: int = 5
) -> List[Dict[str, Any]]:
    """
    Detects basic SYN scans (e.g., nmap, port sweeps) in a list of scapy packets.
    Returns a list of scan events with timestamps and details.
    - syn_threshold: number of unique ports in window seconds to consider a scan
    - window: time window in seconds
    """
    # Structure: {src_ip: [(timestamp, dst_ip, dst_port)]}
    syn_attempts = defaultdict(list)
    scan_events = []

    for pkt in packets:
        if TCP in pkt and (pkt[TCP].flags & 0x02):  # SYN flag
            l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if not l3:
                continue
            src = l3.src
            dst = l3.dst
            dport = pkt[TCP].dport
            ts = int(pkt.time)
            syn_attempts[src].append((ts, dst, dport))

    # Analyze for scans
    for src, attempts in syn_attempts.items():
        # Sort by timestamp
        attempts.sort()
        # Sliding window
        for i in range(len(attempts)):
            t0 = attempts[i][0]
            ports = set()
            dsts = set()
            for j in range(i, len(attempts)):
                t, dst, dport = attempts[j]
                if t - t0 > window:
                    break
                ports.add(dport)
                dsts.add(dst)
            if len(ports) >= syn_threshold:
                scan_events.append(
                    {
                        "src": src,
                        "start_time": t0,
                        "end_time": t,
                        "unique_ports": list(ports),
                        "unique_dsts": list(dsts),
                        "count": len(ports),
                        "type": "SYN scan",
                    }
                )
                # Skip ahead to avoid duplicate events
                break
    return scan_events
