from collections import defaultdict
from typing import List, Dict, Any
from scapy.all import TCP, IP, IPv6


def detect_scans(
    packets: List[Any], syn_threshold: int = 10, window: int = 5
) -> List[Dict[str, Any]]:
    """
    Detects basic SYN scans (e.g., nmap, port sweeps) in a list of scapy packets.
    Returns a list of scan events with timestamps and details.

    Args:
      syn_threshold: Number of unique ports touched within the window
                     that triggers a scan alert
      window: Time window (in seconds) to evaluate unique ports
    """

    # Dictionary keyed by source IP storing tuples of:
    # (timestamp, destination IP, destination port)
    # Example:
    #   { "10.0.0.5": [(1682616000, "10.0.0.10", 22), (...) ] }
    syn_attempts = defaultdict(list)

    # Final results are appended here
    scan_events = []

    # --- PASS 1: Collect only SYN packets ---
    for pkt in packets:
        # Check if this packet is TCP and contains the SYN flag (0x02)
        if TCP in pkt and (pkt[TCP].flags & 0x02):

            # Extract IPv4 or IPv6 layer for addresses
            l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if not l3:
                continue  # skip if no IP layer found

            # Source / destination information
            src = l3.src
            dst = l3.dst
            dport = pkt[TCP].dport  # port being scanned
            ts = int(pkt.time)  # timestamp from the packet

            # Store attempt in dictionary
            syn_attempts[src].append((ts, dst, dport))

    # --- PASS 2: Analyze SYN attempts by source for scanning patterns ---
    for src, attempts in syn_attempts.items():

        # Sort attempts by timestamp (oldest -> newest)
        attempts.sort()

        # Sliding window technique:
        # Move the window start forward one event at a time
        for i in range(len(attempts)):
            t0 = attempts[i][0]  # starting timestamp for this window

            ports = set()  # track unique destination ports
            dsts = set()  # track unique destination IPs

            # Expand the window forward in time
            for j in range(i, len(attempts)):
                t, dst, dport = attempts[j]

                # Stop if we exceed the window size
                if t - t0 > window:
                    break

                ports.add(dport)
                dsts.add(dst)

            # If unique ports exceed threshold -> likely a scan
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

                # Avoid reporting multiple events for same source
                break

    # Return detected scan events for analyst review
    return scan_events


"""
How the SYN Scan Detection Works:

1 - Collect SYN Packets:

    -It loops through all packets and selects only those that are TCP and have the SYN flag set (indicating a connection attempt).
    
    -For each SYN packet, it extracts the source IP, destination IP, destination port, and timestamp.
    
    -It groups these attempts by source IP in a dictionary.
    
    
2 - Analyze for Scanning Patterns:

    -For each source IP, it sorts the SYN attempts by time.

    -It uses a sliding time window (default 5 seconds) to look for bursts of SYNs.

    -For each window, it counts how many unique destination ports were targeted.

    -If the number of unique ports in the window meets or exceeds the threshold (default 10), it flags this as a scan event.


3 - Report Results:

    - For each detected scan, it records the source IP, time window, unique ports and destinations, and scan type.

    - It returns a list of all detected scan events.
    
"""
