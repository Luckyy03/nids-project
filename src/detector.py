from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, DNS

# --- Thresholds (tweak these) ---
PORT_SCAN_THRESHOLD  = 15   # unique ports in 10 seconds = port scan
SYN_FLOOD_THRESHOLD  = 100  # SYN packets in 10 seconds = SYN flood
DNS_TUNNEL_THRESHOLD = 30   # DNS queries in 10 seconds = tunneling
WINDOW_SECONDS       = 10

# --- State tracking dictionaries ---
port_tracker = defaultdict(lambda: {"ports": set(), "times": []})
syn_tracker  = defaultdict(list)
dns_tracker  = defaultdict(list)

def _clean_window(times):
    cutoff = datetime.now() - timedelta(seconds=WINDOW_SECONDS)
    return [t for t in times if t > cutoff]

def detect_port_scan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None
    src = pkt[IP].src
    dst_port = pkt[TCP].dport
    now = datetime.now()
    tracker = port_tracker[src]
    tracker["ports"].add(dst_port)
    tracker["times"] = _clean_window(tracker["times"])
    tracker["times"].append(now)
    recent_ports = len([t for t in tracker["times"] if t > datetime.now() - timedelta(seconds=WINDOW_SECONDS)])
    if recent_ports >= PORT_SCAN_THRESHOLD:
        return {
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": src,
            "detail": f"{recent_ports} ports probed in {WINDOW_SECONDS}s",
            "timestamp": now.isoformat()
        }
    return None

def detect_syn_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None
    if "S" not in str(pkt[TCP].flags) or "A" in str(pkt[TCP].flags):
        return None   # Only pure SYN, not SYN-ACK
    src = pkt[IP].src
    now = datetime.now()
    syn_tracker[src] = _clean_window(syn_tracker[src])
    syn_tracker[src].append(now)
    count = len(syn_tracker[src])
    if count >= SYN_FLOOD_THRESHOLD:
        return {
            "type": "SYN_FLOOD",
            "severity": "CRITICAL",
            "src_ip": src,
            "detail": f"{count} SYN packets in {WINDOW_SECONDS}s",
            "timestamp": now.isoformat()
        }
    return None

def detect_dns_tunneling(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
        return None
    src = pkt[IP].src
    now = datetime.now()
    dns_tracker[src] = _clean_window(dns_tracker[src])
    dns_tracker[src].append(now)
    # Also check for suspiciously long DNS query names
    try:
        qname = pkt[DNS].qd.qname.decode()
        if len(qname) > 50:
            return {
                "type": "DNS_TUNNELING",
                "severity": "HIGH",
                "src_ip": src,
                "detail": f"Suspicious long DNS query: {qname[:60]}",
                "timestamp": now.isoformat()
            }
    except Exception:
        pass
    if len(dns_tracker[src]) >= DNS_TUNNEL_THRESHOLD:
        return {
            "type": "DNS_TUNNELING",
            "severity": "HIGH",
            "src_ip": src,
            "detail": f"{len(dns_tracker[src])} DNS queries in {WINDOW_SECONDS}s",
            "timestamp": now.isoformat()
        }
    return None

def analyze_packet(pkt):
    alerts = []
    for detector in [detect_port_scan, detect_syn_flood, detect_dns_tunneling]:
        result = detector(pkt)
        if result:
            alerts.append(result)
    return alerts
