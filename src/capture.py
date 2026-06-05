from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import os

INTERFACE = "ens33"
PCAP_DIR  = "data"
captured_packets = []

def get_packet_info(pkt):
    info = {
        "timestamp": datetime.now().isoformat(),
        "size": len(pkt),
        "protocol": "OTHER",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "flags": None,
    }
    if pkt.haslayer(IP):
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
    if pkt.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        info["protocol"] = "ICMP"
    if pkt.haslayer(DNS):
        info["protocol"] = "DNS"
    return info

def packet_callback(pkt):
    info = get_packet_info(pkt)
    print(f"  [{info['protocol']}] {info['src_ip']} → {info['dst_ip']} | {info['size']} bytes")
    captured_packets.append(pkt)
    return info

def start_capture(count=100, save=True):
    print(f"[*] Sniffing on {INTERFACE} ...")
    pkts = sniff(iface=INTERFACE, count=count, prn=packet_callback)
    if save:
        os.makedirs(PCAP_DIR, exist_ok=True)
        path = os.path.join(PCAP_DIR, f"capture_{datetime.now().strftime('%H%M%S')}.pcap")
        wrpcap(path, pkts)
        print(f"[*] Saved to {path}")
    return pkts

if __name__ == "__main__":
    start_capture(count=50)
