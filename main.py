from scapy.all import sniff, IP, TCP, UDP
from src.detector import analyze_packet
from src.alerts import send_alert, log_normal_traffic
from rich.console import Console

console = Console()
INTERFACE = "ens33"

def handle_packet(pkt):
    alerts = analyze_packet(pkt)
    for alert in alerts:
        send_alert(alert)
    if not alerts and pkt.haslayer(IP):
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        port  = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        log_normal_traffic(pkt[IP].src, proto, port)

if __name__ == "__main__":
    console.print("[bold green]NIDS started — monitoring network...[/bold green]")
    sniff(iface=INTERFACE, prn=handle_packet, store=False)

