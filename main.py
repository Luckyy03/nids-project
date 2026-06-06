from scapy.all import sniff, IP, TCP, UDP
from src.detector import analyze_packet
from src.alerts import send_alert, log_normal_traffic
from src.ml_classifier import load_model, predict_packet
from rich.console import Console

console = Console()
INTERFACE = "eth0"
model, encoders = None, None

def build_features(pkt):
    return {
        "duration": 0, "protocol_type": "tcp" if pkt.haslayer(TCP) else "udp",
        "service": "http", "flag": "SF", "src_bytes": len(pkt),
        "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 1, "srv_count": 1, "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 1,
        "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }

def handle_packet(pkt):
    alerts = analyze_packet(pkt)
    for alert in alerts:
        send_alert(alert)
    if model and pkt.haslayer(IP):
        features = build_features(pkt)
        prediction = predict_packet(features, model, encoders)
        if prediction == "attack" and not alerts:
            send_alert({"type": "ML_DETECTED", "severity": "HIGH",
                        "src_ip": pkt[IP].src, "detail": "ML model flagged this traffic",
                        "timestamp": str(pkt.time)})
    if not alerts and pkt.haslayer(IP):
        proto = "TCP" if pkt.haslayer(TCP) else "UDP"
        port  = pkt[TCP].dport if pkt.haslayer(TCP) else 0
        log_normal_traffic(pkt[IP].src, proto, port)

if __name__ == "__main__":
    console.print("[bold green]Loading ML model...[/bold green]")
    try:
        model, encoders = load_model()
        console.print("[green]ML model loaded.[/green]")
    except:
        console.print("[yellow]No model found — run src/ml_classifier.py first[/yellow]")
    console.print("[bold green]NIDS started — monitoring...[/bold green]")
    sniff(iface=INTERFACE, prn=handle_packet, store=False)
