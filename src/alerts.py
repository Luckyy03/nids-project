import json, os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()
LOG_FILE = os.path.join("logs", "incidents.json")
os.makedirs("logs", exist_ok=True)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "green",
}

def send_alert(incident: dict):
    severity = incident.get("severity", "LOW")
    color    = SEVERITY_COLORS.get(severity, "white")
    atk_type = incident.get("type", "UNKNOWN")
    src_ip   = incident.get("src_ip", "?")
    detail   = incident.get("detail", "")
    ts       = incident.get("timestamp", "")

    panel = Panel(
        "[white]Source IP:[/white] [bold]" + src_ip + "[/bold]\n"
        "[white]Detail:[/white]    " + detail + "\n"
        "[white]Time:[/white]      " + ts,
        title="[" + color + "] " + severity + " — " + atk_type + " [/" + color + "]",
        border_style=color.replace("bold ", ""),
        box=box.ROUNDED,
    )
    console.print(panel)
    _log_incident(incident)

def _log_incident(incident: dict):
    incident["logged_at"] = datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(incident) + "\n")

def log_normal_traffic(src_ip, protocol, dst_port):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print("  [dim]" + ts + "[/dim]  [green]" + protocol + "[/green]  " + src_ip + " -> port " + str(dst_port))
