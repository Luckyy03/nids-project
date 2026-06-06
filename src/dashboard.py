from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from collections import defaultdict
from datetime import datetime

console = Console()

class Dashboard:
    def __init__(self):
        self.total_packets = 0
        self.alerts_by_type = defaultdict(int)
        self.top_ips = defaultdict(int)
        self.start_time = datetime.now()

    def update(self, pkt_info=None, alert=None):
        self.total_packets += 1
        if alert:
            self.alerts_by_type[alert["type"]] += 1
            self.top_ips[alert.get("src_ip","?")] += 1

    def render(self):
        uptime = str(datetime.now() - self.start_time).split(".")[0]
        table = Table(title=f"NIDS Live — uptime {uptime}", border_style="green")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="bold white")
        table.add_row("Packets analyzed", str(self.total_packets))
        table.add_row("Total alerts", str(sum(self.alerts_by_type.values())))
        for atype, count in self.alerts_by_type.items():
            table.add_row(f"  {atype}", f"[red]{count}[/red]")
        top_ip = max(self.top_ips, key=self.top_ips.get) if self.top_ips else "none"
        table.add_row("Top attacker IP", top_ip)
        return Panel(table, border_style="green")

dashboard = Dashboard()
