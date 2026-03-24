"""
Honeypot TUI — Terminal User Interface

A rich terminal dashboard for monitoring the honeypot.
Connects to the same management API as the Web UI.
Can be compiled to a standalone binary via PyInstaller.

Usage:
    python -m tui.app
    python -m tui.app --api http://192.168.1.100:9090
"""

import argparse
import sys

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, DataTable, 
    Label, TabbedContent, TabPane, RichLog,
    Button, Input, LoadingIndicator,
)
from textual.timer import Timer
from textual import work
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable

from .client import HoneypotClient


class StatsPanel(Static):
    """Dashboard statistics panel."""

    def __init__(self, client: HoneypotClient, **kwargs):
        super().__init__(**kwargs)
        self._client = client

    def on_mount(self):
        self.set_interval(5, self.refresh_stats)
        self.refresh_stats()

    def refresh_stats(self):
        try:
            stats = self._client.get_stats()
            table = RichTable(
                show_header=False,
                expand=True,
                border_style="blue",
                title="📊 Dashboard",
            )
            table.add_column("Metric", style="bold")
            table.add_column("Value", style="cyan", justify="right")

            table.add_row("Total Connections", f"{stats['total_connections']:,}")
            table.add_row("Unique Attackers", f"[red]{stats['unique_attackers']:,}[/]")
            table.add_row("Credentials Captured", f"[yellow]{stats['total_credentials']:,}[/]")
            table.add_row("Total Events", f"{stats['total_events']:,}")
            table.add_row("Last 24h", f"[green]{stats['connections_last_24h']:,}[/]")

            # Protocol breakdown
            for proto, count in stats.get("protocol_breakdown", {}).items():
                pct = (count / stats["total_connections"] * 100) if stats["total_connections"] else 0
                bar = "█" * int(pct / 5)
                table.add_row(
                    f"  {proto.upper()}",
                    f"{count:,} ({pct:.1f}%) {bar}"
                )

            self.update(table)
        except Exception as e:
            self.update(f"[red]Error: {e}[/]")


class AttackerPanel(Static):
    """Top attackers panel."""

    def __init__(self, client: HoneypotClient, **kwargs):
        super().__init__(**kwargs)
        self._client = client

    def on_mount(self):
        self.set_interval(10, self.refresh_attackers)
        self.refresh_attackers()

    def refresh_attackers(self):
        try:
            data = self._client.get_attackers(page=1, per_page=15)
            table = RichTable(
                title="🎯 Top Attackers",
                expand=True,
                border_style="red",
            )
            table.add_column("IP", style="cyan")
            table.add_column("Conns", justify="right", style="bold")
            table.add_column("Protocols")
            table.add_column("Creds", justify="right")
            table.add_column("Last Seen", style="dim")

            for a in data.get("attackers", []):
                protocols = " ".join(
                    f"[{'magenta' if p=='ssh' else 'blue' if p=='http' else 'green' if p=='ftp' else 'yellow' if p=='telnet' else 'cyan'}]{p.upper()}[/]"
                    for p in a.get("protocols", [])
                )
                cred_str = f"[yellow]{a['credential_count']}[/]" if a.get("credential_count", 0) > 0 else "-"
                table.add_row(
                    a["ip"],
                    str(a["connection_count"]),
                    protocols,
                    cred_str,
                    a.get("last_seen", "")[:19],
                )

            self.update(table)
        except Exception as e:
            self.update(f"[red]Error: {e}[/]")


class LogPanel(RichLog):
    """Live log viewer."""

    def __init__(self, client: HoneypotClient, **kwargs):
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)
        self._client = client
        self._last_id = 0

    def on_mount(self):
        self.set_interval(2, self.poll_logs)
        self.load_initial()

    def load_initial(self):
        try:
            logs = self._client.get_recent_logs(30)
            for entry in reversed(logs):
                self._log_entry(entry)
                self._last_id = max(self._last_id, entry.get("id", 0))
        except Exception as e:
            self.write(f"[red]Error: {e}[/]")

    def poll_logs(self):
        try:
            logs = self._client.get_recent_logs(10)
            for entry in reversed(logs):
                if entry.get("id", 0) > self._last_id:
                    self._log_entry(entry)
                    self._last_id = entry["id"]
        except Exception:
            pass

    def _log_entry(self, entry):
        proto = entry.get("protocol", "?").upper()
        color_map = {
            "SSH": "magenta", "HTTP": "blue", "FTP": "green",
            "TELNET": "yellow", "SMTP": "cyan",
        }
        color = color_map.get(proto, "white")
        self.write(
            f"[dim]{entry.get('timestamp', '')}[/] "
            f"[{color}][{proto:6}][/] "
            f"[cyan]{entry.get('src_ip', '?')}[/]"
            f"[dim]:{entry.get('src_port', '')}[/]"
        )


class AnalysisPanel(Static):
    """Analysis report panel."""

    def __init__(self, client: HoneypotClient, **kwargs):
        super().__init__(**kwargs)
        self._client = client

    def run_analysis(self):
        self.update("[yellow]Running analysis...[/]")
        try:
            report = self._client.run_analysis(top_n=10)
            meta = report.get("metadata", {})

            output = []
            output.append(f"[bold]═══ ANALYSIS REPORT ═══[/]")
            output.append(f"Total connections: [cyan]{meta.get('total_connections', 0):,}[/]")
            output.append(f"Unique attackers:  [red]{meta.get('total_unique_attackers', 0):,}[/]")
            output.append("")

            # Top payloads
            output.append("[bold]Top Payloads:[/]")
            for p in report.get("top_payloads", [])[:10]:
                payload = p["payload"][:60]
                output.append(f"  {p['count']:<5} : {payload}")
            output.append("")

            # Top credentials
            output.append("[bold]Top Credentials:[/]")
            for c in report.get("top_credentials", [])[:10]:
                output.append(
                    f"  {c['count']:<5} : [yellow]{c['username']}:{c['password']}[/]"
                )

            self.update("\n".join(output))
        except Exception as e:
            self.update(f"[red]Analysis error: {e}[/]")


class HoneypotTUI(App):
    """Honeypot Terminal User Interface."""

    CSS = """
    Screen {
        background: $surface;
    }
    #stats { height: auto; min-height: 12; }
    #attackers { height: auto; min-height: 15; }
    #logs { height: 1fr; min-height: 15; }
    #analysis { height: auto; min-height: 10; }
    TabbedContent { height: 1fr; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("a", "analyze", "Analyze"),
        ("d", "dashboard", "Dashboard"),
        ("l", "logs", "Logs"),
    ]

    TITLE = "🍯 Honeypot Monitor"
    SUB_TITLE = "Terminal Dashboard"

    def __init__(self, api_url: str = "http://127.0.0.1:9090", **kwargs):
        super().__init__(**kwargs)
        self._client = HoneypotClient(api_url)
        self._stats_panel = StatsPanel(self._client, id="stats")
        self._attacker_panel = AttackerPanel(self._client, id="attackers")
        self._log_panel = LogPanel(self._client, id="logs")
        self._analysis_panel = AnalysisPanel(self._client, id="analysis")

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Dashboard", id="tab-dashboard"):
                with Vertical():
                    yield self._stats_panel
                    yield self._attacker_panel
            with TabPane("Logs", id="tab-logs"):
                yield self._log_panel
            with TabPane("Analysis", id="tab-analysis"):
                yield self._analysis_panel
        yield Footer()

    def action_refresh(self):
        self._stats_panel.refresh_stats()
        self._attacker_panel.refresh_attackers()

    def action_analyze(self):
        self._analysis_panel.run_analysis()

    def action_dashboard(self):
        self.query_one(TabbedContent).active = "tab-dashboard"

    def action_logs(self):
        self.query_one(TabbedContent).active = "tab-logs"

    def on_unmount(self):
        self._client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot TUI — Terminal dashboard"
    )
    parser.add_argument(
        "--api",
        default="http://127.0.0.1:9090",
        help="Management API URL (default: http://127.0.0.1:9090)",
    )
    args = parser.parse_args()

    app = HoneypotTUI(api_url=args.api)
    app.run()


if __name__ == "__main__":
    main()
