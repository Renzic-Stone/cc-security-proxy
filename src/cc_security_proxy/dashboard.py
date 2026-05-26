"""Rich terminal dashboard for CC Security Proxy."""
from __future__ import annotations

import time
import urllib.request
import json
import threading
from typing import TYPE_CHECKING

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich import box

if TYPE_CHECKING:
    from .config import Config

HEADER = """[bold white]CC Security Proxy[/] [dim]v0.1.0[/]"""


def _fetch(port: int, path: str) -> dict:
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        return json.loads(urllib.request.urlopen(req, timeout=3).read())
    except Exception:
        return {}


def _make_layout(config: "Config") -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=3),
    )
    layout["left"].split(
        Layout(name="stats"),
        Layout(name="mode_info"),
    )
    layout["right"].split(
        Layout(name="logs"),
    )
    return layout


def _render_header(config: "Config", uptime: float) -> Panel:
    grid = Table.grid(padding=(0, 4))
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    mode_style = {"smart": "green", "protected": "yellow", "default": "dim"}.get(config.mode, "white")
    grid.add_row(
        f"[bold {mode_style}]Mode: {config.mode}[/]",
        f"[dim]Upstream:[/] {config.upstream_url[:50]}",
        f"[dim]Uptime:[/] {int(uptime//60)}m {int(uptime%60)}s",
    )
    return Panel(grid, title=HEADER, border_style="bright_black")


def _render_stats(health: dict, stats: dict) -> Panel:
    total = stats.get("total_requests", 0)
    fwd = stats.get("forwarded", 0)
    blk = stats.get("blocked", 0)
    err = stats.get("errors", 0)
    blk_pct = f"{blk/total*100:.0f}%" if total > 0 else "0%"

    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_row(
        f"[bold white]{total}[/]\n[dim]TOTAL[/]",
        f"[bold green]{fwd}[/]\n[dim]FORWARD[/]",
        f"[bold red]{blk}[/]\n[dim]BLOCKED[/]",
        f"[bold yellow]{err}[/]\n[dim]ERRORS[/]",
    )
    grid.add_row("", "", "", "")
    grid.add_row(
        f"[dim]Block rate:[/] [bold red]{blk_pct}[/]",
        f"[dim]Listen:[/] {health.get('listen',':8080')}",
        f"[dim]Scanner:[/] [green]active[/]",
        f"[dim]Docker:[/] {'[green]yes[/]' if health.get('docker') else '[dim]no[/]'}",
    )
    return Panel(grid, title="Statistics", border_style="bright_black")


def _render_mode_info(config: "Config") -> Panel:
    lines = []
    mode_desc = {
        "default": "[dim]Pass-through, logging only[/]",
        "protected": "[yellow]Docker sandbox execution[/]",
        "smart": "[green]LLM audit + sandbox fallback[/]",
    }
    lines.append(mode_desc.get(config.mode, ""))
    lines.append("")
    lines.append(f"[dim]Port:[/] {config.proxy_port}")
    if config.mode == "smart":
        lines.append(f"[dim]LLM:[/] {config.llm_model}")
        lines.append(f"[dim]LLM URL:[/] {config.llm_base_url[:40]}")
    if config.mode in ("protected", "smart"):
        lines.append(f"[dim]Sandbox:[/] {config.sandbox_image}")
    return Panel("\n".join(lines), title="Configuration", border_style="bright_black")


def _render_logs(port: int) -> Panel:
    logs = _fetch(port, "/logs")
    if not logs:
        return Panel("[dim]No requests yet[/]", title="Recent Requests", border_style="bright_black")

    table = Table(box=box.SIMPLE, padding=(0, 1), show_header=False)
    table.add_column("Time", style="dim", width=10)
    table.add_column("Verdict", width=9)
    table.add_column("Path", style="dim", max_width=40)
    table.add_column("Reason", style="dim", max_width=35)

    for entry in reversed(logs[-15:]):
        t = time.strftime("%H:%M:%S", time.localtime(entry["time"]))
        v = entry["verdict"]
        v_style = "green" if v == "FORWARD" else "red"
        path = entry.get("path", "/")[:40]
        reason = entry.get("reason", "")[:35]
        table.add_row(t, f"[{v_style}]{v}[/]", path, reason)

    return Panel(table, title="Recent Requests", border_style="bright_black")


def _render_footer() -> Panel:
    return Panel(
        "[dim]Q[/] Quit  [dim]R[/] Refresh  [dim]S[/] Stats  |  "
        "[dim]Polling every 2s  |  http://127.0.0.1:PORT/ui for web dashboard[/]",
        border_style="bright_black",
    )


def run_dashboard(config: "Config") -> None:
    """Run Rich terminal dashboard. Blocks until interrupted."""
    layout = _make_layout(config)
    start_time = time.monotonic()

    def _refresh() -> Layout:
        uptime = time.monotonic() - start_time
        health = _fetch(config.proxy_port, "/health")
        stats = _fetch(config.proxy_port, "/stats")

        layout["header"].update(_render_header(config, uptime))
        layout["stats"].update(_render_stats(health, stats))
        layout["mode_info"].update(_render_mode_info(config))
        layout["logs"].update(_render_logs(config.proxy_port))
        layout["footer"].update(_render_footer())
        return layout

    with Live(_refresh(), refresh_per_second=0.5, screen=True) as live:
        try:
            while True:
                time.sleep(2)
                live.update(_refresh())
        except KeyboardInterrupt:
            pass
