"""Standalone desktop dashboard for CC Security Proxy. tkinter, zero extra deps."""
from __future__ import annotations

import json
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.request import Request, urlopen
from urllib.error import URLError


class DashboardApp:
    def __init__(self, proxy_url: str = "http://127.0.0.1:8080"):
        self.proxy_url = proxy_url.rstrip("/")
        self.running = True
        self.log_entries: list[dict] = []

        # ── Window ──
        self.root = tk.Tk()
        self.root.title("CC Security Proxy")
        self.root.geometry("760x540")
        self.root.minsize(600, 400)
        self.root.configure(bg="#0d1117")

        # ── Style ──
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#0d1117", foreground="#e6edf3",
                        fieldbackground="#161b22", borderwidth=0)
        style.configure("TLabel", background="#0d1117", foreground="#e6edf3")
        style.configure("TFrame", background="#0d1117")
        style.configure("Card.TFrame", background="#161b22", relief="flat")
        style.configure("Card.TLabel", background="#161b22", foreground="#e6edf3")
        style.configure("Green.TLabel", background="#161b22", foreground="#3fb950")
        style.configure("Red.TLabel", background="#161b22", foreground="#f85149")
        style.configure("Yellow.TLabel", background="#161b22", foreground="#d2991d")
        style.configure("Dim.TLabel", background="#161b22", foreground="#8b949e")
        style.configure("Header.TLabel", background="#0d1117", foreground="#e6edf3",
                        font=("Segoe UI", 13, "bold"))
        style.configure("StatusBar.TFrame", background="#161b22")

        # ── Fonts ──
        self.f_header = ("Segoe UI", 10, "bold")
        self.f_stat = ("Segoe UI", 26, "bold")
        self.f_body = ("Segoe UI", 10)
        self.f_small = ("Segoe UI", 9)
        self.f_mono = ("Consolas", 9)

        self._build_ui()
        self._start_refresh()

    def _build_ui(self):
        # ── Top bar ──
        top = ttk.Frame(self.root, style="TFrame")
        top.pack(fill="x", padx=16, pady=(14, 0))

        ttk.Label(top, text="CC Security Proxy", style="Header.TLabel").pack(side="left")
        self.mode_label = ttk.Label(top, text="--", font=self.f_header)
        self.mode_label.pack(side="right", padx=(8, 0))
        self.conn_dot = tk.Canvas(top, width=8, height=8, bg="#0d1117", highlightthickness=0)
        self.conn_dot.pack(side="right")
        self._dot = self.conn_dot.create_oval(0, 0, 8, 8, fill="#8b949e", outline="")

        # Upstream row
        self.upstream_label = ttk.Label(self.root, text="Upstream: --",
                                        font=self.f_small, style="Dim.TLabel")
        self.upstream_label.pack(fill="x", padx=18, pady=(2, 0))

        # ── Stats cards ──
        cards_frame = ttk.Frame(self.root, style="TFrame")
        cards_frame.pack(fill="x", padx=14, pady=(10, 4))
        cards_frame.columnconfigure((0, 1, 2, 3), weight=1, uniform="card")

        self.stat_cards = {}
        for i, (key, label, color) in enumerate([
            ("total", "TOTAL", "#e6edf3"), ("forwarded", "FORWARDED", "#3fb950"),
            ("blocked", "BLOCKED", "#f85149"), ("errors", "ERRORS", "#d2991d"),
        ]):
            card = ttk.Frame(cards_frame, style="Card.TFrame")
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            ttk.Label(card, text="0", font=self.f_stat, foreground=color,
                      style="Card.TLabel").pack(pady=(12, 0))
            ttk.Label(card, text=label, font=self.f_small, style="Dim.TLabel").pack(pady=(0, 10))
            self.stat_cards[key] = card

        # Block rate bar
        self.block_rate_label = ttk.Label(self.root, text="Block Rate: --%",
                                          font=self.f_small, style="Dim.TLabel")
        self.block_rate_label.pack(fill="x", padx=18)

        # ── Request log ──
        log_header = ttk.Frame(self.root, style="TFrame")
        log_header.pack(fill="x", padx=18, pady=(10, 2))
        ttk.Label(log_header, text="Recent Requests", font=self.f_header).pack(side="left")
        ttk.Label(log_header, text="Auto-refresh 3s", font=self.f_small,
                  style="Dim.TLabel").pack(side="right")

        # Log table (Treeview)
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        columns = ("time", "verdict", "path", "reason")
        self.tree = ttk.Treeview(log_frame, columns=columns, show="headings",
                                 height=14, selectmode="none")
        self.tree.heading("time", text="Time", anchor="w")
        self.tree.heading("verdict", text="Verdict", anchor="w")
        self.tree.heading("path", text="Path", anchor="w")
        self.tree.heading("reason", text="Reason", anchor="w")
        self.tree.column("time", width=80, minwidth=70)
        self.tree.column("verdict", width=85, minwidth=75)
        self.tree.column("path", width=160, minwidth=100)
        self.tree.column("reason", width=280, minwidth=150)

        # Treeview styling
        self.tree.tag_configure("forward", foreground="#3fb950")
        self.tree.tag_configure("blocked", foreground="#f85149")
        self.tree.tag_configure("error", foreground="#d2991d")

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ── Status bar ──
        status = ttk.Frame(self.root, style="StatusBar.TFrame")
        status.pack(fill="x", side="bottom")
        self.status_text = ttk.Label(status, text="Connecting...", font=self.f_small,
                                     style="Dim.TLabel", background="#161b22")
        self.status_text.pack(side="left", padx=14, pady=6)
        ttk.Label(status, text=f"Proxy: {self.proxy_url}", font=self.f_small,
                  style="Dim.TLabel", background="#161b22").pack(side="right", padx=14, pady=6)

    def _fetch(self, path: str) -> dict:
        try:
            req = Request(f"{self.proxy_url}{path}")
            return json.loads(urlopen(req, timeout=3).read())
        except Exception:
            return {}

    def _refresh(self):
        if not self.running:
            return

        health = self._fetch("/health")
        stats = self._fetch("/stats")
        logs = self._fetch("/logs")

        # Connection status
        if health:
            self.conn_dot.itemconfig(self._dot, fill="#3fb950")
            self.status_text.config(text="Connected")
            mode = health.get("mode", "?")
            self.mode_label.config(text=f"Mode: {mode.upper()}",
                                   foreground={"smart": "#3fb950", "protected": "#d2991d",
                                               "default": "#8b949e"}.get(mode, "#e6edf3"))
            upstream = health.get("upstream", "")
            self.upstream_label.config(text=f"Upstream: {upstream}" if upstream else "Upstream: (not set)")
            self.root.title(f"CC Security Proxy [{mode}] — {health.get('uptime_seconds', 0)//60}m up")
        else:
            self.conn_dot.itemconfig(self._dot, fill="#f85149")
            self.status_text.config(text="Disconnected — waiting...")
            self.mode_label.config(text="--", foreground="#8b949e")
            self.root.title("CC Security Proxy [offline]")

        # Update stat cards dynamically
        total = stats.get("total_requests", 0)
        fwd = stats.get("forwarded", 0)
        blk = stats.get("blocked", 0)
        err = stats.get("errors", 0)
        blk_pct = f"{blk/total*100:.0f}%" if total > 0 else "0%"

        for key, val in [("total", total), ("forwarded", fwd), ("blocked", blk), ("errors", err)]:
            card = self.stat_cards[key]
            for widget in card.winfo_children():
                if isinstance(widget, ttk.Label) and widget.cget("font") == self.f_stat:
                    widget.config(text=str(val))
                    break

        self.block_rate_label.config(text=f"Block Rate: {blk_pct}  |  Uptime: {health.get('uptime_seconds', 0)//60}m")

        # Update log table (only if new entries)
        if logs:
            new_ids = {(e.get("time", 0), e.get("verdict", ""), e.get("path", "")) for e in logs[-10:]}
            old_ids = {(e.get("time", 0), e.get("verdict", ""), e.get("path", "")) for e in self.log_entries[-10:]}
            if new_ids != old_ids:
                self.tree.delete(*self.tree.get_children())
                for entry in reversed(logs[-20:]):
                    t = time.strftime("%H:%M:%S", time.localtime(entry.get("time", 0)))
                    v = entry.get("verdict", "?")
                    tag = v.lower() if v.lower() in ("forward", "blocked", "error") else ""
                    self.tree.insert("", "end", values=(
                        t, v, entry.get("path", "/")[:50],
                        entry.get("reason", "")[:60],
                    ), tags=[tag])
                self.log_entries = logs
                # Auto-scroll to bottom
                children = self.tree.get_children()
                if children:
                    self.tree.see(children[-1])

        self.root.after(3000, self._refresh)

    def _start_refresh(self):
        self.root.after(500, self._refresh)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self.running = False
        self.root.destroy()


def main():
    import argparse
    import sys

    p = argparse.ArgumentParser(description="CC Security Proxy Desktop Dashboard")
    p.add_argument("--url", default="http://127.0.0.1:8080",
                   help="Proxy URL (default: http://127.0.0.1:8080)")
    p.add_argument("--port", type=int, default=None,
                   help="Proxy port shorthand (equivalent to --url http://127.0.0.1:PORT)")

    args = p.parse_args()
    url = args.url
    if args.port:
        url = f"http://127.0.0.1:{args.port}"

    app = DashboardApp(proxy_url=url)
    app.run()


if __name__ == "__main__":
    main()
