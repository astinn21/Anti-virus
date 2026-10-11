"""
gui/monitor_view.py

Live event log window for the real-time monitor.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from core.monitor import MonitorManager, MonitorEvent
from core.database import Database
from core.quarantine import QuarantineManager
from core.settings import Settings


BG = "#1e1e2e"
CARD_BG = "#2a2a3d"
TEXT = "#e0e0e0"
MUTED = "#9a9ab0"
GREEN = "#4caf50"
RED = "#e53935"
YELLOW = "#ffb300"


class MonitorWindow(tk.Toplevel):
    def __init__(self, parent, monitor: MonitorManager):
        super().__init__(parent)
        self.title("Real-Time Monitor")
        self.geometry("960x560")
        self.configure(bg=BG)

        self.monitor = monitor
        self.db = Database()
        self.settings = Settings(db=self.db)
        self.qm = QuarantineManager(db=self.db)

        # Wire callbacks (they run on the monitor thread → hop to GUI thread)
        self.monitor.on_event = self._on_event_threadsafe
        self.monitor.on_status = self._on_status_threadsafe
        self.monitor.quarantine_manager = self.qm
        self.monitor.set_auto_quarantine(
            self.settings.get_bool("monitor_auto_quarantine", False)
        )

        self._build_ui()
        self._refresh_controls()

        # Stop monitor when the window closes
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Real-Time Monitor",
                  font=("Segoe UI", 14, "bold")).pack(side="left")

        self.status_var = tk.StringVar(value="Stopped.")
        self.status_lbl = tk.Label(top, textvariable=self.status_var,
                                   bg=RED, fg="white",
                                   font=("Segoe UI", 9, "bold"),
                                   padx=8, pady=4)
        self.status_lbl.pack(side="right")

        # Controls
        ctrl = ttk.LabelFrame(self, text="Controls", padding=10)
        ctrl.pack(fill="x", padx=12, pady=(0, 8))

        row = ttk.Frame(ctrl)
        row.pack(fill="x")

        ttk.Label(row, text="Folder:").pack(side="left")
        self.folder_var = tk.StringVar(
            value=self.settings.get("monitor_path") or str(Path.home() / "Desktop")
        )
        ttk.Entry(row, textvariable=self.folder_var).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(row, text="Browse…", command=self._browse).pack(side="left")

        row2 = ttk.Frame(ctrl)
        row2.pack(fill="x", pady=(8, 0))

        ttk.Label(row2, text="Poll interval (s):").pack(side="left")
        self.interval_var = tk.StringVar(
            value=str(self.settings.get_float("monitor_interval", 2.0))
        )
        ttk.Entry(row2, textvariable=self.interval_var, width=6).pack(side="left", padx=6)

        self.autoq_var = tk.BooleanVar(
            value=self.settings.get_bool("monitor_auto_quarantine", False)
        )
        ttk.Checkbutton(row2, text="Auto-quarantine detected files",
                        variable=self.autoq_var,
                        command=self._on_toggle_autoq).pack(side="left", padx=12)

        self.start_btn = ttk.Button(row2, text="Start Monitoring",
                                    command=self._start)
        self.start_btn.pack(side="right", padx=4)
        self.stop_btn = ttk.Button(row2, text="Stop Monitoring",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="right", padx=4)

        # Event log
        log_frame = ttk.LabelFrame(self, text="Detections (live)", padding=8)
        log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        cols = ("time", "type", "path", "threat", "methods", "action")
        self.tree = ttk.Treeview(log_frame, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
        widths = {"time": 140, "type": 80, "path": 280,
                  "threat": 160, "methods": 130, "action": 100}
        for c, w in widths.items():
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)

        ttk.Label(
            self,
            text=("Note: this monitor polls the folder every few seconds. "
                  "It cannot block file writes like a commercial AV driver."),
            font=("Segoe UI", 8, "italic"),
        ).pack(pady=(0, 8))

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def _browse(self):
        folder = filedialog.askdirectory(title="Choose a folder to monitor")
        if folder:
            self.folder_var.set(folder)

    def _on_toggle_autoq(self):
        val = bool(self.autoq_var.get())
        self.settings.set("monitor_auto_quarantine", "true" if val else "false")
        self.monitor.set_auto_quarantine(val)

    def _start(self):
        folder = Path(self.folder_var.get().strip())
        if not folder.exists() or not folder.is_dir():
            messagebox.showerror("Invalid Folder", "Folder does not exist.")
            return
        try:
            interval = float(self.interval_var.get())
        except ValueError:
            messagebox.showerror("Invalid Interval", "Interval must be a number.")
            return

        self.settings.set("monitor_path", str(folder))
        self.settings.set("monitor_interval", str(interval))

        ok = self.monitor.start(folder, interval=interval)
        if not ok:
            messagebox.showerror("Monitor", "Could not start monitoring.")
            return
        self._refresh_controls()

    def _stop(self):
        self.monitor.stop()
        self._refresh_controls()

    def _refresh_controls(self):
        running = self.monitor.is_running
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        if running:
            self.status_var.set(f"● MONITORING: {self.monitor.watched_path}")
            self.status_lbl.config(bg=GREEN)
        else:
            self.status_var.set("Stopped.")
            self.status_lbl.config(bg=RED)

    # ------------------------------------------------------------------
    # Thread-safe event handling
    # ------------------------------------------------------------------

    def _on_event_threadsafe(self, event: MonitorEvent):
        try:
            self.after(0, lambda: self._append_event(event))
        except Exception:
            pass

    def _on_status_threadsafe(self, message: str):
        try:
            self.after(0, lambda: self.status_var.set(message))
        except Exception:
            pass

    def _append_event(self, event: MonitorEvent):
        methods = ",".join(event.detection_methods)
        action = "Quarantined" if event.quarantined else ""
        self.tree.insert("", 0, values=(
            event.timestamp,
            event.event_type,
            str(event.path),
            event.threat_name or "",
            methods,
            action,
        ))

    def _on_close(self):
        if self.monitor.is_running:
            if not messagebox.askyesno(
                "Monitor Running",
                "The monitor is running. Stop it and close this window?"
            ):
                return
            self.monitor.stop()
        # Detach callbacks so the parent can reuse the monitor
        self.monitor.on_event = None
        self.monitor.on_status = None
        self.destroy()