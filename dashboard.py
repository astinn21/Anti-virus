"""
gui/dashboard.py
Redesigned dashboard for Phase 7.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from config import APP_NAME, APP_VERSION
from core.scanner import FileScanner
from core.database import Database
from core.models import ScanResult
from core.quarantine import QuarantineManager
from core.settings import Settings
from core.scan_targets import get_quick_scan_targets, get_full_scan_targets
from gui.quarantine_view import QuarantineWindow
from gui.history_view import HistoryWindow
from gui.settings_view import SettingsWindow


# ---------- Colours ----------
BG = "#1e1e2e"
CARD_BG = "#2a2a3d"
TEXT = "#e0e0e0"
MUTED = "#9a9ab0"
GREEN = "#4caf50"
RED = "#e53935"
ACCENT = "#5c6bc0"


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def short_time(ts: str) -> str:
    if not ts:
        return "Never"
    return ts.replace("T", " ")[:19]


class StatCard(ttk.Frame):
    """A small dashboard card showing a number + label."""

    def __init__(self, parent, label: str, value: str = "0", colour: str = TEXT):
        super().__init__(parent, padding=12, style="Card.TFrame")
        self.value_var = tk.StringVar(value=value)

        ttk.Label(self, textvariable=self.value_var,
                  font=("Segoe UI", 20, "bold"),
                  foreground=colour, background=CARD_BG).pack(anchor="w")
        ttk.Label(self, text=label,
                  font=("Segoe UI", 9),
                  foreground=MUTED, background=CARD_BG).pack(anchor="w")

    def set(self, value: str):
        self.value_var.set(value)


class DashboardFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=0)
        self.scanner = None
        self.db = Database()
        self.qm = QuarantineManager(db=self.db)
        self.settings = Settings(db=self.db)
        self._last_result: ScanResult = None
        self._build_style()
        self.build_ui()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG, foreground=TEXT,
                        fieldbackground=CARD_BG)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD_BG, relief="flat")
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Header.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10),
                        foreground=MUTED, background=BG)
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT)
        style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("TButton", padding=8)
        style.configure("Accent.TButton", background=ACCENT, foreground="white")
        style.map("Accent.TButton",
                  background=[("active", "#7986cb")])
        style.configure("TProgressbar", troughcolor=CARD_BG,
                        background=ACCENT, bordercolor=BG)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def build_ui(self):
        # Header
        header = ttk.Frame(self, padding=(24, 20, 24, 8))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Header.TLabel").pack(side="left")
        ttk.Label(header, text=f"v{APP_VERSION}", style="Sub.TLabel") \
            .pack(side="right", padx=8)

        # Status pill
        status_frame = ttk.Frame(self, padding=(24, 0, 24, 12))
        status_frame.pack(fill="x")

        self.status_label = tk.Label(
            status_frame, text="  ● PROTECTED (DEMO)  ",
            font=("Segoe UI", 11, "bold"),
            bg=GREEN, fg="white", padx=10, pady=6,
        )
        self.status_label.pack(anchor="w")

        # Stat cards row
        cards = ttk.Frame(self, padding=(24, 0, 24, 12))
        cards.pack(fill="x")

        self.card_files = StatCard(cards, "FILES SCANNED")
        self.card_threats = StatCard(cards, "THREATS DETECTED", colour=RED)
        self.card_quarantine = StatCard(cards, "QUARANTINED")
        self.card_scans = StatCard(cards, "TOTAL SCANS")

        self.card_files.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.card_threats.grid(row=0, column=1, sticky="nsew", padx=4)
        self.card_quarantine.grid(row=0, column=2, sticky="nsew", padx=4)
        self.card_scans.grid(row=0, column=3, sticky="nsew", padx=(8, 0))

        for i in range(4):
            cards.columnconfigure(i, weight=1)

        # Scan buttons
        actions = ttk.Frame(self, padding=(24, 0, 24, 12))
        actions.pack(fill="x")

        ttk.Label(actions, text="Scan", style="Section.TLabel").pack(anchor="w", pady=(0, 6))

        btn_row = ttk.Frame(actions)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="⚡ Quick Scan",
                   command=self.start_quick_scan, style="Accent.TButton") \
            .pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🛡 Full Scan",
                   command=self.start_full_scan, style="Accent.TButton") \
            .pack(side="left", padx=8)
        ttk.Button(btn_row, text="📁 Custom Scan",
                   command=self.start_custom_scan, style="Accent.TButton") \
            .pack(side="left", padx=8)

        # Tools row
        tools = ttk.Frame(self, padding=(24, 0, 24, 12))
        tools.pack(fill="x")
        ttk.Label(tools, text="Tools", style="Section.TLabel").pack(anchor="w", pady=(0, 6))

        tool_row = ttk.Frame(tools)
        tool_row.pack(fill="x")

        ttk.Button(tool_row, text="🔒 Quarantine",
                   command=self.open_quarantine).pack(side="left", padx=(0, 8))
        ttk.Button(tool_row, text="📜 Scan History",
                   command=self.open_history).pack(side="left", padx=8)
        ttk.Button(tool_row, text="🗂 Manage Signatures",
                   command=self.show_signatures).pack(side="left", padx=8)
        ttk.Button(tool_row, text="⚙ Settings",
                   command=self.open_settings).pack(side="left", padx=8)

        # Last scan card
        last = ttk.LabelFrame(self, text="Last Scan", padding=12)
        last.pack(fill="x", padx=24, pady=(0, 12))
        self.last_scan_label = ttk.Label(last, text="No scans yet.", style="Card.TLabel")
        self.last_scan_label.pack(anchor="w")

        # Progress
        prog = ttk.LabelFrame(self, text="Scan Progress", padding=12)
        prog.pack(fill="x", padx=24, pady=(0, 12))

        self.progress_var = tk.IntVar(value=0)
        ttk.Progressbar(prog, orient="horizontal", mode="determinate",
                        variable=self.progress_var).pack(fill="x")
        self.progress_label = ttk.Label(prog, text="Idle.")
        self.progress_label.pack(anchor="w", pady=(6, 0))
        self.cancel_btn = ttk.Button(prog, text="Cancel Scan",
                                     command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(anchor="e", pady=(6, 0))

        # Footer
        ttk.Label(
            self,
            text="Educational prototype — Not a replacement for commercial antivirus software.",
            style="Sub.TLabel",
        ).pack(side="bottom", pady=10)

    # ------------------------------------------------------------------
    # Stats refresh
    # ------------------------------------------------------------------

    def refresh_stats(self):
        last = self.db.get_last_completed_scan()
        if last:
            files = last["files_scanned"]
            threats = last["threats_found"]
        else:
            files = 0
            threats = 0

        # Count from history totals (sum across all scans)
        rows = self.db.list_scans()
        total_files = sum(r["files_scanned"] for r in rows)
        total_threats = sum(r["threats_found"] for r in rows)

        self.card_files.set(str(total_files))
        self.card_threats.set(str(total_threats))
        self.card_quarantine.set(str(self.qm.count()))
        self.card_scans.set(str(self.db.count_scans()))

        if last:
            self.last_scan_label.config(
                text=f"Type: {last['scan_type']}   "
                     f"Target: {last['target']}\n"
                     f"Finished: {short_time(last['finished_at'])}   "
                     f"Files: {last['files_scanned']}   "
                     f"Threats: {last['threats_found']}   "
                     f"Duration: {last['duration_seconds']:.2f}s"
            )
        else:
            self.last_scan_label.config(text="No scans yet.")

    # ------------------------------------------------------------------
    # Scan actions
    # ------------------------------------------------------------------

    def _start_scan(self, scan_type: str, targets):
        if self.scanner is not None:
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return
        targets = [Path(t) for t in targets if Path(t).exists()]
        if not targets:
            messagebox.showwarning("No Targets",
                                   "No valid folders to scan. Check Settings.")
            return

        self.progress_var.set(0)
        self.progress_label.config(
            text=f"Starting {scan_type} scan on {len(targets)} folder(s)…"
        )
        self.cancel_btn.config(state="normal")

        self.scanner = FileScanner(
            db=self.db, progress_callback=self._on_progress, scan_type=scan_type,
        )
        threading.Thread(target=self._run_scan, args=(targets,), daemon=True).start()

    def start_quick_scan(self):
        targets = get_quick_scan_targets(self.settings)
        self._start_scan("quick", targets)

    def start_full_scan(self):
        targets = get_full_scan_targets(self.settings)
        if not targets:
            messagebox.showwarning("No Target",
                                   "Full scan target missing. Check Settings.")
            return
        if not messagebox.askyesno(
            "Full Scan",
            f"Full scan will walk:\n{targets[0]}\n\n"
            "This may take a while. Continue?"
        ):
            return
        self._start_scan("full", targets)

    def start_custom_scan(self):
        folder_str = filedialog.askdirectory(title="Select a folder to scan")
        if not folder_str:
            return
        self._start_scan("custom", [folder_str])

    def _run_scan(self, targets):
        try:
            combined = ScanResult(target=Path(",".join(str(t) for t in targets)))
            for t in targets:
                r = self.scanner.scan_folder(Path(t))
                combined.files.extend(r.files)
                combined.errors.extend(r.errors)
                combined.total_size += r.total_size
            result = combined
        except Exception as e:
            result = ScanResult(target=Path(str(targets)))
            result.errors.append(type("E", (), {"path": targets, "reason": str(e)})())
        self.after(0, lambda: self._on_scan_finished(result))

    def _on_progress(self, current: int, total: int, current_path: str):
        def update():
            if total > 0:
                self.progress_var.set(int(current / total * 100))
            short = current_path if len(current_path) < 70 else "..." + current_path[-67:]
            self.progress_label.config(text=f"[{current}/{total}] {short}")
        try:
            self.after(0, update)
        except Exception:
            pass

    def _on_scan_finished(self, result: ScanResult):
        self.scanner = None
        self.cancel_btn.config(state="disabled")
        self._last_result = result

        self.progress_var.set(100)
        self.progress_label.config(
            text=f"Scan complete. {result.file_count} files, "
                 f"{result.threat_count} threats, {result.error_count} errors."
        )

        if result.threat_count > 0:
            self.status_label.config(text=f"  ● {result.threat_count} THREAT(S) DETECTED  ",
                                     bg=RED)
        else:
            self.status_label.config(text="  ● NO THREATS FOUND  ", bg=GREEN)

        self.refresh_stats()
        self._show_result_popup(result)

    def _show_result_popup(self, result: ScanResult):
        win = tk.Toplevel(self)
        win.title("Scan Result")
        win.geometry("960x520")
        win.configure(bg=BG)

        ttk.Label(win, text=f"Target: {result.target}",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        ttk.Label(
            win,
            text=f"Files: {result.file_count}   "
                 f"Size: {human_size(result.total_size)}   "
                 f"Threats: {result.threat_count}   "
                 f"Errors: {result.error_count}",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=10, pady=(0, 8))

        cols = ("path", "method", "threat", "severity", "reason")
        tree = ttk.Treeview(win, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            tree.heading(c, text=c)
        tree.column("path", width=220)
        tree.column("method", width=90)
        tree.column("threat", width=160)
        tree.column("severity", width=70)
        tree.column("reason", width=340)
        tree.pack(fill="both", expand=True, padx=10, pady=8)

        self._tree_items = {}
        for f in result.detected_files:
            methods = ",".join(f.detection_methods) if f.detection_methods else ""
            reason = " | ".join(f.reasons) if f.reasons else ""
            iid = tree.insert("", "end", values=(
                str(f.path), methods, f.threat_name or "", f.severity or "", reason,
            ))
            self._tree_items[iid] = f

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x", padx=10, pady=(0, 10))

        def quarantine_selected():
            items = tree.selection()
            if not items:
                messagebox.showinfo("Nothing selected", "Select one or more files to quarantine.")
                return
            if self.settings.get_bool("confirm_before_quarantine", True):
                if not messagebox.askyesno(
                    "Confirm Quarantine",
                    f"Move {len(items)} file(s) into quarantine?"
                ):
                    return
            ok, failed = 0, 0
            for iid in items:
                info = self._tree_items.get(iid)
                if info is None:
                    continue
                entry = self.qm.quarantine_file(
                    path=info.path, threat_name=info.threat_name,
                    severity=info.severity, sha256=info.sha256,
                )
                if entry is not None:
                    ok += 1
                    tree.delete(iid)
                else:
                    failed += 1
            self.refresh_stats()
            messagebox.showinfo("Quarantine Complete",
                                f"Quarantined: {ok}\nFailed: {failed}")

        ttk.Button(btns, text="Quarantine Selected", command=quarantine_selected) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right", padx=5)

    def cancel_scan(self):
        if self.scanner is not None:
            self.scanner.cancel()
            self.progress_label.config(text="Cancelling...")
            self.cancel_btn.config(state="disabled")

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def open_quarantine(self):
        QuarantineWindow(self)
        self.after(500, self.refresh_stats)

    def open_history(self):
        HistoryWindow(self)
        self.after(500, self.refresh_stats)

    def open_settings(self):
        SettingsWindow(self)
        self.after(500, self.refresh_stats)

    def show_signatures(self):
        win = tk.Toplevel(self)
        win.title("Detection Signatures")
        win.geometry("760x480")
        win.configure(bg=BG)

        ttk.Label(win, text=f"Hash signatures: {self.db.count_threats()}   |   "
                            f"Byte signatures: {self.db.count_signatures()}",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=8)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=10, pady=6)

        f1 = ttk.Frame(nb)
        nb.add(f1, text="Hash signatures")
        cols = ("sha256", "name", "severity", "added_on")
        t1 = ttk.Treeview(f1, columns=cols, show="headings")
        for c in cols:
            t1.heading(c, text=c)
            t1.column(c, width=140, anchor="w")
        t1.column("sha256", width=260)
        for r in self.db.list_threats():
            t1.insert("", "end", values=(r["sha256"], r["name"], r["severity"], r["added_on"]))
        t1.pack(fill="both", expand=True)

        f2 = ttk.Frame(nb)
        nb.add(f2, text="Byte signatures")
        cols2 = ("name", "pattern_hex", "severity", "description")
        t2 = ttk.Treeview(f2, columns=cols2, show="headings")
        for c in cols2:
            t2.heading(c, text=c)
            t2.column(c, width=140, anchor="w")
        t2.column("pattern_hex", width=240)
        for r in self.db.list_signatures():
            t2.insert("", "end", values=(r["name"], r["pattern_hex"], r["severity"], r["description"] or ""))
        t2.pack(fill="both", expand=True)