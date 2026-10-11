"""
gui/quarantine_view.py
Window that lists quarantined files with Restore / Delete actions.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from core.quarantine import QuarantineManager


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


class QuarantineWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Quarantine")
        self.geometry("960x520")
        self.qm = QuarantineManager()
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Quarantined Files",
                  font=("Segoe UI", 13, "bold")).pack(side="left")

        self.count_var = tk.StringVar(value="0")
        ttk.Label(top, textvariable=self.count_var,
                  font=("Segoe UI", 10)).pack(side="right")

        cols = ("id", "name", "threat", "severity", "size", "quarantined_on", "original_path")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c)
        widths = {
            "id": 90, "name": 180, "threat": 170, "severity": 80,
            "size": 90, "quarantined_on": 150, "original_path": 320,
        }
        for c, w in widths.items():
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=6)

        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")

        ttk.Button(btns, text="Restore Selected", command=self.restore_selected) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Restore As…", command=self.restore_as) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Delete Forever", command=self.delete_selected) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Refresh", command=self.refresh) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Close", command=self.destroy) \
            .pack(side="right", padx=5)

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        entries = self.qm.list_entries()
        self.count_var.set(f"{len(entries)} item(s)")

        for e in entries:
            self.tree.insert("", "end", iid=e.id, values=(
                e.id[:10] + "…",
                e.name,
                e.threat_name or "",
                e.severity or "",
                human_size(e.size),
                e.quarantined_on,
                str(e.original_path),
            ))

    def _selected_ids(self):
        return list(self.tree.selection())

    def restore_selected(self):
        ids = self._selected_ids()
        if not ids:
            messagebox.showinfo("Nothing selected", "Select one or more items to restore.")
            return
        if not messagebox.askyesno(
            "Confirm Restore",
            f"Restore {len(ids)} file(s) to their original locations?\n\n"
            "WARNING: These files were flagged as suspicious. Restoring them "
            "puts them back on your system."
        ):
            return

        ok = 0
        failed = 0
        for qid in ids:
            if self.qm.restore(qid):
                ok += 1
            else:
                failed += 1

        self.refresh()
        messagebox.showinfo("Restore Complete",
                            f"Restored: {ok}\nFailed: {failed}")

    def restore_as(self):
        ids = self._selected_ids()
        if len(ids) != 1:
            messagebox.showinfo("Select one", "Select exactly one item to restore as a custom location.")
            return
        qid = ids[0]
        entry = self.qm.get_entry(qid)
        if entry is None:
            return

        target = filedialog.asksaveasfilename(
            title="Restore As",
            initialfile=entry.name,
        )
        if not target:
            return

        if self.qm.restore(qid, destination=Path(target)):
            self.refresh()
            messagebox.showinfo("Restored", f"Restored to:\n{target}")
        else:
            messagebox.showerror("Restore Failed", "Could not restore the file.")

    def delete_selected(self):
        ids = self._selected_ids()
        if not ids:
            messagebox.showinfo("Nothing selected", "Select one or more items to delete.")
            return
        if not messagebox.askyesno(
            "Confirm Permanent Delete",
            f"Permanently delete {len(ids)} quarantined file(s)?\n\n"
            "This CANNOT be undone."
        ):
            return
        ok = 0
        for qid in ids:
            if self.qm.delete_forever(qid):
                ok += 1
        self.refresh()
        messagebox.showinfo("Deleted", f"Deleted {ok} file(s).")