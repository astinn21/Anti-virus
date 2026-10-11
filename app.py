"""
gui/app.py
Main application window. Manages frames and navigation.
"""

import tkinter as tk
from tkinter import ttk

from config import WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_TITLE
from gui.dashboard import DashboardFrame


class AntivirusApp(tk.Tk):
    """Main Tkinter application window."""

    def __init__(self):
        super().__init__()

        self.title(WINDOW_TITLE)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(800, 500)

        # Style
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Container that holds all frames
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        # Show dashboard by default
        self.current_frame = None
        self.show_frame(DashboardFrame)

    def show_frame(self, frame_class):
        """Destroy current frame and show a new one."""
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = frame_class(parent=self)
        self.current_frame.pack(fill="both", expand=True)