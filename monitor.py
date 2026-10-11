"""
core/monitor.py

Controlled real-time monitoring by polling a folder every N seconds.

This is intentionally simple and safe for an educational prototype.
It does NOT hook into the OS kernel; it just watches a folder's
contents and reacts to new or modified files.
"""

import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.detection import DetectionEngine
from core.database import Database
from core.logger import get_logger


log = get_logger()


@dataclass
class MonitorEvent:
    timestamp: str
    event_type: str          # "created" | "modified"
    path: Path
    detected: bool
    threat_name: Optional[str]
    severity: Optional[str]
    detection_methods: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    quarantined: bool = False


@dataclass
class FileSnapshot:
    mtime: float
    size: int


class MonitorManager:
    """
    Polling-based folder monitor.

    Usage:
        m = MonitorManager(db, on_event=my_callback)
        m.start(Path.home() / "Desktop")
        ...
        m.stop()
    """

    def __init__(
        self,
        db: Optional[Database] = None,
        on_event: Optional[Callable[[MonitorEvent], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        auto_quarantine: bool = False,
        quarantine_manager=None,
    ):
        self.db = db or Database()
        self.detection = DetectionEngine(self.db)
        self.on_event = on_event
        self.on_status = on_status
        self.auto_quarantine = auto_quarantine
        self.quarantine_manager = quarantine_manager  # avoid circular import

        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._snapshot: Dict[Path, FileSnapshot] = {}
        self._watched_path: Optional[Path] = None
        self._interval: float = 2.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def watched_path(self) -> Optional[Path]:
        return self._watched_path

    def start(self, folder: Path, interval: float = 2.0) -> bool:
        if self.is_running:
            log.warning("Monitor already running")
            return False

        folder = Path(folder)
        if not folder.exists() or not folder.is_dir():
            log.error(f"Monitor: invalid folder {folder}")
            return False

        self._watched_path = folder
        self._interval = max(0.5, float(interval))
        self._stop_flag.clear()

        # Initial snapshot — no events for pre-existing files
        self._snapshot = self._scan_folder_once()

        self._thread = threading.Thread(
            target=self._loop, name="monitor", daemon=True,
        )
        self._thread.start()

        log.info(f"Monitor started on {folder} (interval={self._interval}s)")
        self._emit_status(f"Monitoring: {folder}")
        return True

    def stop(self):
        if not self.is_running:
            return
        self._stop_flag.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 1.0)
        self._thread = None
        log.info("Monitor stopped")
        self._emit_status("Monitor stopped.")

    def set_auto_quarantine(self, value: bool):
        self.auto_quarantine = bool(value)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self):
        while not self._stop_flag.is_set():
            try:
                current = self._scan_folder_once()
                self._diff_and_handle(current)
                self._snapshot = current
            except Exception as e:
                log.error(f"Monitor loop error: {e}")
            self._stop_flag.wait(self._interval)

    def _scan_folder_once(self) -> Dict[Path, FileSnapshot]:
        """
        Walk the watched folder (non-recursive by default — keeps it cheap).
        Set recursive=True in the code below if you want subfolders.
        """
        result: Dict[Path, FileSnapshot] = {}
        folder = self._watched_path
        if folder is None or not folder.exists():
            return result

        # Non-recursive walk
        for entry in os.scandir(folder):
            try:
                if not entry.is_file():
                    continue
                stat = entry.stat()
                result[Path(entry.path)] = FileSnapshot(mtime=stat.st_mtime, size=stat.st_size)
            except (PermissionError, FileNotFoundError, OSError):
                continue
        return result

    def _diff_and_handle(self, current: Dict[Path, FileSnapshot]):
        new_files = []
        modified_files = []

        for path, snap in current.items():
            old = self._snapshot.get(path)
            if old is None:
                new_files.append(path)
            elif old.mtime != snap.mtime or old.size != snap.size:
                modified_files.append(path)

        for path in new_files:
            self._handle(path, "created")
        for path in modified_files:
            self._handle(path, "modified")

    def _handle(self, path: Path, event_type: str):
        try:
            det = self.detection.analyze(path)
        except Exception as e:
            log.error(f"Monitor analyze failed for {path}: {e}")
            return

        event = MonitorEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event_type=event_type,
            path=path,
            detected=det.detected,
            threat_name=det.threat_name,
            severity=det.severity,
            detection_methods=list(det.detection_methods),
            reasons=list(det.reasons),
        )

        if det.detected:
            log.warning(
                f"Monitor detected [{event_type}] {path} | "
                f"threat={det.threat_name} methods={','.join(det.detection_methods)}"
            )

            if self.auto_quarantine and self.quarantine_manager is not None:
                try:
                    entry = self.quarantine_manager.quarantine_file(
                        path=path,
                        threat_name=det.threat_name,
                        severity=det.severity,
                        sha256=det.sha256,
                    )
                    if entry is not None:
                        event.quarantined = True
                        log.warning(f"Monitor auto-quarantined: {path}")
                except Exception as e:
                    log.error(f"Auto-quarantine failed for {path}: {e}")

        # Only emit to the GUI for detections OR always? We emit detections only
        # to avoid spamming the log on every normal file save. Change the
        # condition below to `if True:` if you want to see every event.
        if event.detected or event.quarantined:
            self._emit_event(event)

    def _emit_event(self, event: MonitorEvent):
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception as e:
                log.error(f"Monitor on_event callback failed: {e}")

    def _emit_status(self, message: str):
        if self.on_status is not None:
            try:
                self.on_status(message)
            except Exception:
                pass