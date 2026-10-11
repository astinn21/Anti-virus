"""
core/scanner.py
Walks folders, runs detection, and records scan history + logs.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from core.models import FileInfo, ScanError, ScanResult
from core.database import Database
from core.detection import DetectionEngine
from core.logger import get_logger


log = get_logger()


class FileScanner:
    def __init__(
        self,
        db: Optional[Database] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        scan_type: str = "custom",
    ):
        self.db = db or Database()
        self.detection = DetectionEngine(self.db)
        self.progress_callback = progress_callback
        self.scan_type = scan_type
        self._cancelled = False
        self.scan_id: Optional[int] = None

    def cancel(self):
        self._cancelled = True

    def scan_folder(self, folder: Path) -> ScanResult:
        folder = Path(folder)
        result = ScanResult(target=folder)
        started = time.time()

        # ---- Record scan start ----
        try:
            self.scan_id = self.db.start_scan_record(self.scan_type, str(folder))
        except Exception as e:
            log.error(f"Failed to start scan record: {e}")
            self.scan_id = None

        log.info(f"Scan started: type={self.scan_type} target={folder}")

        if not folder.exists():
            result.errors.append(ScanError(folder, "Folder does not exist"))
            self._finalize(started, result, status="failed")
            return result
        if not folder.is_dir():
            result.errors.append(ScanError(folder, "Path is not a folder"))
            self._finalize(started, result, status="failed")
            return result

        all_files = []
        for root, dirs, files in os.walk(folder, onerror=self._on_walk_error_factory(result)):
            if self._cancelled:
                break
            for name in files:
                all_files.append(Path(root) / name)

        total = len(all_files)
        if total == 0:
            log.info(f"Scan finished: no files found in {folder}")
            self._finalize(started, result, status="completed")
            return result

        for index, file_path in enumerate(all_files, start=1):
            if self._cancelled:
                break

            info = self._process_file(file_path)

            if info.readable:
                result.files.append(info)
                result.total_size += info.size
                if info.detected:
                    log.warning(
                        f"DETECTED: {file_path} | "
                        f"threat={info.threat_name} | "
                        f"methods={','.join(info.detection_methods)}"
                    )
            else:
                result.errors.append(ScanError(file_path, info.error or "Unreadable"))

            if self.progress_callback:
                try:
                    self.progress_callback(index, total, str(file_path))
                except Exception:
                    pass

        status = "cancelled" if self._cancelled else "completed"
        self._finalize(started, result, status=status)
        return result

    # ------------------------------------------------------------------

    def _finalize(self, started: float, result: ScanResult, status: str):
        duration = round(time.time() - started, 3)

        if self.scan_id is not None:
            try:
                self.db.finish_scan_record(
                    scan_id=self.scan_id,
                    files_scanned=result.file_count,
                    threats_found=result.threat_count,
                    errors_count=result.error_count,
                    duration_seconds=duration,
                    status=status,
                )
            except Exception as e:
                log.error(f"Failed to record scan history: {e}")

        log.info(
            f"Scan {status}: files={result.file_count} "
            f"threats={result.threat_count} errors={result.error_count} "
            f"duration={duration}s"
        )

    def _process_file(self, path: Path) -> FileInfo:
        try:
            stat = path.stat()
            size = stat.st_size
        except (PermissionError, FileNotFoundError, OSError) as e:
            return FileInfo(path=path, name=path.name,
                            extension=path.suffix.lower(), size=0,
                            readable=False, error=str(e))

        info = FileInfo(
            path=path, name=path.name,
            extension=path.suffix.lower(), size=size,
            readable=True,
        )

        try:
            det = self.detection.analyze(path)
        except Exception as e:
            info.error = f"Detection error: {e}"
            return info

        info.sha256 = det.sha256
        info.detected = det.detected
        info.threat_name = det.threat_name
        info.severity = det.severity
        info.detection_methods = det.detection_methods
        info.reasons = det.reasons
        return info

    def _on_walk_error_factory(self, result: ScanResult):
        def _on_error(os_error):
            try:
                result.errors.append(ScanError(Path(os_error.filename), str(os_error)))
            except Exception:
                pass
        return _on_error