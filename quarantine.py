"""
core/quarantine.py
Quarantine manager with logging and defensive checks.
"""

import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from config import QUARANTINE_DIR
from core.database import Database
from core.hasher import hash_file
from core.logger import get_logger


log = get_logger()


@dataclass
class QuarantineEntry:
    id: str
    original_path: Path
    stored_path: Path
    name: str
    sha256: Optional[str]
    threat_name: Optional[str]
    severity: Optional[str]
    size: int
    quarantined_on: str


class QuarantineManager:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.dir = QUARANTINE_DIR
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.error(f"Could not create quarantine folder: {e}")

    def quarantine_file(self, path: Path, threat_name=None, severity=None,
                        sha256=None) -> Optional[QuarantineEntry]:
        path = Path(path)
        if not path.exists() or not path.is_file():
            log.error(f"Quarantine failed: not a file: {path}")
            return None

        if sha256 is None:
            try:
                sha256 = hash_file(path)
            except Exception as e:
                log.error(f"Quarantine hash failed for {path}: {e}")
                sha256 = None

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        qid = uuid.uuid4().hex
        stored = self.dir / f"{qid}.bin"

        try:
            shutil.copy2(path, stored)
        except Exception as e:
            log.error(f"Quarantine copy failed for {path}: {e}")
            return None

        if not stored.exists():
            log.error(f"Quarantine file not created: {stored}")
            return None

        try:
            ok = self.db.add_quarantine_entry(
                qid=qid,
                original_path=str(path),
                stored_path=str(stored),
                name=path.name,
                sha256=sha256,
                threat_name=threat_name,
                severity=severity,
                size=size,
            )
        except Exception as e:
            log.error(f"Quarantine DB insert exception: {e}")
            ok = False

        if not ok:
            try:
                stored.unlink()
            except Exception:
                pass
            return None

        try:
            path.unlink()
        except Exception as e:
            try:
                stored.unlink()
            except Exception:
                pass
            try:
                self.db.delete_quarantine_entry(qid)
            except Exception:
                pass
            log.error(f"Quarantine could not delete original {path}: {e}")
            return None

        log.warning(
            f"QUARANTINED: {path} -> id={qid[:10]} "
            f"threat={threat_name} severity={severity}"
        )
        return QuarantineEntry(
            id=qid, original_path=path, stored_path=stored,
            name=path.name, sha256=sha256, threat_name=threat_name,
            severity=severity, size=size, quarantined_on="",
        )

    def list_entries(self):
        try:
            rows = self.db.list_quarantine()
        except Exception as e:
            log.error(f"Quarantine list failed: {e}")
            return []
        return [QuarantineEntry(
            id=r["id"], original_path=Path(r["original_path"]),
            stored_path=Path(r["stored_path"]), name=r["name"],
            sha256=r["sha256"], threat_name=r["threat_name"],
            severity=r["severity"], size=r["size"],
            quarantined_on=r["quarantined_on"],
        ) for r in rows]

    def get_entry(self, qid: str) -> Optional[QuarantineEntry]:
        try:
            r = self.db.get_quarantine_entry(qid)
        except Exception:
            return None
        if r is None:
            return None
        return QuarantineEntry(
            id=r["id"], original_path=Path(r["original_path"]),
            stored_path=Path(r["stored_path"]), name=r["name"],
            sha256=r["sha256"], threat_name=r["threat_name"],
            severity=r["severity"], size=r["size"],
            quarantined_on=r["quarantined_on"],
        )

    def restore(self, qid: str, destination: Optional[Path] = None) -> bool:
        entry = self.get_entry(qid)
        if entry is None or not entry.stored_path.exists():
            log.error(f"Restore failed: missing entry {qid}")
            return False

        target = Path(destination) if destination else entry.original_path
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry.stored_path, target)
        except Exception as e:
            log.error(f"Restore copy failed for {qid}: {e}")
            return False

        try:
            entry.stored_path.unlink()
        except Exception:
            pass
        try:
            self.db.delete_quarantine_entry(qid)
        except Exception:
            pass
        log.info(f"RESTORED: id={qid[:10]} -> {target}")
        return True

    def delete_forever(self, qid: str) -> bool:
        entry = self.get_entry(qid)
        if entry is None:
            return False
        try:
            if entry.stored_path.exists():
                entry.stored_path.unlink()
        except Exception as e:
            log.error(f"Delete failed for {qid}: {e}")
            return False
        try:
            self.db.delete_quarantine_entry(qid)
        except Exception:
            pass
        log.warning(f"DELETED FROM QUARANTINE: id={qid[:10]} name={entry.name}")
        return True

    def count(self) -> int:
        try:
            return self.db.count_quarantine()
        except Exception:
            return 0