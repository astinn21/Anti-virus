"""
config.py
Application-wide constants and paths.
"""

from pathlib import Path

# --- Application Info ---
APP_NAME = "Python Antivirus System"
APP_VERSION = "0.1.0"
APP_AUTHOR = "BSCS Student Project"

# --- Base Directory ---
BASE_DIR = Path(__file__).resolve().parent

# --- Data Directories ---
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "antivirus.db"

# --- Logs ---
LOGS_DIR = BASE_DIR / "logs"
LOG_FILE = LOGS_DIR / "activity.log"

# --- Ensure directories exist ---
DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# --- GUI Settings ---
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 600
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"