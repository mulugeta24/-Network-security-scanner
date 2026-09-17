"""Application settings for NETRECON."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_TIMEOUT = 0.5
DEFAULT_MAX_WORKERS = 20
DATABASE_PATH = PROJECT_ROOT / "data" / "netrecon.db"
REPORTS_DIRECTORY = PROJECT_ROOT / "reports"
