"""SQLite storage for NETRECON scan results."""

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from config import DATABASE_PATH


_COLUMNS = ("target", "port", "protocol", "status", "service", "scan_time")


def initialize_database(db_path: str | Path = DATABASE_PATH) -> Path:
    """Create the database directory and scan_results table if needed."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    status TEXT NOT NULL,
                    service TEXT NOT NULL,
                    scan_time TEXT NOT NULL
                )
                """
            )
    return path


def save_results(results: list[dict[str, Any]], db_path: str | Path = DATABASE_PATH) -> int:
    """Save scan results with a parameterized batch insert."""
    path = initialize_database(db_path)
    values = [tuple(result[column] for column in _COLUMNS) for result in results]
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.executemany(
                """
                INSERT INTO scan_results
                    (target, port, protocol, status, service, scan_time)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
    return len(values)


def _read_rows(query: str, parameters: tuple[Any, ...], db_path: str | Path) -> list[dict[str, Any]]:
    path = initialize_database(db_path)
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_scan_history(db_path: str | Path = DATABASE_PATH) -> list[dict[str, Any]]:
    """Return all saved results, newest scan records first."""
    return _read_rows(
        "SELECT id, target, port, protocol, status, service, scan_time "
        "FROM scan_results ORDER BY id DESC",
        (),
        db_path,
    )


def get_results_by_target(target: str, db_path: str | Path = DATABASE_PATH) -> list[dict[str, Any]]:
    """Return saved results for one exact target."""
    return _read_rows(
        "SELECT id, target, port, protocol, status, service, scan_time "
        "FROM scan_results WHERE target = ? ORDER BY id DESC",
        (target,),
        db_path,
    )
