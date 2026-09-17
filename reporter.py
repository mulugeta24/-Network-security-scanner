"""Human-readable and CSV report generation."""

import csv
from datetime import datetime
from pathlib import Path
import re
from typing import Any

from config import REPORTS_DIRECTORY


def _safe_filename_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "_", value).strip("._") or "target"


def _counts(results: list[dict[str, Any]]) -> dict[str, int]:
    return {status: sum(result["status"] == status for result in results) for status in ("open", "closed", "timeout", "error")}


def generate_report(results: list[dict[str, Any]], output_dir: str | Path = REPORTS_DIRECTORY) -> Path:
    """Write a timestamped text report and return its path."""
    if not results:
        raise ValueError("Cannot generate a report without scan results.")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = str(results[0]["target"])
    scan_date = datetime.now()
    counts = _counts(results)
    lines = [
        "=" * 50,
        "             NETRECON SCAN REPORT",
        "=" * 50,
        "",
        f"Target: {target}",
        f"Scan date: {scan_date:%Y-%m-%d %H:%M:%S}",
        f"Total ports scanned: {len(results)}",
        f"Open ports found: {counts['open']}",
        "",
        "-" * 50,
        "OPEN PORTS",
        "-" * 50,
        "",
    ]
    open_results = [result for result in results if result["status"] == "open"]
    if open_results:
        for result in open_results:
            lines.extend([
                f"Port: {result['port']}/{result['protocol']}",
                "Status: open",
                f"Service: {result['service']}",
                "",
            ])
    else:
        lines.append("No open ports found.\n")
    lines.extend([
        "-" * 50,
        "SCAN SUMMARY",
        "-" * 50,
        "",
        f"Open: {counts['open']}",
        f"Closed: {counts['closed']}",
        f"Timeout: {counts['timeout']}",
        f"Errors: {counts['error']}",
        "",
        "Scan completed successfully.",
    ])
    timestamp = scan_date.strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{_safe_filename_part(target)}_{timestamp}.txt"
    report_path = directory / filename
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def generate_csv_report(results: list[dict[str, Any]], output_dir: str | Path = REPORTS_DIRECTORY) -> Path:
    """Write the same scan results as a timestamped CSV file."""
    if not results:
        raise ValueError("Cannot generate a report without scan results.")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = str(results[0]["target"])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = directory / f"scan_{_safe_filename_part(target)}_{timestamp}.csv"
    with path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=["target", "port", "protocol", "status", "service", "scan_time"])
        writer.writeheader()
        writer.writerows({field: result[field] for field in writer.fieldnames} for result in results)
    return path
