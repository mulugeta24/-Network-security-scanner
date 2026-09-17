"""Command-line entry point for NETRECON."""

import argparse
import sys

from config import DATABASE_PATH, DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT
from database import save_results
from reporter import generate_csv_report, generate_report
from scanner import parse_ports, scan_target
from utils import summarize_results
from validators import resolve_target, validate_target


BANNER = """==================================================
       NETRECON NETWORK SECURITY SCANNER
==================================================
Authorized security assessment tool
=================================================="""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Perform authorized TCP connection checks.")
    parser.add_argument("--target", help="Authorized IP address or hostname")
    parser.add_argument("--ports", help="Ports such as 22,80,443 or 1-100")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-port timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Maximum concurrent workers")
    return parser


def _ask(prompt: str, supplied: str | None) -> str:
    return supplied if supplied is not None else input(prompt).strip()


def _positive_float(value: float) -> float:
    if value <= 0:
        raise ValueError("Timeout must be greater than 0.")
    return value


def run(arguments: argparse.Namespace) -> int:
    print(BANNER)
    print("Warning: scan only systems you own or are explicitly authorized to assess.\n")
    target = _ask("Enter authorized target: ", arguments.target)
    ports_text = _ask("Enter ports (example: 22,80,443 or 1-100): ", arguments.ports)

    target = validate_target(target)
    ports = parse_ports(ports_text)
    timeout = _positive_float(arguments.timeout)
    if arguments.workers < 1:
        raise ValueError("Worker count must be at least 1.")

    if arguments.target is None and arguments.ports is None:
        print(f"\nTarget: {target}")
        print(f"Ports to scan: {len(ports)}")
        print(f"Timeout: {timeout} seconds")
        print(f"Workers: {arguments.workers}")
        if input("Start scan? [y/N]: ").strip().lower() not in {"y", "yes"}:
            print("Scan cancelled.")
            return 0
    else:
        print(f"\nTarget: {target}")
        print(f"Ports to scan: {len(ports)}")
        print(f"Timeout: {timeout} seconds")
        print(f"Workers: {arguments.workers}")
        if input("Start scan? [y/N]: ").strip().lower() not in {"y", "yes"}:
            print("Scan cancelled.")
            return 0

    # Resolution is done after confirmation so a declined scan has no network activity.
    resolve_target(target)
    print("\nScanning...\n")
    results = scan_target(target, ports, arguments.workers, timeout)
    for result in results:
        if result["status"] == "open":
            print(f"[OPEN] {target}:{result['port']}/tcp - {result['service']}")

    counts = summarize_results(results)
    report_path = generate_report(results)
    csv_path = generate_csv_report(results)
    save_results(results)
    print("\nScan summary")
    print(f"Total ports scanned: {len(results)}")
    print(f"Open ports: {counts['open']}")
    print(f"Closed ports: {counts['closed']}")
    print(f"Timeout results: {counts['timeout']}")
    print(f"Errors: {counts['error']}")
    print(f"Database location: {DATABASE_PATH}")
    print(f"Report location: {report_path}")
    print(f"CSV report location: {csv_path}")
    return 0


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except (ValueError, OSError, PermissionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
