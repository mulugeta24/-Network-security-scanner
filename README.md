# NETRECON - Network Security Scanner

NETRECON is a beginner-friendly Python network security assessment tool. It performs basic TCP connection checks against one authorized IP address or hostname, identifies common service names, stores results in SQLite, and creates readable reports.

**Use this project only on localhost, your own computer, an isolated VirtualBox laboratory, an authorized educational platform, or another system where you have explicit permission.** Port scanning without authorization may be illegal and disruptive. NETRECON does not exploit vulnerabilities, bypass authentication, crack passwords, evade detection, or perform destructive actions.

## Features

- IPv4, IPv6, and hostname validation
- Individual ports and inclusive port ranges, such as `22,80,443` or `1-100`
- Duplicate removal and sorted port input
- Concurrent TCP checks using `ThreadPoolExecutor`
- `open`, `closed`, `timeout`, and `error` statuses
- Common TCP service names from Python's socket service database
- SQLite history at `data/netrecon.db`
- Timestamped text and CSV reports in `reports/`
- Interactive mode and command-line arguments
- Standard-library unit tests

## Technologies

Python 3.11 or newer, `socket`, `ipaddress`, `concurrent.futures`, `sqlite3`, `argparse`, `datetime`, `pathlib`, `unittest`, and the Python standard library. SQLite is built into Python; no separate database server installation is required.

## Folder structure

```text
netrecon/
├── main.py
├── scanner.py
├── database.py
├── reporter.py
├── config.py
├── validators.py
├── utils.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/.gitkeep
├── reports/.gitkeep
└── tests/
    ├── __init__.py
    ├── test_scanner.py
    ├── test_validators.py
    └── test_database.py
```

## Installation

No external packages are required. Install Python 3.11 or newer, then open this folder in your terminal or editor.

### Visual Studio Code

1. Open Visual Studio Code.
2. Select **File > Open Folder** and choose the NETRECON folder.
3. Open a new integrated terminal.
4. Confirm Python is available with `python --version`.
5. Run `python main.py`.

### Windows

```text
python --version
python main.py
```

### Kali Linux

```text
python3 --version
python3 main.py
```

## Usage

Interactive mode asks for the target, ports, timeout, and worker count:

```text
python main.py
```

You can provide the target and ports as arguments. The program still asks for confirmation before scanning:

```text
python main.py --target 127.0.0.1 --ports 22,80,443
python main.py --target 127.0.0.1 --ports 1-100 --timeout 0.5 --workers 20
```

The timeout is applied to each TCP connection. Worker count is capped by the value you provide; the default is 20. Start with a small localhost port list such as `22,80,443`.

## Example output

```text
[OPEN] 127.0.0.1:80/tcp - http

Scan summary
Total ports scanned: 3
Open ports: 1
Closed ports: 2
Timeout results: 0
Errors: 0
Database location: .../data/netrecon.db
Report location: .../reports/scan_127.0.0.1_20260917_120000.txt
```

A service label such as `http` is only the commonly associated service name from Python's local socket service database. It does not prove the exact software or version running on a port.

## Database and reports

The first scan creates `data/netrecon.db` and the `scan_results` table automatically. SQLite is a local file database and does not need a server. Each result stores the target, port, protocol, status, service label, and timestamp.

Each scan creates a timestamped text report and a CSV report in `reports/`. Runtime database and report files are excluded from Git by `.gitignore`, while `.gitkeep` preserves the directories.

## Testing

Run the standard-library test suite from the project directory:

```text
python -m unittest discover -s tests -v
```

The database tests use a temporary database. The parser and validator tests do not contact the network.

## Troubleshooting

- **Python is not recognized:** install Python and enable it on `PATH`, then reopen the terminal.
- **Invalid target:** use an IP address or a hostname without spaces or unsupported characters.
- **Invalid ports:** use comma-separated integers or inclusive ranges from 1 through 65535.
- **No open ports:** ensure a service is listening on the authorized test machine; closed results are normal.
- **Permission or database errors:** check that the project directory is writable and that the database is not locked by another process.
- **Slow results:** use a smaller port list, a reasonable timeout, and no more workers than your environment needs.

## How it works

1. `validators.py` checks the target format.
2. `scanner.py` parses ports, creates TCP sockets, calls `connect_ex()`, classifies the result, and closes every socket.
3. A bounded `ThreadPoolExecutor` checks multiple ports concurrently.
4. `database.py` stores the resulting records with parameterized SQLite queries.
5. `reporter.py` writes text and CSV reports.
6. `main.py` displays the summary and locations of saved artifacts.

## Legal and ethical use

Scan only systems for which you have explicit authorization. Keep practice inside localhost or an isolated lab such as VirtualBox. Do not use NETRECON to scan public internet ranges, bypass access controls, exploit vulnerabilities, disrupt services, or collect information beyond the authorized assessment.

## Future improvements

Possible educational extensions include configurable output formats, a history viewing command, structured logging, retry policies for transient errors, and richer but still non-invasive service metadata.
