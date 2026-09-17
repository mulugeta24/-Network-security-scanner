"""Safe TCP connection scanning primitives."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import errno
import select
import socket
from typing import Any


class PortInputError(ValueError):
    """Raised when a port list or range is malformed."""


def parse_ports(port_input: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges into sorted unique ports."""
    if not port_input or not port_input.strip():
        raise PortInputError("Port input cannot be empty.")

    ports: set[int] = set()
    for item in port_input.split(","):
        item = item.strip()
        if not item:
            raise PortInputError("Port input contains an empty item.")
        if item.count("-") > 1:
            raise PortInputError(f"Invalid port range: {item}")

        if "-" in item:
            start_text, end_text = (part.strip() for part in item.split("-"))
            start = _parse_port(start_text, item)
            end = _parse_port(end_text, item)
            if start > end:
                raise PortInputError(f"Range start cannot exceed its end: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(item, item))

    return sorted(ports)


def _parse_port(value: str, original: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise PortInputError(f"Port must be an integer: {original}") from error
    if not 1 <= port <= 65535:
        raise PortInputError(f"Port must be between 1 and 65535: {original}")
    return port


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def _result(target: str, port: int, status: str) -> dict[str, Any]:
    return {
        "target": target,
        "port": port,
        "protocol": "tcp",
        "status": status,
        "service": _service_name(port),
        "scan_time": datetime.now().isoformat(timespec="seconds"),
    }


def _status_from_connection_code(connection_code: int) -> str:
    """Translate common POSIX and Windows connect_ex codes into scan statuses."""
    if connection_code == 0:
        return "open"
    if connection_code in {errno.ECONNREFUSED, 10061}:
        return "closed"
    if connection_code in {
        errno.ETIMEDOUT,
        errno.EWOULDBLOCK,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        10060,  # WSAETIMEDOUT
        10035,  # WSAEWOULDBLOCK
        10065,  # WSAEHOSTUNREACH
        10051,  # WSAENETUNREACH
    }:
        return "timeout"
    return "error"


def scan_port(target: str, port: int, timeout: float) -> dict[str, Any]:
    """Perform one TCP connect check and always close the socket."""
    sock: socket.socket | None = None
    try:
        addresses = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
        if not addresses:
            return _result(target, port, "error")
        family, socktype, protocol, _, address = addresses[0]
        sock = socket.socket(family, socktype, protocol)
        sock.settimeout(timeout)
        connection_code = sock.connect_ex(address)
        if connection_code in {errno.EWOULDBLOCK, 10035}:
            _, writable, exceptional = select.select([], [sock], [sock], timeout)
            if not writable and not exceptional:
                connection_code = errno.ETIMEDOUT
            else:
                connection_code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        status = _status_from_connection_code(connection_code)
        return _result(target, port, status)
    except socket.timeout:
        return _result(target, port, "timeout")
    except OSError:
        return _result(target, port, "error")
    finally:
        if sock is not None:
            sock.close()


def scan_target(
    target: str, ports: list[int], max_workers: int = 20, timeout: float = 0.5
) -> list[dict[str, Any]]:
    """Scan ports concurrently and return results sorted by port."""
    if max_workers < 1:
        raise ValueError("Worker count must be at least 1.")
    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda port: scan_port(target, port, timeout), ports))
    return sorted(results, key=lambda result: result["port"])
