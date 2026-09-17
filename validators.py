"""Input validation helpers for targets and scan options."""

import ipaddress
import re
import socket


_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_target(target: str) -> str:
    """Validate an IPv4 address, IPv6 address, or ordinary hostname."""
    value = target.strip()
    if not value:
        raise ValueError("Target cannot be empty.")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if len(value) > 253 or value.endswith("."):
        raise ValueError("Target must be a valid IP address or hostname.")

    labels = value.split(".")
    if "." in value and all(label.isdigit() for label in labels):
        raise ValueError("Target must be a valid IP address or hostname.")
    if all(_HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return value
    raise ValueError("Target must be a valid IP address or hostname.")


def resolve_target(target: str) -> str:
    """Confirm that a hostname can be resolved without initiating a scan."""
    validated = validate_target(target)
    try:
        socket.getaddrinfo(validated, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError(f"Target could not be resolved: {validated}") from error
    return validated
