"""TCP port availability helpers used by the UI layer."""
from __future__ import annotations

import logging
import socket
import time

import psutil

log = logging.getLogger('core')


def _get_bound_ports() -> set[int] | None:
    """Return the set of all TCP ports currently bound on the system.

    Returns None if the information could not be collected (e.g. access
    denied), so callers can fall back to a direct socket check.
    """
    try:
        return {
            conn.laddr.port
            for conn in psutil.net_connections(kind='tcp')
            if conn.laddr
        }
    except (psutil.AccessDenied, OSError):
        return None


def _socket_port_in_use(port: int) -> bool:
    """Fallback: attempt a non-blocking socket bind to determine if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('127.0.0.1', port))
            return False
        except OSError:
            return True


def is_port_available(port: int, bound_ports: set[int] | None = None) -> bool:
    """Check if a port is available for binding."""
    if bound_ports is not None:
        return port not in bound_ports
    ports = _get_bound_ports()
    if ports is not None:
        return port not in ports
    return not _socket_port_in_use(port)


def validate_port_available(port: int, flag_name: str, retries: int = 10,
                            delay: float = 0.5) -> None:
    """Validate that an explicitly specified port is available.

    Retries briefly to handle hot-reload scenarios where the previous
    process hasn't released the port yet. Raises an OSError if the port
    is still in use after all retries.
    """
    for attempt in range(retries):
        if is_port_available(port):
            return
        if attempt < retries - 1:
            log.debug('Port %s in use, retrying in %ss (%s/%s)',
                      port, delay, attempt + 1, retries)
            time.sleep(delay)
    raise OSError(
        f"Port {port} is already in use. "
        f"Either free the port or remove the {flag_name} flag to auto-"
        f"select an available port.")


def get_valid_port(port: int) -> int:
    """Get the first available port starting from the specified port.

    Raises RuntimeError if no available port is found between `port` and 65535.
    """
    max_port = 65535
    start_port = port
    bound_ports = _get_bound_ports()
    while port <= max_port:
        if is_port_available(port, bound_ports):
            return port
        port += 1
    raise RuntimeError(
        f"No available port found between {start_port} and {max_port}")
