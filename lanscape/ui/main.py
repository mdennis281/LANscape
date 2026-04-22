"""Main entry point for the LANscape application when running as a module."""
import logging
import time
import traceback

import psutil

from lanscape.core.logger import configure_logging
from lanscape.core.runtime_args import parse_args, was_port_explicit, was_ws_port_explicit
from lanscape.core.version_manager import get_installed_version
from lanscape.ui.ws.server import run_server
from lanscape.ui.react_proxy import start_webapp_server
from lanscape.core.service_scan import resources as svc_resources

log = logging.getLogger('core')

# Module-level reference so helper functions can access it after main() sets it.
args = None  # pylint: disable=invalid-name


def main():
    """Core entry point for running lanscape as a module."""
    global args  # pylint: disable=global-statement
    args = parse_args()
    configure_logging(args.loglevel, args.logfile)

    if not args.printer_safety:
        svc_resources.PRINTER_SAFETY = False

    try:
        _main()
    except KeyboardInterrupt:
        log.info('Keyboard interrupt received, terminating...')
    except Exception as e:
        log.critical(f'Unexpected error: {e}')
        log.debug(traceback.format_exc())


def _main():
    log.info(f'LANscape v{get_installed_version()}')

    # Check if WebSocket server only mode is requested
    if args.ws_server:
        start_websocket_server()
        return

    # Default: Start webapp mode (React UI + WebSocket backend)
    start_webapp_mode()


def start_websocket_server():
    """Start the WebSocket server only."""
    if was_ws_port_explicit():
        validate_port_available(args.ws_port, '--ws-port')
    else:
        args.ws_port = get_valid_port(args.ws_port)

    log.info(f'Starting WebSocket server on port {args.ws_port}')

    try:
        run_server(host='0.0.0.0', port=args.ws_port, debug_mode=args.debug)
    except KeyboardInterrupt:
        log.info('WebSocket server stopped by user')
    except Exception as e:
        log.critical(f'WebSocket server failed: {e}')
        log.debug(traceback.format_exc())
        raise


def start_webapp_mode():
    """Start the React webapp with WebSocket backend (default mode)."""
    if was_port_explicit():
        validate_port_available(args.ui_port, '--ui-port')
    else:
        args.ui_port = get_valid_port(args.ui_port)

    if was_ws_port_explicit():
        validate_port_available(args.ws_port, '--ws-port')
    else:
        args.ws_port = get_valid_port(args.ws_port)

    log.info('Starting React webapp mode')
    log.info(f'Reserving ports: {args.ui_port} - UI | {args.ws_port} - WS')

    try:
        start_webapp_server(
            http_port=args.ui_port,
            ws_port=args.ws_port,
            open_browser=True,
            persistent=args.persistent,
            mdns_enabled=args.mdns_enabled,
            debug_mode=args.debug,
        )
    except KeyboardInterrupt:
        log.info('Webapp stopped by user')
    except Exception as e:
        log.critical(f'Webapp failed: {e}')
        log.debug(traceback.format_exc())
        raise


def _get_bound_ports() -> set[int]:
    """Return the set of all TCP ports currently bound on the system."""
    try:
        return {
            conn.laddr.port
            for conn in psutil.net_connections(kind='tcp')
            if conn.laddr
        }
    except (psutil.AccessDenied, OSError):
        return set()


def is_port_available(port: int, bound_ports: set[int] | None = None) -> bool:
    """Check if a port is available for binding."""
    if bound_ports is None:
        bound_ports = _get_bound_ports()
    return port not in bound_ports


def validate_port_available(port: int, flag_name: str, retries: int = 10,
                            delay: float = 0.5) -> None:
    """
    Validate that an explicitly specified port is available.
    Retries briefly to handle hot-reload scenarios where the previous
    process hasn't released the port yet.
    Raises an error if the port is still in use after all retries.
    """
    for attempt in range(retries):
        if is_port_available(port):
            return
        if attempt < retries - 1:
            log.debug(f'Port {port} in use, retrying in {delay}s '
                      f'({attempt + 1}/{retries})')
            time.sleep(delay)
    raise OSError(
        f"Port {port} is already in use. "
        f"Either free the port or remove the {flag_name} flag to auto-"
        f"select an available port."
    )


def get_valid_port(port: int) -> int:
    """
    Get the first available port starting from the specified port.

    Args:
        port: Starting port number to check

    Returns:
        First available port

    Raises:
        RuntimeError: If no available port found between port and 65535
    """
    max_port = 65535
    start_port = port
    bound_ports = _get_bound_ports()
    while port <= max_port:
        if is_port_available(port, bound_ports):
            return port
        port += 1
    raise RuntimeError(
        f"No available port found between {start_port} and {max_port}"
    )


if __name__ == "__main__":
    main()
