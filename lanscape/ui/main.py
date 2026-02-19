"""Main entry point for the LANscape application when running as a module."""
import socket
import logging
import traceback

from lanscape.core.logger import configure_logging
from lanscape.core.runtime_args import parse_args, was_port_explicit, was_ws_port_explicit
from lanscape.core.version_manager import get_installed_version, is_update_available
from lanscape.ui.ws.server import run_server
from lanscape.ui.react_proxy import start_webapp_server

# do this so any logs generated on import are displayed
args = parse_args()
configure_logging(args.loglevel, args.logfile)


log = logging.getLogger('core')


def main():
    """Core entry point for running lanscape as a module."""
    try:
        _main()
    except KeyboardInterrupt:
        log.info('Keyboard interrupt received, terminating...')
    except Exception as e:
        log.critical(f'Unexpected error: {e}')
        log.debug(traceback.format_exc())


def _main():
    log.info(f'LANscape v{get_installed_version()}')
    try_check_update()

    # Check if WebSocket server only mode is requested
    if args.ws_server:
        start_websocket_server()
        return

    # Default: Start webapp mode (React UI + WebSocket backend)
    start_webapp_mode()


def try_check_update():
    """Check for updates and log if available."""
    try:
        if is_update_available():
            log.info('An update is available!')
            log.info(
                'Run "pip install --upgrade lanscape --no-cache" to suppress this message.')
    except BaseException:
        log.debug(traceback.format_exc())
        log.warning('Unable to check for updates.')


def start_websocket_server():
    """Start the WebSocket server only."""
    if was_ws_port_explicit():
        validate_port_available(args.ws_port, '--ws-port')
    else:
        args.ws_port = get_valid_port(args.ws_port)

    log.info(f'Starting WebSocket server on port {args.ws_port}')

    try:
        run_server(host='0.0.0.0', port=args.ws_port)
    except KeyboardInterrupt:
        log.info('WebSocket server stopped by user')
    except Exception as e:
        log.critical(f'WebSocket server failed: {e}')
        log.debug(traceback.format_exc())
        raise


def start_webapp_mode():
    """Start the React webapp with WebSocket backend (default mode)."""
    if was_port_explicit():
        validate_port_available(args.port, '--port')
    else:
        args.port = get_valid_port(args.port)

    if was_ws_port_explicit():
        validate_port_available(args.ws_port, '--ws-port')
    else:
        args.ws_port = get_valid_port(args.ws_port)

    log.info('Starting React webapp mode')
    log.info(f'Reserving ports: {args.port} - UI | {args.ws_port} - WS')

    try:
        start_webapp_server(
            http_port=args.port,
            ws_port=args.ws_port,
            open_browser=True,
            persistent=args.persistent
        )
    except KeyboardInterrupt:
        log.info('Webapp stopped by user')
    except Exception as e:
        log.critical(f'Webapp failed: {e}')
        log.debug(traceback.format_exc())
        raise


def is_port_available(port: int) -> bool:
    """Check if a port is available for binding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) != 0


def validate_port_available(port: int, flag_name: str) -> None:
    """
    Validate that an explicitly specified port is available.
    Raises an error if the port is already in use.
    """
    if not is_port_available(port):
        raise OSError(
            f"Port {port} is already in use. "
            f"Either free the port or remove the {flag_name} flag to auto-select an available port."
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
    while port <= max_port:
        if is_port_available(port):
            return port
        port += 1
    raise RuntimeError(
        f"No available port found between {start_port} and {max_port}"
    )


if __name__ == "__main__":
    main()
