"""Main entry point for the LANscape application when running as a module."""
import logging
import traceback

from lanscape.core.logger import configure_logging
from lanscape.ui.port_availability import (
    get_valid_port,
    is_port_available,
    validate_port_available,
)
from lanscape.core.runtime_args import parse_args, was_port_explicit, was_ws_port_explicit
from lanscape.core.version_manager import get_installed_version
from lanscape.ui.ws.server import run_server
from lanscape.ui.react_proxy import start_webapp_server
from lanscape.core.service_scan import resources as svc_resources

# Re-exports for backward compatibility with any external callers that
# imported these from lanscape.ui.main.
__all__ = ['main', 'get_valid_port', 'is_port_available', 'validate_port_available']

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

    # Source-checkout dev orchestration. `lanscape.local` is excluded from
    # sdist/wheel builds, so installed users hit ImportError and fall through.
    # In a source checkout with `lanscape/local/.env` configured, hot-reload
    # dev mode replaces the default bundled-UI flow. `--ws-server` is the
    # backend-only escape hatch (and the form the dev runner re-invokes).
    if not args.ws_server:
        try:
            # pylint: disable=import-outside-toplevel
            from lanscape.local import dev_runner, is_configured
        except ImportError:
            pass
        else:
            if is_configured():
                dev_runner.run(args)
                return
            log.info(
                'Source checkout detected. Create lanscape/local/.env to '
                'enable hot-reload dev mode (see CONTRIBUTING.md).')

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


if __name__ == "__main__":
    main()
