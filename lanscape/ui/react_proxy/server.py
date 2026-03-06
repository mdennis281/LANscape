"""
Webapp Server - Serves the React webapp with integrated WebSocket backend.

This module provides a simple HTTP server for the React static files
and starts the WebSocket server for API communication.
"""

import asyncio
import logging
import os
import threading
import time
import webbrowser
import socket
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from functools import partial
from typing import Optional, Callable
from subprocess import Popen

from pwa_launcher import open_pwa, ChromiumNotFoundError

from lanscape.ui.ws.server import WebSocketServer
from lanscape.ui.react_proxy.discovery import (
    DiscoveryService,
    DiscoverResponse,
    build_default_route,
    get_local_address_strings,
)

REACT_BUILD_DIR = Path(__file__).resolve().parent.parent / 'react_build'

log = logging.getLogger('WebappServer')


class SPAHandler(SimpleHTTPRequestHandler):
    """
    HTTP handler for Single Page Application.

    Serves static files and falls back to index.html for client-side routing.
    Also exposes ``/api/discover`` which returns mDNS-discovered backends.
    """

    # Set by the controller so every request handler can access it.
    discovery: Optional['DiscoveryService'] = None
    mdns_enabled: bool = True
    default_route: str = 'http://localhost:5001'

    def __init__(self, *args, directory: str = None, **kwargs):
        self.spa_directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        """Handle GET requests with API routes and SPA fallback."""
        # --- API routes --------------------------------------------------
        if self.path == '/api/discover':
            return self._handle_discover()

        # --- Static / SPA -----------------------------------------------
        # Get the requested file path
        path = self.translate_path(self.path)

        # If the path doesn't exist and isn't a file request, serve index.html
        if not os.path.exists(path) and not self.path.startswith('/assets'):
            self.path = '/index.html'  # pylint: disable=attribute-defined-outside-init

        # Check if index.html exists and has content
        index_path = os.path.join(self.spa_directory, 'index.html')
        if self.path in ('/index.html', '/'):
            if not os.path.exists(index_path) or os.path.getsize(index_path) == 0:
                return self._serve_missing_build_page()

        return super().do_GET()

    def _serve_missing_build_page(self) -> None:
        """Serve a fallback page when the React build is missing."""
        html = b'''LANscape UI is missing. Something went wrong with the install.'''
        self.send_response(503)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    # -----------------------------------------------------------------
    # API endpoint handlers
    # -----------------------------------------------------------------

    def _handle_discover(self) -> None:
        """Return discovery info including mDNS instances and default route."""
        instances = []
        if self.discovery is not None:
            instances = self.discovery.get_instances()

        response = DiscoverResponse(
            mdns_enabled=self.mdns_enabled,
            default_route=self.default_route,
            instances=instances,
        )

        payload = response.model_dump_json().encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):  # pylint: disable=arguments-renamed,arguments-differ
        """Override to use our logger instead of stderr."""
        log.debug(f'{self.address_string()} - {fmt % args}')

    def end_headers(self):
        """Add CORS and cache-control headers."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

        # Vite content-hashed assets are safe to cache long-term.
        # Everything else (index.html, manifest, etc.) must be revalidated
        # so the browser always picks up new builds.
        if hasattr(self, 'path') and self.path.startswith('/assets/'):
            self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
        else:
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')

        super().end_headers()


def start_static_server(directory: Path, port: int, host: str = '127.0.0.1') -> ThreadingHTTPServer:
    """
    Start the static file HTTP server.

    Each incoming connection is handled in its own thread so that concurrent
    requests (assets, /api/discover, service-worker fetches) never block each
    other.

    Args:
        directory: Directory containing static files to serve
        port: Port to bind to
        host: Host to bind to (default: 127.0.0.1)

    Returns:
        The ThreadingHTTPServer instance
    """
    handler = partial(SPAHandler, directory=str(directory))
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True  # Don't block shutdown on in-flight requests
    log.debug(f'Static server binding on http://{host}:{port}')
    return server


class WebappServerController:
    """
    Controller for the webapp server with auto-shutdown support.

    Monitors WebSocket connections and shuts down when all clients disconnect
    (unless persistent mode is enabled).
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        http_port: int = 5001,
        ws_port: int = 8766,
        host: str = '127.0.0.1',
        persistent: bool = False,
        mdns_enabled: bool = True,
    ):
        """
        Initialize the webapp server controller.

        Args:
            http_port: Port for HTTP static file server
            ws_port: Port for WebSocket server
            host: Host to bind to
            persistent: If True, don't auto-shutdown when clients disconnect
            mdns_enabled: If False, skip mDNS advertisement and browsing
        """
        self.http_port = http_port
        self.ws_port = ws_port
        self.host = host
        self.persistent = persistent
        self.mdns_enabled = mdns_enabled

        self._http_server: Optional[ThreadingHTTPServer] = None
        self._ws_server: Optional[WebSocketServer] = None
        self._discovery: Optional[DiscoveryService] = None
        self._shutdown_event = threading.Event()
        self._had_connection = False
        self._ws_loop: Optional[asyncio.AbstractEventLoop] = None
        self._client_count: int = 0

    def _run_ws_server(self, on_client_change: Callable[[int], None]) -> None:
        """
        Run the WebSocket server in its own event loop.

        Args:
            on_client_change: Callback when client count changes
        """
        self._ws_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._ws_loop)

        self._ws_server = WebSocketServer(
            host='0.0.0.0',
            port=self.ws_port,
            on_client_change=on_client_change
        )

        try:
            self._ws_loop.run_until_complete(self._ws_server.serve_forever())
        except asyncio.CancelledError:
            pass
        finally:
            self._ws_loop.close()

    def _on_client_change(self, client_count: int) -> None:
        """
        Handle WebSocket client count changes.

        Args:
            client_count: Current number of connected clients
        """
        log.debug(f'WebSocket clients: {client_count}')

        self._client_count = client_count

        if client_count > 0:
            self._had_connection = True
        elif self._had_connection and not self.persistent:
            threading.Thread(target=self._delayed_shutdown_check, daemon=True).start()

    def start(
        self,
        webapp_dir: Path,
        open_browser: bool = True
    ) -> None:
        """
        Start the webapp server.

        Args:
            webapp_dir: Directory containing the webapp static files
            open_browser: Whether to open a browser window
        """
        # Start WebSocket server in a thread
        ws_thread = threading.Thread(
            target=self._run_ws_server,
            args=(self._on_client_change,),
            daemon=True
        )
        ws_thread.start()
        log.debug(f'WebSocket server started on ws://{self.host}:{self.ws_port}')

        # Start HTTP server
        self._http_server = start_static_server(webapp_dir, self.http_port, '0.0.0.0')

        # Tell the handler the default route and mDNS status so
        # /api/discover can include them in every response.
        SPAHandler.default_route = build_default_route(self.http_port)
        SPAHandler.mdns_enabled = self.mdns_enabled

        # Start mDNS discovery in a background thread (unless disabled).
        # Zeroconf() + register_service() can block on Windows (multicast socket
        # setup, network announcements) and would delay the HTTP loop if run
        # inline here.  The handler checks `discovery is not None` before use,
        # so returning [] from /api/discover during the brief init window is safe.
        if self.mdns_enabled:
            def _start_discovery() -> None:
                try:
                    discovery = DiscoveryService(
                        ws_port=self.ws_port,
                        http_port=self.http_port,
                    )
                    # Assign the discovery instance before starting it so that
                    # shutdown logic that checks `self._discovery` can always
                    # see and stop it, even if shutdown races with startup.
                    self._discovery = discovery
                    SPAHandler.discovery = discovery
                    discovery.start()
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    log.warning('mDNS broadcasting failed to start')
                    log.debug('mDNS startup error details:', exc_info=exc)
                    self._discovery = None
                    SPAHandler.discovery = None

            threading.Thread(target=_start_discovery, daemon=True, name='mDNS-init').start()
        else:
            log.info('mDNS service disabled')

        # Build the localhost URL for the local browser (no ws-server param;
        # the frontend will discover the backend via mDNS or same-origin default).
        local_url = f'http://localhost:{self.http_port}'

        # Open browser
        if open_browser:
            threading.Thread(
                target=_open_browser,
                args=(local_url, 1.5, self.http_port),
                daemon=True
            ).start()

        if self.persistent:
            log.info('Running in persistent mode. Press Ctrl+C to stop.')
        else:
            log.info('Will shutdown when all clients disconnect. Press Ctrl+C to stop.')

        # Run HTTP server with shutdown check
        self._http_server.timeout = 1.0  # Check shutdown every second
        try:
            while not self._shutdown_event.is_set():
                self._http_server.handle_request()
        except KeyboardInterrupt:
            log.info('Interrupted by user')
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        """Shutdown all servers and validate port closure."""
        log.info('Shutting down...')
        errors = []

        # Stop mDNS discovery
        if self._discovery:
            try:
                self._discovery.stop()
                SPAHandler.discovery = None
            except Exception as e:  # pylint: disable=broad-exception-caught
                errors.append(f'mDNS discovery: {e}')

        # Stop HTTP server
        if self._http_server:
            try:
                log.info('Stopping HTTP server (port %d)...', self.http_port)
                self._http_server.server_close()
                log.debug('HTTP server stopped')
            except Exception as e:  # pylint: disable=broad-exception-caught
                errors.append(f'HTTP server (port {self.http_port}): {e}')

        # Stop WebSocket server
        if self._ws_server and self._ws_loop:
            try:
                log.info('Stopping WebSocket server (port %d)...', self.ws_port)
                asyncio.run_coroutine_threadsafe(
                    self._ws_server.stop(),
                    self._ws_loop
                )
                log.debug('WebSocket server stopped')
            except Exception as e:  # pylint: disable=broad-exception-caught
                errors.append(f'WebSocket server (port {self.ws_port}): {e}')

        # Validate ports are released
        log.debug('Waiting for OS to release ports...')
        time.sleep(0.3)  # Brief wait for OS to release ports

        for port_num, label in [
            (self.http_port, 'HTTP'),
            (self.ws_port, 'WebSocket')
        ]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('localhost', port_num)) == 0:
                    errors.append(f'{label} port {port_num} did not close cleanly')

        if errors:
            for err in errors:
                log.warning(err)
        else:
            log.info('LANscape closed gracefully')

    def _delayed_shutdown_check(self) -> None:
        """Check if clients reconnected during the shutdown delay."""
        time.sleep(2)  # Brief delay to allow for quick reconnects
        if self._client_count == 0:  # Check again after delay
            # Had connections before, now zero - time to shutdown
            log.info('All clients disconnected, shutting down...')
            self._shutdown_event.set()
        else:
            log.debug('New client connected during shutdown delay, aborting shutdown')


# pylint: disable=too-many-arguments,too-many-positional-arguments
def start_webapp_server(
    http_port: int = 5001,
    ws_port: int = 8766,
    host: str = '127.0.0.1',
    open_browser: bool = True,
    persistent: bool = False,
    mdns_enabled: bool = True,
) -> None:
    """
    Start the webapp server with both HTTP (static files) and WebSocket (API).

    This is the main entry point for running the React webapp with Python backend.
    Serves the bundled React build from the package's react_build directory.

    Args:
        http_port: Port for the HTTP static file server (default: 5001)
        ws_port: Port for the WebSocket server (default: 8766)
        host: Host to bind to (default: 127.0.0.1)
        open_browser: Whether to open a browser window (default: True)
        persistent: Don't auto-shutdown when clients disconnect (default: False)
        mdns_enabled: Enable mDNS service discovery (default: True)
    """
    webapp_dir = REACT_BUILD_DIR

    if not webapp_dir.exists():
        try:
            webapp_dir.mkdir(parents=True, exist_ok=True)
            log.warning('React UI build directory not found - created empty directory')
        except OSError as exc:
            # Do not crash startup if we cannot create the UI directory
            # (e.g. read-only site-packages). The HTTP server will still start.
            log.warning(
                'React UI build directory %s could not be created (%s). '
                'Continuing without bundled UI assets.',
                webapp_dir,
                exc,
            )

    is_empty = False
    if not webapp_dir.exists():
        # Directory still doesn't exist (e.g. mkdir failed), treat as empty
        is_empty = True
    else:
        try:
            is_empty = not any(webapp_dir.iterdir())
        except OSError as exc:
            # Directory exists but is not accessible; treat as missing assets
            log.warning(
                'React UI build directory %s is not accessible (%s). '
                'The webapp will display an error page.',
                webapp_dir,
                exc,
            )
            is_empty = True

    if is_empty:
        log.warning(
            'React UI build is missing. The webapp will display an error page. '
            'Reinstall with: pip install --force-reinstall lanscape'
        )

    log.debug(f'UI: Bundled build at {webapp_dir}')

    # Create and start the controller
    controller = WebappServerController(
        http_port=http_port,
        ws_port=ws_port,
        host=host,
        persistent=persistent,
        mdns_enabled=mdns_enabled,
    )
    controller.start(webapp_dir, open_browser=open_browser)


def _format_listen_urls(http_port: int) -> str:
    """Build a multi-line string listing every reachable URL for this server."""
    urls: list[str] = [f'http://localhost:{http_port}']
    for addr in get_local_address_strings():
        urls.append(f'http://{addr}:{http_port}')
    try:
        hostname = socket.gethostname()
        if hostname:
            urls.append(f'http://{hostname.lower()}:{http_port}')
    except OSError:
        pass
    return '\n'.join(f'  - {u}' for u in urls)


def _open_browser(
    url: str,
    wait: float = 1.5,
    http_port: int = 5001,
) -> Optional[Popen]:
    """
    Open a browser window to the specified URL.

    Args:
        url: URL to open
        wait: Seconds to wait before opening (default: 1.5)
        http_port: The HTTP port (used to display accessible URLs on failure)

    Returns:
        Popen instance if PWA was opened, None otherwise
    """
    time.sleep(wait)
    # Suppress pwa_launcher logs — browser-not-found errors are expected
    # on headless systems and handled gracefully with our own warning.
    logging.getLogger('pwa_launcher').setLevel(logging.CRITICAL)
    try:
        log.debug(f'Opening browser: {url}')
        return open_pwa(url, auto_profile=False)
    except ChromiumNotFoundError:
        success = webbrowser.open(url)
        if success:
            log.warning('Chromium not found, using default browser')
        else:
            listen_urls = _format_listen_urls(http_port)
            log.warning(
                'Could not open browser. Webapp running at:\n%s',
                listen_urls,
            )
    except Exception as e:
        log.debug(f'Browser open failed: {e}')
        listen_urls = _format_listen_urls(http_port)
        log.info('Open your browser to:\n%s', listen_urls)
    return None
