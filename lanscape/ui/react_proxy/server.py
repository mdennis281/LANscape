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
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from functools import partial
from typing import Optional, Callable
from subprocess import Popen

from pwa_launcher import open_pwa, ChromiumNotFoundError

from lanscape.ui.ws.server import WebSocketServer

REACT_BUILD_DIR = Path(__file__).resolve().parent.parent / 'react_build'

log = logging.getLogger('WebappServer')


class SPAHandler(SimpleHTTPRequestHandler):
    """
    HTTP handler for Single Page Application.

    Serves static files and falls back to index.html for client-side routing.
    """

    def __init__(self, *args, directory: str = None, **kwargs):
        self.spa_directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        """Handle GET requests with SPA fallback."""
        # Get the requested file path
        path = self.translate_path(self.path)

        # If the path doesn't exist and isn't a file request, serve index.html
        if not os.path.exists(path) and not self.path.startswith('/assets'):
            self.path = '/index.html'  # pylint: disable=attribute-defined-outside-init

        return super().do_GET()

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
        if self.path.startswith('/assets/'):
            self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
        else:
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')

        super().end_headers()


def start_static_server(directory: Path, port: int, host: str = '127.0.0.1') -> HTTPServer:
    """
    Start the static file HTTP server.

    Args:
        directory: Directory containing static files to serve
        port: Port to bind to
        host: Host to bind to (default: 127.0.0.1)

    Returns:
        The HTTPServer instance
    """
    handler = partial(SPAHandler, directory=str(directory))
    server = HTTPServer((host, port), handler)
    log.debug(f'Static server binding on http://{host}:{port}')
    return server


class WebappServerController:
    """
    Controller for the webapp server with auto-shutdown support.

    Monitors WebSocket connections and shuts down when all clients disconnect
    (unless persistent mode is enabled).
    """

    def __init__(
        self,
        http_port: int = 5001,
        ws_port: int = 8766,
        host: str = '127.0.0.1',
        persistent: bool = False
    ):
        """
        Initialize the webapp server controller.

        Args:
            http_port: Port for HTTP static file server
            ws_port: Port for WebSocket server
            host: Host to bind to
            persistent: If True, don't auto-shutdown when clients disconnect
        """
        self.http_port = http_port
        self.ws_port = ws_port
        self.host = host
        self.persistent = persistent

        self._http_server: Optional[HTTPServer] = None
        self._ws_server: Optional[WebSocketServer] = None
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
            time.sleep(5)  # Brief delay to allow for quick reconnects
            if self._client_count == 0:  # Check again after delay
                # Had connections before, now zero - time to shutdown
                log.info('All clients disconnected, shutting down...')
                self._shutdown_event.set()
            else:
                log.debug('New client connected during shutdown delay, aborting shutdown')

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

        url = f'http://{self.host}:{self.http_port}?ws-server=localhost:{self.ws_port}'

        # Open browser
        if open_browser:
            threading.Thread(
                target=_open_browser,
                args=(url,),
                daemon=True
            ).start()

        log.debug(f'Webapp available at {url}')
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
        log.debug('Shutting down webapp server...')
        errors = []

        # Stop HTTP server
        if self._http_server:
            try:
                self._http_server.server_close()
            except Exception as e:  # pylint: disable=broad-exception-caught
                errors.append(f'HTTP server (port {self.http_port}): {e}')

        # Stop WebSocket server
        if self._ws_server and self._ws_loop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._ws_server.stop(),
                    self._ws_loop
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                errors.append(f'WebSocket server (port {self.ws_port}): {e}')

        # Validate ports are released
        import socket as _socket  # pylint: disable=import-outside-toplevel
        time.sleep(0.3)  # Brief wait for OS to release ports

        for port_num, label in [
            (self.http_port, 'HTTP'),
            (self.ws_port, 'WebSocket')
        ]:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                if s.connect_ex(('localhost', port_num)) == 0:
                    errors.append(f'{label} port {port_num} did not close cleanly')

        if errors:
            for err in errors:
                log.warning(err)
        else:
            log.info('LANscape closed gracefully')


# pylint: disable=too-many-arguments,too-many-positional-arguments
def start_webapp_server(
    http_port: int = 5001,
    ws_port: int = 8766,
    host: str = '127.0.0.1',
    open_browser: bool = True,
    persistent: bool = False
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
    """
    webapp_dir = REACT_BUILD_DIR

    if not webapp_dir.exists() or not any(webapp_dir.iterdir()):
        raise RuntimeError(
            f'Webapp build not found at: {webapp_dir}\n'
            'The React UI build is missing from this installation. '
            'Please reinstall the package or check your installation.'
        )

    log.debug(f'UI: Bundled build at {webapp_dir}')

    # Create and start the controller
    controller = WebappServerController(
        http_port=http_port,
        ws_port=ws_port,
        host=host,
        persistent=persistent
    )
    controller.start(webapp_dir, open_browser=open_browser)


def _open_browser(url: str, wait: float = 1.5) -> Optional[Popen]:
    """
    Open a browser window to the specified URL.

    Args:
        url: URL to open
        wait: Seconds to wait before opening (default: 1.5)

    Returns:
        Popen instance if PWA was opened, None otherwise
    """
    time.sleep(wait)
    # Suppress noisy pwa_launcher logs
    logging.getLogger('pwa_launcher').setLevel(logging.WARNING)
    try:
        log.debug(f'Opening browser: {url}')
        return open_pwa(url, auto_profile=False)
    except ChromiumNotFoundError:
        success = webbrowser.open(url)
        if success:
            log.warning('Chromium not found, using default browser')
        else:
            log.warning(f'Could not open browser. Webapp running at {url}')
    except Exception as e:
        log.debug(f'Browser open failed: {e}')
        log.info(f'Open your browser to: {url}')
    return None
