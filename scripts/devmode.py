#!/usr/bin/env python3
"""
LANscape Development Mode

Runs both the Python WebSocket backend and React frontend with hot reloading.
- Python: WebSocket server with optional auto-reload on file changes
- React: Vite dev server with HMR (Hot Module Replacement)

Usage:
    python scripts/devmode.py [options]

Options:
    --ui-path PATH    Path to lanscape-ui directory (default: ../lanscape-ui)
    --ws-port PORT    WebSocket server port (default: 8766)
    --ui-port PORT    Vite dev server port (default: 3000)
    --no-reload       Disable Python auto-reload on file changes
    --no-browser      Don't open browser automatically
"""

import argparse
import os
import socket
import subprocess
import sys
import signal
import time
import threading
from pathlib import Path

from pwa_launcher import open_pwa, ChromiumNotFoundError


def find_ui_path(specified_path: str | None) -> Path:
    """Find the lanscape-ui directory."""
    if specified_path:
        path = Path(specified_path)
        if path.exists():
            return path.resolve()
        raise FileNotFoundError(f"UI path not found: {specified_path}")

    # Try common relative paths
    script_dir = Path(__file__).parent
    candidates = [
        script_dir.parent.parent / 'lanscape-ui',  # Sibling directory
        script_dir.parent / 'lanscape-ui',          # Child directory
        Path.home() / 'projects' / 'lanscape-ui',   # Home projects
    ]

    for candidate in candidates:
        if candidate.exists() and (candidate / 'package.json').exists():
            return candidate.resolve()

    raise FileNotFoundError(
        "Could not find lanscape-ui directory. "
        "Use --ui-path to specify the location."
    )


def check_npm_installed():
    """Check if npm is available."""
    try:
        subprocess.run(
            ['npm', '--version'],
            capture_output=True,
            check=True,
            shell=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError(
            "npm is not installed or not in PATH. "
            "Please install Node.js to run the React dev server."
        ) from exc


def wait_for_port(port: int, timeout: float = 30.0) -> bool:
    """Wait for a port to become available (server listening)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                if result == 0:
                    return True
        except OSError:
            pass
        time.sleep(0.25)
    return False


def is_port_available(port: int) -> bool:
    """Check if a port is available for binding."""
    # First check if something is already listening (connect test)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                # Something is already listening
                return False
    except OSError:
        pass

    # Then check if we can bind to 0.0.0.0 (what the server uses)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            return True
    except OSError:
        return False


def find_available_port(start_port: int, max_attempts: int = 20) -> int:
    """Find an available port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    end_port = start_port + max_attempts
    raise RuntimeError(f"Could not find available port in range {start_port}-{end_port}")


def find_listening_port(start_port: int, max_attempts: int = 10, timeout: float = 60) -> int | None:
    """Find which port Vite is actually listening on (it may auto-increment)."""
    start_time = time.time()
    ports_to_check = list(range(start_port, start_port + max_attempts))

    while time.time() - start_time < timeout:
        for port in ports_to_check:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.1)
                    result = sock.connect_ex(('localhost', port))
                    if result == 0:
                        return port
            except OSError:
                pass
        time.sleep(0.25)
    return None


def open_browser_when_ready(ui_port: int, ws_port: int):
    """Wait for Vite to be ready, then open PWA browser."""
    print(f"⏳ Waiting for Vite dev server (starting at port {ui_port})...")
    actual_port = find_listening_port(ui_port, max_attempts=10, timeout=60)
    if actual_port:
        # Use ws-server query param to tell the UI which WebSocket port to use
        url = f"http://localhost:{actual_port}?ws-server=localhost:{ws_port}"
        if actual_port != ui_port:
            print(f"   (Vite is using port {actual_port})")
        print(f"🌐 Opening PWA browser: {url}")
        try:
            open_pwa(url)
        except ChromiumNotFoundError:
            print("⚠️  Chromium not found, opening in default browser...")
            import webbrowser  # pylint: disable=import-outside-toplevel
            webbrowser.open(url)
    else:
        print("⚠️  Timeout waiting for Vite dev server")


def start_python_backend(ws_port: int, auto_reload: bool) -> subprocess.Popen:
    """Start the Python WebSocket server."""
    cmd = [sys.executable, '-m', 'lanscape', '--ws-server', '--ws-port', str(ws_port)]

    if auto_reload:
        # Use watchdog for auto-reload
        try:
            import watchdog  # noqa: F401 pylint: disable=import-outside-toplevel,unused-import
            # Wrap with watchmedo
            cmd = [
                sys.executable, '-m', 'watchdog.watchmedo',
                'auto-restart',
                '--directory', './lanscape',
                '--pattern', '*.py',
                '--recursive',
                '--'
            ] + cmd
            print("🔄 Python auto-reload enabled (watching lanscape/*.py)")
        except ImportError:
            print("⚠️  watchdog not installed, auto-reload disabled")
            print("   Install with: pip install watchdog")

    print(f"🐍 Starting Python WebSocket server on port {ws_port}...")
    # pylint: disable=consider-using-with
    return subprocess.Popen(cmd, shell=False)


def start_react_frontend(ui_path: Path, ws_port: int) -> subprocess.Popen:
    """Start the Vite dev server (never opens browser - we handle that)."""
    env = os.environ.copy()
    env['VITE_NO_OPEN'] = 'true'  # Disable Vite's browser opening

    cmd = ['npm', 'run', 'dev']

    print("⚛️  Starting React dev server...")
    print(f"   WebSocket URL: ws://localhost:{ws_port}")
    # pylint: disable=consider-using-with
    return subprocess.Popen(
        cmd,
        cwd=ui_path,
        env=env,
        shell=True
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Run LANscape in development mode with hot reloading'
    )
    parser.add_argument(
        '--ui-path',
        type=str,
        help='Path to lanscape-ui directory'
    )
    parser.add_argument(
        '--ws-port',
        type=int,
        default=8766,
        help='WebSocket server port (default: 8766)'
    )
    parser.add_argument(
        '--ui-port',
        type=int,
        default=3000,
        help='Vite dev server port (default: 3000)'
    )
    parser.add_argument(
        '--no-reload',
        action='store_true',
        help='Disable Python auto-reload'
    )
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help="Don't open browser automatically"
    )
    return parser.parse_args()


def run_dev_servers(args: argparse.Namespace, ui_path: Path):
    """Start and monitor dev servers."""
    processes: list[subprocess.Popen] = []

    def cleanup(signum=None, frame=None):  # pylint: disable=unused-argument
        """Clean up processes on exit."""
        print("\n🛑 Shutting down...")
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:  # pylint: disable=broad-exception-caught
                proc.kill()
        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Find available port for WebSocket server
    ws_port = find_available_port(args.ws_port)
    if ws_port != args.ws_port:
        print(f"📡 Port {args.ws_port} in use, using port {ws_port}")

    # Start Python backend
    python_proc = start_python_backend(ws_port, not args.no_reload)
    processes.append(python_proc)

    # Give Python a moment to start
    time.sleep(1)

    # Start React frontend
    react_proc = start_react_frontend(ui_path, ws_port)
    processes.append(react_proc)

    # Open browser in background thread (waits for Vite to be ready)
    if not args.no_browser:
        browser_thread = threading.Thread(
            target=open_browser_when_ready,
            args=(args.ui_port, ws_port),
            daemon=True
        )
        browser_thread.start()

    print("-" * 60)
    print("✅ Development servers running!")
    print(f"   React:     http://localhost:{args.ui_port}")
    print(f"   WebSocket: ws://localhost:{ws_port}")
    print("-" * 60)
    print("Press Ctrl+C to stop all servers")
    print("")

    # Wait for processes
    while True:
        for proc in processes:
            if proc.poll() is not None:
                print(f"⚠️  Process exited with code {proc.returncode}")
                cleanup()
        time.sleep(1)


def main():
    """Main entry point."""
    args = parse_arguments()

    print("=" * 60)
    print("🚀 LANscape Development Mode")
    print("=" * 60)

    # Find UI path
    try:
        ui_path = find_ui_path(args.ui_path)
        print(f"📁 UI Path: {ui_path}")
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    # Check npm
    try:
        check_npm_installed()
    except RuntimeError as e:
        print(f"❌ {e}")
        sys.exit(1)

    print("-" * 60)

    try:
        run_dev_servers(args, ui_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
