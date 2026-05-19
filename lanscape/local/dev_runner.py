"""
LANscape local dev orchestrator.

Triggered by `python -m lanscape` in a source checkout that has configured
`lanscape/local/.env`. Replaces the bundled-UI flow with three things in
concert:
  - Python WebSocket backend (subprocess; optionally wrapped with watchdog
    for auto-restart on .py changes)
  - UI dev server (subprocess; whatever `LANSCAPE_UI_DEV_CMD` says)
  - PWA browser pointed at the UI with the WS port wired in via query param

`--ws-server` bypasses this module upstream — both as a contributor escape
hatch for backend-only runs and as the form the orchestrator uses when it
re-invokes itself for the WS subprocess.
"""
from __future__ import annotations

import logging
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from lanscape.ui.port_availability import get_valid_port
from lanscape.core.runtime_args import RuntimeArgs, was_port_explicit
from lanscape.local import ENV_FILE, REPO_ROOT

log = logging.getLogger('core.devmode')

# Vite default; differs from the bundled-UI default (5001).
VITE_DEFAULT_PORT = 3000


class DevSetupError(RuntimeError):
    """Misconfigured local dev environment — surfaced with actionable hints."""


@dataclass
class DevConfig:
    """Resolved local dev environment settings loaded from ``lanscape/local/.env``."""
    ui_path: Path
    ui_dev_cmd: str
    open_browser: bool
    auto_reload: bool

    @classmethod
    def from_env(cls, env: dict[str, str]) -> 'DevConfig':
        """Build a :class:`DevConfig` from environment-variable values."""
        ui_path_raw = env.get('LANSCAPE_UI_PATH')
        if not ui_path_raw:
            raise DevSetupError(
                f"LANSCAPE_UI_PATH is not set in {ENV_FILE}")

        ui_path = Path(ui_path_raw)
        if not ui_path.is_absolute():
            ui_path = (REPO_ROOT / ui_path).resolve()

        if not ui_path.is_dir():
            raise DevSetupError(
                f"LANSCAPE_UI_PATH does not exist: {ui_path}\n"
                f"  (resolved from `{ui_path_raw}` in {ENV_FILE})")

        return cls(
            ui_path=ui_path,
            ui_dev_cmd=env.get(
                'LANSCAPE_UI_DEV_CMD',
                'npm run dev -- --port {ui_port} --strictPort'),
            open_browser=_truthy(env.get('LANSCAPE_OPEN_BROWSER', 'true')),
            auto_reload=_truthy(env.get('LANSCAPE_AUTO_RELOAD', 'true')),
        )


def run(args: RuntimeArgs) -> None:
    """Take over the process: spawn backend + UI dev server, exit when done.

    Caller (lanscape.ui.main) is responsible for gating on `is_configured()`
    so we always have a real .env to read here.
    """
    try:
        config = DevConfig.from_env(_load_env(ENV_FILE))
    except DevSetupError as e:
        print(f"\n[lanscape dev] {e}\n", file=sys.stderr)
        sys.exit(1)

    # If user didn't explicitly set --ui-port, swap to the Vite default.
    # (RuntimeArgs default is 5001, which is the bundled-UI port.)
    if not was_port_explicit():
        args.ui_port = VITE_DEFAULT_PORT

    args.ws_port = get_valid_port(args.ws_port)
    args.ui_port = get_valid_port(args.ui_port)

    log.info('-' * 60)
    log.info('LANscape dev mode')
    log.info('  UI repo : %s', config.ui_path)
    log.info('  UI port : %s  (Vite)', args.ui_port)
    log.info('  WS port : %s  (backend)', args.ws_port)
    log.info('  Reload  : %s', 'on' if config.auto_reload else 'off')
    log.info('-' * 60)

    procs: list[subprocess.Popen] = []
    stop = threading.Event()
    # Captures the rc of the first child to exit, so callers can tell a
    # backend/UI crash apart from a clean Ctrl+C shutdown. `None` = no child
    # failure observed (Ctrl+C / SIGTERM path); int = failing child's rc.
    failure_rc: list[int | None] = [None]

    def _shutdown(signum=None, frame=None):  # pylint: disable=unused-argument
        if stop.is_set():
            return
        stop.set()
        log.info('Shutting down dev servers...')
        for p in procs:
            try:
                p.terminate()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:  # pylint: disable=broad-exception-caught
                p.kill()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        procs.append(_spawn_backend(args, config))
        time.sleep(0.5)
        procs.append(_spawn_ui(args, config))

        if config.open_browser:
            threading.Thread(
                target=_open_browser_when_ready,
                args=(args.ui_port, args.ws_port),
                daemon=True,
            ).start()

        _supervise(procs, stop, failure_rc, _shutdown)
    finally:
        _shutdown()

    if failure_rc[0] is not None:
        sys.exit(failure_rc[0])


def _supervise(
    procs: list[subprocess.Popen],
    stop: threading.Event,
    failure_rc: list[int | None],
    shutdown,
) -> None:
    """Poll children; on first exit, record a non-zero rc and tear down."""
    while not stop.is_set():
        for p in procs:
            if p.poll() is not None:
                rc = p.returncode if p.returncode is not None else 1
                log.warning('Process exited (rc=%s); shutting down', rc)
                if failure_rc[0] is None and rc != 0:
                    failure_rc[0] = rc
                shutdown()
                return
        time.sleep(0.5)


def _spawn_backend(args: RuntimeArgs, config: DevConfig) -> subprocess.Popen:
    """Run `python -m lanscape --ws-server ...`, optionally under watchdog."""
    cmd = [sys.executable, '-m', 'lanscape', '--ws-server'] + _forward_args(args)

    if config.auto_reload:
        try:
            import watchdog  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import
            cmd = [
                sys.executable, '-m', 'watchdog.watchmedo', 'auto-restart',
                '--directory', str(REPO_ROOT / 'lanscape'),
                '--pattern', '*.py',
                '--recursive',
                '--',
            ] + cmd
            log.info('Auto-reload enabled (watching lanscape/**/*.py)')
        except ImportError:
            log.warning(
                'watchdog not installed; auto-reload disabled. '
                'Install dev extras: pip install -e ".[dev]"')

    log.info('Backend: %s', ' '.join(cmd[-6:]))
    return subprocess.Popen(cmd, shell=False)  # pylint: disable=consider-using-with


def _spawn_ui(args: RuntimeArgs, config: DevConfig) -> subprocess.Popen:
    """Run the configured UI dev command inside the lanscape-ui repo."""
    cmd_str = config.ui_dev_cmd.format(ui_port=args.ui_port, ws_port=args.ws_port)
    # On Windows, `npm` is a .cmd shim — easiest to spawn via shell.
    use_shell = os.name == 'nt'
    cmd: list[str] | str = cmd_str if use_shell else shlex.split(cmd_str)

    env = os.environ.copy()
    env['VITE_NO_OPEN'] = 'true'  # we open the PWA ourselves

    log.info('UI: %s', cmd_str)
    log.info('  cwd: %s', config.ui_path)
    return subprocess.Popen(  # pylint: disable=consider-using-with
        cmd, cwd=config.ui_path, env=env, shell=use_shell)


def _open_browser_when_ready(ui_port: int, ws_port: int, timeout: float = 60.0) -> None:
    """Wait for the UI dev server to *respond to HTTP*, then open a PWA window.

    A bare TCP listening probe is unreliable here: Vite binds the socket well
    before it has finished optimizing deps and is actually able to serve a
    page. We probe HTTP so we only open the browser when the dev server is
    genuinely ready to render.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _is_ui_ready(ui_port):
            url = f'http://localhost:{ui_port}?ws-server=localhost:{ws_port}'
            log.info('Opening PWA: %s', url)
            try:
                # pylint: disable=import-outside-toplevel
                from pwa_launcher import ChromiumNotFoundError, open_pwa
                try:
                    open_pwa(url)
                except ChromiumNotFoundError:
                    import webbrowser
                    webbrowser.open(url)
            except ImportError:
                import webbrowser
                webbrowser.open(url)
            return
        time.sleep(0.25)
    log.warning('UI dev server did not respond to HTTP within %.0fs', timeout)


def _is_ui_ready(port: int, timeout: float = 0.5) -> bool:
    """True only when the dev server actually responds to an HTTP request.

    Issues a minimal HTTP/1.0 GET over a raw socket so we don't pull urllib
    into the hot loop and so we treat any HTTP/* status line as 'ready'
    (Vite may 200, 304, 302, etc. depending on dep-optimization state).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(('127.0.0.1', port))
            s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            data = s.recv(16)
        return data.startswith(b'HTTP/')
    except (OSError, socket.timeout):
        return False


def _forward_args(args: RuntimeArgs) -> list[str]:
    """Recreate the user's relevant flags for the WS-server subprocess.
    --ws-port is always concrete here (we already resolved it above)."""
    out: list[str] = ['--ws-port', str(args.ws_port)]
    if args.debug:
        out += ['--debug']
    if args.persistent:
        out += ['--persistent']
    if not args.mdns_enabled:
        out += ['--mdns-off']
    if not args.printer_safety:
        out += ['--printer-mayhem']
    if args.logfile:
        out += ['--logfile', args.logfile]
    if args.loglevel and args.loglevel != 'INFO':
        out += ['--loglevel', args.loglevel]
    return out


def _load_env(path: Path) -> dict[str, str]:
    """Tiny .env parser: KEY=VALUE per line, # comments, optional quoting."""
    out: dict[str, str] = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or \
                (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def _truthy(v: str | None) -> bool:
    if not v:
        return False
    return v.strip().lower() in ('1', 'true', 'yes', 'on')
