"""
Local development helpers for LANscape contributors.

This subpackage is excluded from sdist/wheel builds (see pyproject.toml and
MANIFEST.in). It exists only in the source checkout, and acts as the trigger
that turns `python -m lanscape --debug` into a hot-reloading dev environment.

Installed users never see this — `import lanscape.local` raises ImportError
on a packaged install, and the entry point falls through to normal --debug
behavior.

To enable, copy `.env.example` to `.env` and edit `LANSCAPE_UI_PATH`.
"""
from pathlib import Path

LOCAL_DIR = Path(__file__).resolve().parent
ENV_FILE = LOCAL_DIR / ".env"
ENV_EXAMPLE = LOCAL_DIR / ".env.example"
REPO_ROOT = LOCAL_DIR.parent.parent  # <repo>/lanscape/local/.. /.. = <repo>


def is_configured() -> bool:
    """True when a contributor has created `lanscape/local/.env` (opt-in dev mode)."""
    return ENV_FILE.is_file()
