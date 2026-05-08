# Contributing to LANScape

Thank you for helping improve LANScape! This guide keeps local development consistent & understandable

## Prerequisites
- Python 3.10+ installed
- Git
- PowerShell 7+ on Windows (or Bash/zsh on macOS/Linux)

## One-time setup
1. Clone the repo and `cd` into it.
2. Create a virtual environment:
   - Windows (PowerShell):
     ```powershell
     python -m venv .env
     .\.env\Scripts\Activate.ps1
     ```
   - macOS/Linux (bash/zsh):
     ```bash
     python -m venv .env
     source .env/bin/activate
     ```
3. Upgrade pip and install all dependencies (including dev tools) from `pyproject.toml`:
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -e ".[dev]"
   ```

## Everyday development
- **Execute locally** 
   ```bash
    python -m lanscape # ensure version number loads as 0.0.0
   ```
- **Local dev mode (hot-reloading frontend + backend)** — see "Local dev mode" below.
- **Run tests** (fast, parallel):
  ```bash
  python -m pytest tests/ -n auto --dist=loadscope -v
  ```
- **Lint** (pylint with repo defaults):
  ```bash
  python -m pylint --score=yes scripts/ lanscape/ tests/
  ```
- **Format** (autopep8, 100 col limit):
  ```bash
  python -m autopep8 --in-place --recursive . --max-line-length 100 -aa
  ```

## Local dev mode

In a source checkout, `python -m lanscape` automatically runs in
hot-reloading dev mode whenever `lanscape/local/.env` exists. There's no
flag to remember — the presence of `.env` is the opt-in. It orchestrates:

- the Python WebSocket backend, wrapped in `watchdog` for auto-restart on
  `.py` changes
- the React/Vite UI dev server in your sibling `lanscape-ui` repo
- a PWA browser window pointed at the dev server, with the WS port wired in
  via query param

The `lanscape/local/` subpackage that powers this is excluded from PyPI
builds, so installed users always get the bundled-UI flow.

### One-time setup

You also need a clone of the `lanscape-ui` repo. Then:

```bash
cp lanscape/local/.env.example lanscape/local/.env
# edit lanscape/local/.env and set LANSCAPE_UI_PATH to your lanscape-ui clone
```

`lanscape/local/.env` is gitignored — it's per-developer config.

### Run it

```bash
python -m lanscape
```

That's the full dev experience. All the standard `lanscape` flags pass
through, so for example:

| Command                                       | Behavior                                          |
| --------------------------------------------- | ------------------------------------------------- |
| `python -m lanscape`                          | Vite + backend + browser, hot reload              |
| `python -m lanscape --debug`                  | Same, plus DEBUG logs and debug WS handlers       |
| `python -m lanscape --ws-server`              | Backend only (no Vite, no browser) — escape hatch |
| `python -m lanscape --ui-port 3001`           | Run Vite on a non-default port                    |
| `python -m lanscape --ws-port 9000`           | Pin the WS port                                   |
| `python -m lanscape --persistent --mdns-off`  | Any other lanscape flags forward to the backend   |

In dev mode, `--ui-port` means the Vite port (default `3000`). In production
it means the bundled-UI port (default `5001`). The default flips automatically
when dev mode is active.

To temporarily run the bundled-UI flow from a source checkout (e.g. to test
what installed users see), rename `lanscape/local/.env` out of the way.

### What goes in `.env`

| Variable                  | Purpose                                                            |
| ------------------------- | ------------------------------------------------------------------ |
| `LANSCAPE_UI_PATH`        | Path to the `lanscape-ui` repo (relative paths resolve from repo root). |
| `LANSCAPE_UI_DEV_CMD`     | Command to start the UI dev server. `{ui_port}` and `{ws_port}` substitute. |
| `LANSCAPE_OPEN_BROWSER`   | `true`/`false` — auto-open a PWA window when Vite is ready.        |
| `LANSCAPE_AUTO_RELOAD`    | `true`/`false` — wrap the backend with `watchdog` for auto-restart. |

## Adding or changing dependencies
- Add them to the appropriate section of `pyproject.toml` (`dependencies` for runtime, `project.optional-dependencies.dev` for tooling/tests).
- Never add a `requirements.txt`; CI installs from `pyproject.toml` only.

## Contribution flow
1. Create a feature branch from `main`.
2. Make changes with type hints and tests where relevant.
3. Run lint and tests locally.
4. Open a PR; CI will run pytest and pylint across supported Python versions.
5. Ensure PR includes version number, ie. "<major>.<minor>.<patch> - <PR title>"

Thanks for contributing! 💡
