# Copilot agent onboarding: py-net-scan

Purpose
- Python-based network scanning tool/CLI and library for scanning hosts/ports/subnets and reporting results (console and/or structured output).
- Expect a small-to-medium Python repo with a package named "lanscape" or similar, plus a CLI entry point.

Trust these instructions
- Follow the sequences below verbatim. Only search the repo if something here is missing or fails.
- Prefer commands exactly as written; they are resilient across common Python project setups.

Tech and repo facts
- Language/runtime: Python 3.10+ recommended (works across 3.8–3.13 in typical CI matrices).
- Packaging: pyproject.toml (PEP 517/518) or requirements.txt. Some repos use Poetry or Pipenv; steps below cover each.
- Lint/format/type-check: commonly ruff/flake8, black, isort, mypy (run them if config is present in pyproject.toml, setup.cfg, or standalone files).
- Tests: pytest under tests/.
- CI: GitHub Actions under .github/workflows. Typical jobs: lint + tests across multiple Python versions.

Do this first (per session)
1) Create and activate a virtual environment.
   - Windows (PowerShell):
     - py -3.11 -m venv .venv
     - .\.venv\Scripts\Activate.ps1
   - POSIX:
     - python3 -m venv .venv
     - source .venv/bin/activate
2) Upgrade base tooling:
   - python -m pip install -U pip setuptools wheel

Bootstrap (install dependencies)
- If pyproject.toml exists and repo uses setuptools/hatch/flit:
  - Prefer editable install with dev extras when defined:
    - python -m pip install -e ".[dev]" || python -m pip install -e .
- If requirements files exist:
  - python -m pip install -r requirements.txt
  - If present: python -m pip install -r requirements-dev.txt
- If Poetry is declared (pyproject has tool.poetry):
  - python -m pip install pipx || true
  - pipx ensurepath
  - pipx install poetry || python -m pip install poetry
  - poetry install --with dev || poetry install
- If Pipenv is declared (Pipfile present):
  - python -m pip install pipenv
  - pipenv install --dev || pipenv install
- If pre-commit config is present (.pre-commit-config.yaml):
  - python -m pip install pre-commit
  - pre-commit install

Build (package artifact, if needed)
- Only needed for release/packaging; not required to run or test.
- python -m pip install build
- python -m build
- Artifacts appear in dist/.

Run (CLI and module)
- Try in this order (use --help to confirm):
  1) py-net-scan --help   # if console_script entry point is defined
  2) python -m py_net_scan --help   # package module runner
  3) python -m pynet_scan --help    # alternative package name
  4) python main.py --help          # if a top-level script exists
- For a quick smoke run that shouldn’t require elevated privileges:
  - python -m py_net_scan scan --target 127.0.0.1 --ports 80,443 --timeout 1 --concurrency 50  # adjust to actual CLI
  - If raw sockets/Scapy are used, Windows may require Administrator and Npcap; on Linux/macOS use sudo as needed.

Test
- Prefer pytest. Run from repo root:
  - python -m pip install -U pytest
  - pytest -q
- To run a subset (when debugging):
  - pytest -q tests -k "smoke or cli"  # adapt expression to repo tests

Lint/format/type-check (run all that are configured)
- Ruff (preferred when configured in pyproject.toml):
  - python -m pip install ruff
  - ruff check .
  - ruff format .           # if project uses ruff for formatting
- Black/Isort (common if not using ruff format):
  - python -m pip install black isort
  - black --check . && isort --check-only .
  - To auto-fix: black . && isort .
- Flake8 (if configured):
  - python -m pip install flake8
  - flake8 .
- Mypy (if configured):
  - python -m pip install mypy
  - mypy .

Continuous Integration (reproduce locally)
- Inspect .github/workflows/*.yml to confirm exact job steps and Python versions.
- Reproduce typical CI locally in this order:
  1) Clean env, then Bootstrap steps above.
  2) Run formatters/lints as configured (ruff/black/isort/flake8).
  3) Run type-checks if configured (mypy/pyright).
  4) Run pytest -q.
- Optional: use nektos/act to approximate GitHub Actions locally when needed.

Project layout and where to change things
- Package code likely in one of:
  - src/py_net_scan/ ...
  - py_net_scan/ ...
  - p y n e t _ s c a n / ... (alt name)
- Common important files:
  - CLI entry: src/<pkg>/cli.py, <pkg>/cli.py, or __main__.py (module runner)
  - Core scanning logic: <pkg>/scanner.py or similar (hosts/ports/concurrency/timeouts)
  - Utilities: <pkg>/net/*.py, <pkg>/models/*.py, <pkg>/output/*.py
  - Tests: tests/ (unit/integration)
  - Configs (one or more): pyproject.toml, setup.cfg, .flake8, ruff.toml, mypy.ini, pytest.ini, .pre-commit-config.yaml
- If adding features:
  - Update CLI parser (argparse/typer/click) and wire into scanning functions.
  - Add tests in tests/ mirroring structure of the feature area.
  - Expose new options via __init__.py and entry points if required.

Validation before committing
- Always run, in order (skip tools not configured):
  1) ruff check .  OR flake8 .
  2) ruff format . OR black . && isort .
  3) mypy .
  4) pytest -q
- If CI defines additional checks (security, packaging sdist/wheel), run them locally as in the CI workflow.

Common pitfalls and remedies
- Missing dev deps: run python -m pip install -e ".[dev]" or install requirements-dev.txt.
- Windows raw socket errors: use an elevated shell and ensure Npcap is installed if required by dependencies like scapy.
- Long scans/timeouts: prefer localhost/loopback targets for tests; keep timeouts small and concurrency limited for CI speed.
- Import path issues: if package uses src/ layout, ensure editable install (pip install -e .) so tests can import the package.
- Pre-commit failing: run pre-commit run -a and fix autofixes before retrying.

Minimal change workflow (fast path)
1) New shell: activate venv.
2) python -m pip install -e ".[dev]" || python -m pip install -e .
3) ruff check . || flake8 .
4) pytest -q
5) Make change; re-run 3–4; then run formatters (ruff format . or black . && isort .) and commit.

When to search
- Only search the codebase if: a command above is missing, a tool is not configured, or entry points aren’t found.
- Start with: pyproject.toml, setup.cfg, README.md, .github/workflows/, tests/, and the package directory (src/py_net_scan or py_net_scan).
