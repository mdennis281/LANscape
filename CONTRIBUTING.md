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
