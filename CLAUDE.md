# LANScape — Python Network Scanner

LANScape is a portable local-network scanning tool built in **Python + React**. This repo is the Python scanning library. It exposes a WebSocket server that streams real-time updates (discovered devices, open ports, identified services) to the React UI in the sibling `lanscape-ui` project.

## Repo layout

- `lanscape/` — the library. New public classes/features **must** be exported from `lanscape/__init__.py`.
- `tests/` — pytest suite. Every new feature or changed behavior needs a test here.
- `scripts/tasks/` — helper scripts used by the PR / analysis workflows (see `pr_analysis.py`, `resolve_comment.py`).
- `docs/wiki/` — usage docs for library and WebSocket consumers. Kept in sync via `.github/workflows/chore-wiki-sync.yml`.
- `docker/` — `Dockerfile`, `Dockerfile.arm64`, `docker-entrypoint.sh`.
- `.github/` — GitHub Actions workflows, plus the legacy Copilot instructions/prompts that these Claude files mirror.

## Environment

Use the project venv (`.env/`). Before running Python, activate it:

- Windows: `.env/Scripts/activate`
- macOS / Linux: `source .env/bin/activate`

## Design preferences (when writing code)

- Pydantic models for structured data. If a function has "too many args," it's usually a missing Pydantic model.
- `requests` for HTTP calls.
- Thread pools over `asyncio` where applicable.
- Python 3.10+ syntax.
- Type hints on every function and method.
- Any new/changed dependency must also land in `pyproject.toml`.

## Definition of done

Every change should:

1. Add/update unit tests under `tests/`.
2. Export new public library features from `lanscape/__init__.py`.
3. Pass lint — see `/lint` (pylint must score 10/10).
4. Pass tests — `python -m pytest tests/<file>.py -v` for small changes, or the `Run Unit Tests` VS Code task for bigger ones.
5. Update `docs/wiki/` if schemas/models changed or features were added/removed — see `/wiki-sync`.

If tests fail after a fix, loop back through the definition of done.

## Agents and commands

Role-specific context lives in `.claude/agents/`:

- **coder** (`.claude/agents/coder.md`) — implementation work.
- **reviewer** (`.claude/agents/reviewer.md`) — PR code review.

Reusable workflows are slash commands in `.claude/commands/`:

- `/lint` — run pylint (and autopep8 for mass fixes) to 10/10.
- `/summarize-changes` — summarize current branch diff vs `main`.
- `/resolve-pr` — full PR resolution workflow (unresolved comments + failing checks).
- `/wiki-sync` — update `docs/wiki/` when schemas or features change.

## Related Copilot files

This setup mirrors the GitHub Copilot configuration in `.github/copilot-instructions.md`, `.github/instructions/`, `.github/prompts/`, and `.vscode/mcp.json`. Both toolchains are kept in sync intentionally; when editing guidance, update both sides.
