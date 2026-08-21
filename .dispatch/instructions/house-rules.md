# LANscape house rules

Things this repo does differently. All of these are enforced by CI or by the
release pipeline — getting them wrong fails a check or ships a bad release.

## PR titles are the release version

`quality-pr-title.yml` rejects any non-Dependabot PR whose title is not
`X.Y.Z - Description`, and rejects `X.Y.Z` that is not strictly greater than the
newest `releases/*` tag. Conventional-commit titles (`feat:`, `chore(scope):`)
fail this check. Use `4.1.7 - Fix ARP parsing on macOS`.

Commits inside the PR are still conventional — it is only the PR *title* that
carries the version, because the squash commit becomes the release trigger.

## Merging to main publishes a release

`release-trigger-main-push.yml` reads the first line of the squashed commit. If
it starts with `X.Y.Z` it creates and pushes `releases/X.Y.Z`, which fires the
GitHub release, the cross-repo lanscape-ui build, and the PyPI publish. There is
no "merge without releasing" path for a human PR. Treat every merge as a ship.

Dependabot is the exception: its `build(...)` / `ci(...)` titles carry no
version, and the workflow auto-increments the patch of the latest release.

## Never hand-edit the version

`pyproject.toml` says `version = "0.0.0"` on purpose. `release-pypi-publish.yml`
`sed`s the real version in at build time from the git tag. Bumping it in a PR is
always wrong.

## The virtualenv is `.env/`, one per worktree

Not `.venv/`. Every command in this repo is an editable install of the current
checkout, so a shared interpreter makes parallel worktrees overwrite each
other's `lanscape` install. Build a venv in each worktree:

```
python -m venv .env
.env\Scripts\python.exe -m pip install -e ".[dev]"   # .env/bin/python on macOS/Linux
```

## Dev mode needs two things that are not in the repo

`python -m lanscape` becomes the hot-reload dev environment only when
`lanscape/local/.env` exists — that file is gitignored, so a fresh worktree does
not have it, and it points at a *sibling clone of the `lanscape-ui` repo*. Copy
it in when you start a worktree:

```
cp lanscape/local/.env.example lanscape/local/.env   # then set LANSCAPE_UI_PATH
```

Without it, `python -m lanscape` still binds both ports but serves **503** —
`lanscape/ui/react_build/` ships empty and is filled by the release pipeline.
For backend-only work use `python -m lanscape --ws-server`, which needs neither.

`lanscape/local/` is excluded from the wheel (`pyproject.toml`, `MANIFEST.in`).
Never import it from shipping code without the `try/except ImportError` guard
`lanscape/ui/main.py` uses.

## Integration tests do not run under plain pytest

`pyproject.toml` sets `addopts = -m 'not integration'`, so `pytest tests/` skips
them by design. They need Docker and their own harness:

```
tests/integration/run.ps1 -Build      # Windows
tests/integration/run.sh --build      # macOS/Linux
```

## Dependencies live in `pyproject.toml` only

Runtime deps in `[project.dependencies]`, tooling in
`[project.optional-dependencies.dev]`. Never add a `requirements.txt` — CI
installs from `pyproject.toml` and nothing else.
