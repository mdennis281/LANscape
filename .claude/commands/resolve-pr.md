---
description: Resolve unresolved PR review comments and/or failing CI checks for the active pull request.
allowed-tools: Bash, Read, Write, Edit, Glob, Grep
---

# Resolve PR Issues

You are a PR resolution agent. Your task is to resolve **unresolved review comments** and **failing GitHub Actions checks** on the active pull request.

All PR data is gathered via local scripts that use the `gh` CLI — no MCP tools are needed.

## Step 0: Generate PR Analysis

Run:

```bash
python scripts/tasks/pr_analysis.py
```

This creates a `pr-analysis/` directory at the project root containing:
- `summary.md` — overview of comments and CI checks
- `comments/<thread_id>.json` — detail files for each unresolved review thread
- `checks/<check_name>.json` — detail files with logs for each failed CI check

**ALWAYS run a new analysis on invocation** to get the latest PR status.

## Step 1: Triage — Read the Summary

Read `pr-analysis/summary.md` to understand PR state.

### 1a. Identify Unresolved Comments

Focus on threads marked **Unresolved** that are **not outdated**.

### 1b. Identify Failing CI Checks

Focus on checks with conclusion `failure`, `timed_out`, or `action_required`.

### 1c. Decide the Workflow

| Unresolved Comments | Failing Checks | Action                                   |
|---------------------|----------------|------------------------------------------|
| Yes                 | No             | Run **Comment Resolution** (Step 2)      |
| No                  | Yes            | Run **Actions Troubleshooting** (Step 3) |
| Yes                 | Yes            | Run **both** sequentially (2 -> 3)       |
| No                  | No             | Report "PR is clean" and stop            |

---

## Step 2: Comment Resolution

For each unresolved, non-outdated review thread:

### 2a. Read the Comment Detail

Read the corresponding JSON file in `pr-analysis/comments/` for the full thread context (file path, line, body, replies).

### 2b. Evaluate the Comment

1. Read the file at the thread's `path` and `line`.
2. Ask: is the suggestion technically correct? Does it improve quality/safety/maintainability? Would it break existing behavior?

### 2c. Implement or Dismiss

- **Valid:** implement the fix, run relevant tests, then resolve.
- **Not valid:** the suggestion is incorrect, outdated, or harmful — resolve without changes.

Use your judgment. If a fix is reasonable and improves the code, implement it.

### 2d. Resolve the Thread

```bash
python scripts/tasks/resolve_comment.py --pr <PR_NUMBER> --comment-id "<THREAD_ID>"
```

The script outputs the thread state as JSON after resolution. Thread IDs are in `pr-analysis/summary.md` and the JSON detail files.

### 2e. Verify Resolution

Re-run the PR Analysis script (Step 0) and confirm all threads are resolved in the updated `summary.md`.

---

## Step 3: Actions Troubleshooting

### 3a. Read the Failed Check Details

For each failed check, read its JSON in `pr-analysis/checks/`. Each file has check metadata and failure logs (last 200 lines; full context in the file).

### 3b. Diagnose the Failure

| Category                  | Indicators                               | Resolution                                                    |
|---------------------------|------------------------------------------|---------------------------------------------------------------|
| **Lint failure**          | `pylint`, `autopep8`, score below thresh | Fix per `/lint`                                               |
| **Test failure**          | `pytest`, `FAILED`, assertion errors     | Read the failing test, understand the assertion, fix          |
| **Build/Package failure** | `twine`, `build`, `sdist`                | Check `pyproject.toml`, fix packaging config                  |
| **Docker build failure**  | `docker`, `COPY`, `RUN`                  | Check `docker/Dockerfile`, `Dockerfile.arm64`, `entrypoint.sh`|
| **Dependency failure**    | `pip install`, version conflicts         | Update dependency pins in `pyproject.toml`                    |
| **Timeout**               | `timed_out` conclusion                   | Check for infinite loops, network issues, or raise timeout    |

### 3c. Implement the Fix

1. Apply the fix.
2. Validate locally:
   - Lint: `python -m pylint lanscape`
   - Tests: `python -m pytest tests/<relevant_test>.py -v`
   - Build: `python -m build && twine check dist/*`
3. Commit and push.

### 3d. Re-check

CI re-runs automatically. Re-run the PR Analysis script once the new runs complete.

---

## Quick reference

| Purpose                   | Script                                    | Arguments                                |
|---------------------------|-------------------------------------------|------------------------------------------|
| Generate PR analysis      | `python scripts/tasks/pr_analysis.py`     | _(none — uses current branch)_           |
| Resolve a comment thread  | `python scripts/tasks/resolve_comment.py` | `--pr <NUMBER> --comment-id <THREAD_ID>` |

## Notes

- Both scripts require `gh` CLI installed and authenticated (`gh auth login`).
- The analysis script auto-detects the current branch and finds the associated open PR into `main`.
- If no open PR exists for the current branch, the script exits with an error.
- The `pr-analysis/` directory is gitignored and fully recreated on each run.
- Thread IDs are GraphQL node IDs (e.g. `PRRT_kwDO...`).
- Always run tests before resolving threads or committing.
- Skip `isOutdated: true` review threads unless the comment is clearly still relevant.
