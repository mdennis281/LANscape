---
agent: agent
---

# Resolve PR Issues

You are a PR resolution agent. Your task is to resolve **unresolved review comments** and **failing GitHub Actions checks** on the active pull request.

All PR data is gathered via local scripts that use the `gh` CLI — no MCP tools are needed.

## Step 0: Generate PR Analysis

Run the **PR Analysis** VS Code task, or execute directly:

```bash
python scripts/tasks/pr_analysis.py
```

This creates a `pr-analysis/` directory at the project root containing:
- `summary.md` — overview of comments and CI checks
- `comments/<thread_id>.json` — detail files for each unresolved review thread
- `checks/<check_name>.json` — detail files with logs for each failed CI check

## Step 1: Triage — Read the Summary

Read `pr-analysis/summary.md` to understand the PR state. ALWAYS RUN A NEW ANALYSIS ON INVOCATION OF THIS WORKFLOW TO GET THE LATEST PR STATUS.

### 1a. Identify Unresolved Comments

The summary lists all review threads with their IDs and resolution status. Focus on threads marked **Unresolved** that are **not outdated**.

### 1b. Identify Failing CI Checks

The summary shows all CI check runs with their status and conclusion. Focus on checks with conclusion `failure`, `timed_out`, or `action_required`.

### 1c. Decide the Workflow

| Unresolved Comments | Failing Checks | Action                              |
|---------------------|----------------|--------------------------------------|
| Yes                 | No             | Run **Comment Resolution** (Step 2)  |
| No                  | Yes            | Run **Actions Troubleshooting** (Step 3) |
| Yes                 | Yes            | Run **both** sequentially (2 → 3)    |
| No                  | No             | Report "PR is clean" and stop        |

---

## Step 2: Comment Resolution

For each unresolved, non-outdated review thread:

### 2a. Read the Comment Detail

Read the corresponding JSON file in `pr-analysis/comments/` for the full thread context — including the file path, line number, comment body, and all replies.

### 2b. Evaluate the Comment

1. Read the file at the thread's `path` and `line` in the local workspace
2. Analyze the suggestion:
   - Is it technically correct?
   - Does it improve code quality, safety, or maintainability?
   - Would it break existing functionality?

### 2c. Implement or Dismiss

**If valid:** Implement the fix, run relevant tests, then proceed to resolve.
**If not valid:** The suggestion is incorrect, outdated, or harmful — proceed to resolve without changes.

Use your judgment. If a fix is reasonable and improves the code, implement it.

### 2d. Resolve the Thread

Run the **Resolve PR Comment** VS Code task, or execute directly:

```bash
python scripts/tasks/resolve_comment.py --pr <PR_NUMBER> --comment-id "<THREAD_ID>"
```

The script will output the thread state as JSON after resolution. The `THREAD_ID` values are listed in `pr-analysis/summary.md` and the JSON detail files.

### 2e. Verify Resolution

After resolving all threads, re-run the PR Analysis script (Step 0) and confirm all threads are now resolved in the updated `summary.md`.

---

## Step 3: Actions Troubleshooting

### 3a. Read the Failed Check Details

For each failed check, read the corresponding JSON file in `pr-analysis/checks/`. Each file contains:
- Check metadata (name, status, conclusion, workflow, URL)
- Failure logs (truncated to last 200 lines; full context in the file)

### 3b. Diagnose the Failure

Common failure categories and resolution strategies:

| Category | Indicators | Resolution |
|----------|-----------|------------|
| **Lint failure** | `pylint`, `autopep8`, score below threshold | Fix lint issues per `.github/prompts/linting.prompt.md` |
| **Test failure** | `pytest`, `FAILED`, assertion errors | Read the failing test, understand the assertion, fix the code or test |
| **Build/Package failure** | `twine`, `build`, `sdist` | Check `pyproject.toml`, fix packaging config |
| **Docker build failure** | `docker`, `COPY`, `RUN` | Check `docker/Dockerfile`, `docker/Dockerfile.arm64`, and `docker/docker-entrypoint.sh` |
| **Dependency failure** | `pip install`, version conflicts | Update dependency pins in `pyproject.toml` |
| **Timeout** | `timed_out` conclusion | Check for infinite loops, network issues, or increase timeout |

### 3c. Implement the Fix

1. Apply the fix to the relevant source files
2. Run local validation:
   - For lint failures: Run the `Run Linter (Pylint)` VS Code task
   - For test failures: `python.exe -m pytest tests/<relevant_test>.py -v`
   - For build failures: `python -m build && twine check dist/*`
3. Commit and push the fix

### 3d. Re-check

After pushing the fix, the CI will re-run automatically. Re-run the PR Analysis script to verify the updated check statuses once the new runs complete.

---

## Quick Reference: Scripts & Tasks

| Purpose | Script / Task | Arguments |
|---------|--------------|-----------|
| Generate PR analysis | `python scripts/tasks/pr_analysis.py` | _(none — uses current branch)_ |
| Resolve a comment thread | `python scripts/tasks/resolve_comment.py` | `--pr <NUMBER> --comment-id <THREAD_ID>` |
| VS Code: PR Analysis | Task: **PR Analysis** | _(none)_ |
| VS Code: Resolve PR Comment | Task: **Resolve PR Comment** | Prompted for PR number and thread ID |

## Output Files

| File | Contents |
|------|----------|
| `pr-analysis/summary.md` | PR overview, comment table (resolved/unresolved with IDs), CI check table |
| `pr-analysis/comments/<id>.json` | Full thread detail: path, line, all comments with authors and bodies |
| `pr-analysis/checks/<name>.json` | Check metadata + failure logs |

## Notes

- Both scripts require the `gh` CLI to be installed and authenticated (`gh auth login`).
- The analysis script auto-detects the current branch and finds the associated open PR into `main`.
- If no open PR exists for the current branch, the script exits with an error.
- The `pr-analysis/` directory is gitignored and fully recreated on each run.
- Thread IDs are GraphQL node IDs (e.g. `PRRT_kwDO...`) — these are the values needed by the resolve script.
- After implementing fixes, always run tests before resolving threads or committing.
- Skip `isOutdated: true` review threads unless the comment is clearly still relevant to current code.
