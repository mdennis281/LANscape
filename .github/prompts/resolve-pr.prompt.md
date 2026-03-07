---
agent: agent
---

# Resolve PR Issues

You are a PR resolution agent. Your task is to resolve **unresolved review comments** and **failing GitHub Actions checks** on the active pull request. Use MCP tools for all operations — never use `gh` CLI unless explicitly noted as an exception.

## Step 0: Identify the Active PR

Use the `github-pull-request_activePullRequest` tool to get the PR number, URL, branch, owner, and repo.

Store the `owner`, `repo`, and `pullNumber` — they are used in every subsequent step.

## Step 1: Triage — Detect What Needs Attention

### 1a. Check for Unresolved Review Threads

Use the MCP tool `pull_request_read` with:
- `method`: `get_review_comments`
- `owner`, `repo`, `pullNumber` from Step 0

Scan the results for threads where `isResolved` is `false` and `isOutdated` is `false`. These are the **actionable review comments**.

### 1b. Check for Failing CI Checks

Use the MCP tool `pull_request_read` with:
- `method`: `get_check_runs`
- `owner`, `repo`, `pullNumber` from Step 0

Identify any check runs with `conclusion` of `failure`, `timed_out`, or `action_required`. These are the **failing checks**.

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

### 2a. Evaluate the Comment

1. Read the file at the thread's `path` and `line` in the local workspace
2. Analyze the suggestion:
   - Is it technically correct?
   - Does it improve code quality, safety, or maintainability?
   - Would it break existing functionality?

### 2b. Implement or Dismiss

**If valid:** Implement the fix, run relevant tests, then proceed to resolve.
**If not valid:** The suggestion is incorrect, outdated, or harmful — proceed to resolve without changes.

Use your judgment. If a fix is reasonable and improves the code, implement it.

### 2c. Resolve the Thread

The GitHub MCP server does not expose a thread-resolve mutation. This is the **one exception** where `gh` CLI is required.

First, get the thread node IDs via GraphQL (the MCP `get_review_comments` response does not include them):

```powershell
gh api graphql -f query='query { repository(owner: "OWNER", name: "REPO") { pullRequest(number: PR_NUMBER) { reviewThreads(first: 50) { nodes { id isResolved isOutdated comments(first: 1) { nodes { body path line } } } } } } }'
```

Then resolve each unresolved thread:

```powershell
gh api graphql -f query='mutation { resolveReviewThread(input: { threadId: "THREAD_ID" }) { thread { isResolved } } }'
```

Replace `OWNER`, `REPO`, `PR_NUMBER`, and `THREAD_ID` with values from previous steps.

### 2d. Verify Resolution

Re-run Step 1a and confirm all threads are now resolved.

---

## Step 3: Actions Troubleshooting

### 3a. Identify Failing Jobs

Use the MCP tool `actions_list` with:
- `method`: `list_workflow_runs`
- `owner`, `repo`
- Filter to the PR's head branch or use the run ID from failing check runs in Step 1b

Then use `actions_list` with:
- `method`: `list_workflow_jobs`
- `resource_id`: the workflow run ID
- to get the list of jobs and their statuses

### 3b. Get Failure Logs

Use the MCP tool `get_job_logs` with:
- `owner`, `repo`
- `run_id`: the failing workflow run ID
- `failed_only`: `true`
- `return_content`: `true`
- `tail_lines`: `100` (increase if needed for full context)

### 3c. Diagnose the Failure

Common failure categories and resolution strategies:

| Category | Indicators | Resolution |
|----------|-----------|------------|
| **Lint failure** | `pylint`, `autopep8`, score below threshold | Fix lint issues per `.github/prompts/linting.prompt.md` |
| **Test failure** | `pytest`, `FAILED`, assertion errors | Read the failing test, understand the assertion, fix the code or test |
| **Build/Package failure** | `twine`, `build`, `sdist` | Check `pyproject.toml`, fix packaging config |
| **Docker build failure** | `docker`, `COPY`, `RUN` | Check `docker/Dockerfile`, `docker/Dockerfile.arm64`, and `docker/docker-entrypoint.sh` |
| **Dependency failure** | `pip install`, version conflicts | Update dependency pins in `pyproject.toml` |
| **Timeout** | `timed_out` conclusion | Check for infinite loops, network issues, or increase timeout |

### 3d. Implement the Fix

1. Apply the fix to the relevant source files
2. Run local validation:
   - For lint failures: Run the `Run Linter (Pylint)` VS Code task
   - For test failures: `python.exe -m pytest tests/<relevant_test>.py -v`  
   - For build failures: `python -m build && twine check dist/*`
3. Commit the fix using `mcp_gitkraken_git_add_or_commit` and push using `mcp_gitkraken_git_push`

### 3e. Re-check (Optional)

After pushing the fix, the CI will re-run automatically. If the user wants immediate verification, use `actions_run_trigger` with method `rerun_failed_jobs` to re-trigger only the failed jobs.

---

## Quick Reference: MCP Tools Used

| Purpose | MCP Tool | Method/Params |
|---------|----------|---------------|
| Active PR context | `github-pull-request_activePullRequest` | _(no params)_ |
| PR review threads | `pull_request_read` | `method: get_review_comments` |
| PR check runs | `pull_request_read` | `method: get_check_runs` |
| PR details | `pull_request_read` | `method: get` |
| PR diff | `pull_request_read` | `method: get_diff` |
| PR changed files | `pull_request_read` | `method: get_files` |
| Update PR description | `update_pull_request` | `owner, repo, pullNumber, body` |
| List workflow runs | `actions_list` | `method: list_workflow_runs` |
| List workflow jobs | `actions_list` | `method: list_workflow_jobs` |
| Get job logs | `get_job_logs` | `failed_only: true, return_content: true` |
| Rerun failed jobs | `actions_run_trigger` | `method: rerun_failed_jobs` |
| Git commit | `mcp_gitkraken_git_add_or_commit` | `directory, files, message` |
| Git push | `mcp_gitkraken_git_push` | `directory` |
| Resolve thread | `gh api graphql` | **Exception** — not available via MCP |
| Get thread node IDs | `gh api graphql` | **Exception** — not available via MCP |

## Notes

- **Always use MCP tools** — never use `gh` CLI unless explicitly marked as an exception in the table above.
- The only `gh` CLI exceptions are `resolveReviewThread` / `unresolveReviewThread` GraphQL mutations and fetching thread node IDs — these are not in any MCP toolset.
- After implementing fixes, always run tests before resolving threads or committing.
- Use `mcp_gitkraken_git_add_or_commit` for commits. Messages should reference the PR context: `"Address PR #<number> feedback"` or `"Fix CI: <description>"`
- Skip `isOutdated: true` review threads unless the comment is clearly still relevant to current code.
