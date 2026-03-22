"""
PR Analysis Script — generates a pr-analysis/ directory with a markdown summary
and JSON detail files for the current branch's pull request.

Requires:
    - gh CLI installed and authenticated
    - git CLI available on PATH

Usage:
    python scripts/tasks/pr_analysis.py
"""
import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_ROOT / "pr-analysis"


# ── Pydantic Models ──────────────────────────────────────────────────────────

class ReviewComment(BaseModel):
    """A single comment within a review thread."""
    author: str = ""
    body: str = ""
    created_at: str = ""


class ReviewThread(BaseModel):
    """A PR review thread with resolution status."""
    id: str
    is_resolved: bool
    is_outdated: bool
    path: str = ""
    line: Optional[int] = None
    original_line: Optional[int] = None
    diff_side: str = ""
    comments: list[ReviewComment] = Field(default_factory=list)


class CheckRun(BaseModel):
    """A CI check run with status and conclusion."""
    name: str
    status: str = ""
    conclusion: str = ""
    workflow_name: str = ""
    details_url: str = ""
    run_id: Optional[int] = None


class PRInfo(BaseModel):
    """Core PR metadata."""
    number: int
    title: str = ""
    url: str = ""
    state: str = ""
    head_branch: str = ""
    base_branch: str = "main"


class AnalysisSummary(BaseModel):
    """Full analysis result."""
    pr: PRInfo
    threads: list[ReviewThread] = Field(default_factory=list)
    checks: list[CheckRun] = Field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────────

def run_command(
    args: list[str],
    check: bool = True,
    capture: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(args))
    return subprocess.run(
        args, check=check, capture_output=capture,
        encoding="utf-8", errors="replace", timeout=120
    )


def check_gh_cli() -> None:
    """Verify that gh CLI is installed and authenticated."""
    if not shutil.which("gh"):
        print("ERROR: GitHub CLI (gh) is not installed.", file=sys.stderr)
        print("Install it from https://cli.github.com/", file=sys.stderr)
        sys.exit(1)

    result = run_command(["gh", "auth", "status"], check=False)
    if result.returncode != 0:
        print("ERROR: GitHub CLI is not authenticated.", file=sys.stderr)
        print("Run 'gh auth login' to authenticate.", file=sys.stderr)
        sys.exit(1)


def get_current_branch() -> str:
    """Get the currently checked-out git branch."""
    result = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return result.stdout.strip()


def get_repo_info() -> tuple[str, str]:
    """Get the owner and repo name from the gh CLI."""
    result = run_command([
        "gh", "repo", "view", "--json", "owner,name"
    ])
    data = json.loads(result.stdout)
    return data["owner"]["login"], data["name"]


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r'[^\w\-.]', '_', name)


# ── Data Fetchers ────────────────────────────────────────────────────────────

def find_pr_for_branch(branch: str) -> PRInfo:
    """Find the open PR from the current branch into main."""
    result = run_command([
        "gh", "pr", "list",
        "--head", branch,
        "--base", "main",
        "--state", "open",
        "--json", "number,title,url,state,headRefName",
        "--limit", "1"
    ])
    prs = json.loads(result.stdout)
    if not prs:
        print(
            f"ERROR: No open PR found for branch '{branch}' targeting 'main'.",
            file=sys.stderr
        )
        sys.exit(1)

    pr_data = prs[0]
    return PRInfo(
        number=pr_data["number"],
        title=pr_data.get("title", ""),
        url=pr_data.get("url", ""),
        state=pr_data.get("state", ""),
        head_branch=pr_data.get("headRefName", branch),
    )


def fetch_review_threads(owner: str, repo: str, pr_number: int) -> list[ReviewThread]:
    """Fetch all review threads via GraphQL."""
    query = """
    query($owner: String!, $repo: String!, $number: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $number) {
          reviewThreads(first: 100) {
            nodes {
              id
              isResolved
              isOutdated
              path
              line
              originalLine
              diffSide
              comments(first: 50) {
                nodes {
                  author { login }
                  body
                  createdAt
                }
              }
            }
          }
        }
      }
    }
    """
    result = run_command([
        "gh", "api", "graphql",
        "-F", f"owner={owner}",
        "-F", f"repo={repo}",
        "-F", f"number={pr_number}",
        "-f", f"query={query}"
    ])
    data = json.loads(result.stdout)

    threads_data = (
        data.get("data", {})
        .get("repository", {})
        .get("pullRequest", {})
        .get("reviewThreads", {})
        .get("nodes", [])
    )

    threads: list[ReviewThread] = []
    for node in threads_data:
        comments = [
            ReviewComment(
                author=c.get("author", {}).get("login", "") if c.get("author") else "",
                body=c.get("body", ""),
                created_at=c.get("createdAt", ""),
            )
            for c in node.get("comments", {}).get("nodes", [])
        ]
        threads.append(ReviewThread(
            id=node["id"],
            is_resolved=node.get("isResolved", False),
            is_outdated=node.get("isOutdated", False),
            path=node.get("path", ""),
            line=node.get("line"),
            original_line=node.get("originalLine"),
            diff_side=node.get("diffSide", ""),
            comments=comments,
        ))
    return threads


def fetch_check_runs(pr_number: int) -> list[CheckRun]:
    """Fetch CI check run statuses for a PR."""
    result = run_command([
        "gh", "pr", "checks", str(pr_number),
        "--json", "name,state,bucket,description,link,event,workflow"
    ], check=False)

    if result.returncode != 0:
        logger.warning("Could not fetch check runs: %s", result.stderr)
        return []

    raw_checks = json.loads(result.stdout)
    checks: list[CheckRun] = []
    for c in raw_checks:
        workflow = c.get("workflow") or ""
        state = c.get("state", "")
        # gh pr checks uses 'bucket' for pass/fail/pending categorization
        # and 'state' for the raw status string
        bucket = c.get("bucket", "")
        # Map bucket to conclusion-like values
        if bucket == "fail":
            conclusion = "failure"
        elif bucket == "pass":
            conclusion = "success"
        elif bucket in ("pending", ""):
            conclusion = ""
        else:
            conclusion = bucket
        checks.append(CheckRun(
            name=c.get("name", ""),
            status=state,
            conclusion=conclusion,
            workflow_name=workflow,
            details_url=c.get("link", ""),
        ))
    return checks


def fetch_failed_run_ids(owner: str, repo: str, branch: str) -> dict[str, int]:
    """Map workflow run names to run IDs for failed runs on this branch."""
    result = run_command([
        "gh", "api",
        f"/repos/{owner}/{repo}/actions/runs",
        "--jq", ".workflow_runs[] | {id: .id, name: .name, conclusion: .conclusion, "
                "head_branch: .head_branch}",
        "-q", f".workflow_runs | map(select(.head_branch == \"{branch}\")) "
              f"| group_by(.name) | map(sort_by(.id) | reverse | .[0]) | .[]"
    ], check=False)

    if result.returncode != 0:
        # Fallback: use gh run list
        return _fetch_failed_run_ids_fallback(branch)
    return {}


def _fetch_failed_run_ids_fallback(branch: str) -> dict[str, int]:
    """Fallback method to get failed run IDs using gh run list."""
    result = run_command([
        "gh", "run", "list",
        "--branch", branch,
        "--status", "failure",
        "--json", "databaseId,name,workflowName",
        "--limit", "20"
    ], check=False)

    if result.returncode != 0:
        return {}

    runs = json.loads(result.stdout)
    mapping: dict[str, int] = {}
    for r in runs:
        name = r.get("workflowName", r.get("name", ""))
        if name and name not in mapping:
            mapping[name] = r["databaseId"]
    return mapping


def fetch_failed_job_logs(run_id: int) -> str:
    """Fetch the log output for failed jobs in a workflow run."""
    result = run_command(
        ["gh", "run", "view", str(run_id), "--log-failed"],
        check=False
    )
    if result.returncode != 0:
        return f"Could not fetch logs for run {run_id}: {result.stderr.strip()}"

    log_text = result.stdout
    # Truncate to last 200 lines per job to keep output manageable
    lines = log_text.splitlines()
    if len(lines) > 200:
        lines = ["... (truncated, showing last 200 lines) ..."] + lines[-200:]
    return "\n".join(lines)


# ── Output Generation ────────────────────────────────────────────────────────

def prepare_output_dir() -> None:
    """Clear and recreate the output directory."""
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)
    (OUTPUT_DIR / "comments").mkdir()
    (OUTPUT_DIR / "checks").mkdir()


def write_comment_files(threads: list[ReviewThread]) -> None:
    """Write JSON detail files for each unresolved, non-outdated thread."""
    for thread in threads:
        if thread.is_resolved or thread.is_outdated:
            continue
        filename = sanitize_filename(thread.id) + ".json"
        filepath = OUTPUT_DIR / "comments" / filename
        filepath.write_text(
            thread.model_dump_json(indent=2),
            encoding="utf-8"
        )


def write_check_files(
    checks: list[CheckRun],
    failed_logs: dict[str, str]
) -> None:
    """Write JSON detail files for each failed check."""
    for check in checks:
        if check.conclusion not in ("failure", "timed_out", "action_required"):
            continue
        filename = sanitize_filename(check.name) + ".json"
        filepath = OUTPUT_DIR / "checks" / filename
        detail = {
            **check.model_dump(),
            "logs": failed_logs.get(check.workflow_name, "")
                    or failed_logs.get(check.name, "No logs available."),
        }
        filepath.write_text(
            json.dumps(detail, indent=2),
            encoding="utf-8"
        )


def _build_comments_section(
    threads: list[ReviewThread]
) -> list[str]:
    """Build the review comments section of the summary."""
    resolved = [t for t in threads if t.is_resolved]
    unresolved = [t for t in threads if not t.is_resolved and not t.is_outdated]
    outdated = [t for t in threads if t.is_outdated and not t.is_resolved]

    lines: list[str] = [
        "## Review Comments",
        "",
        "| Status | Count |",
        "| --- | --- |",
        f"| Resolved | {len(resolved)} |",
        f"| Unresolved | {len(unresolved)} |",
        f"| Outdated | {len(outdated)} |",
        "",
    ]

    if unresolved:
        lines += ["### Unresolved Comments", ""]
        lines += ["| Thread ID | File | Line | First Comment |"]
        lines += ["| --- | --- | --- | --- |"]
        for t in unresolved:
            preview = ""
            if t.comments:
                preview = t.comments[0].body[:80].replace("\n", " ")
                if len(t.comments[0].body) > 80:
                    preview += "..."
            line_str = str(t.line) if t.line else "—"
            lines.append(f"| `{t.id}` | `{t.path}` | {line_str} | {preview} |")
        lines += [
            "",
            "> Detail files: `pr-analysis/comments/<thread_id>.json`",
            "",
        ]

    if resolved:
        lines += ["### Resolved Comments", ""]
        lines += ["| Thread ID | File | Line |", "| --- | --- | --- |"]
        for t in resolved:
            line_str = str(t.line) if t.line else "—"
            lines.append(f"| `{t.id}` | `{t.path}` | {line_str} |")
        lines.append("")

    return lines


def _build_checks_section(checks: list[CheckRun]) -> list[str]:
    """Build the CI checks section of the summary."""
    lines: list[str] = ["## CI Checks", ""]
    if not checks:
        lines.append("No check runs found.")
        return lines

    lines += ["| Check | Status | Conclusion | Workflow |"]
    lines += ["| --- | --- | --- | --- |"]
    for c in checks:
        conclusion = c.conclusion or "—"
        lines.append(
            f"| {c.name} | {c.status} | {conclusion} | {c.workflow_name} |"
        )
    lines.append("")

    failed = [
        c for c in checks
        if c.conclusion in ("failure", "timed_out", "action_required")
    ]
    if failed:
        lines.append(
            f"> {len(failed)} failing check(s). "
            f"Detail files: `pr-analysis/checks/<check_name>.json`"
        )
        lines.append("")

    return lines


def generate_summary_md(summary: AnalysisSummary) -> str:
    """Generate the markdown summary content."""
    pr = summary.pr

    lines: list[str] = [
        f"# PR Analysis: #{pr.number} — {pr.title}",
        "",
        f"- **URL:** {pr.url}",
        f"- **Branch:** `{pr.head_branch}` → `{pr.base_branch}`",
        f"- **State:** {pr.state}",
        "",
    ]

    lines += _build_comments_section(summary.threads)
    lines += _build_checks_section(summary.checks)

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────

def _collect_pr_data(
    branch: str
) -> tuple[AnalysisSummary, dict[str, str]]:
    """Gather all PR data: info, threads, checks, and failed logs."""
    owner, repo = get_repo_info()
    logger.info("Repository: %s/%s", owner, repo)

    pr_info = find_pr_for_branch(branch)
    logger.info("Found PR #%d: %s", pr_info.number, pr_info.title)

    logger.info("Fetching review threads...")
    threads = fetch_review_threads(owner, repo, pr_info.number)
    logger.info(
        "  %d threads (%d unresolved)",
        len(threads),
        sum(1 for t in threads if not t.is_resolved and not t.is_outdated)
    )

    logger.info("Fetching CI check runs...")
    checks = fetch_check_runs(pr_info.number)
    failed_checks = [
        c for c in checks
        if c.conclusion in ("failure", "timed_out", "action_required")
    ]
    logger.info(
        "  %d checks (%d failing)", len(checks), len(failed_checks)
    )

    failed_logs: dict[str, str] = {}
    if failed_checks:
        logger.info("Fetching failed run logs...")
        run_ids = _fetch_failed_run_ids_fallback(branch)
        for check in failed_checks:
            run_id = run_ids.get(check.workflow_name) or run_ids.get(check.name)
            if run_id:
                failed_logs[check.workflow_name or check.name] = (
                    fetch_failed_job_logs(run_id)
                )

    summary = AnalysisSummary(pr=pr_info, threads=threads, checks=checks)
    return summary, failed_logs


def main() -> None:
    """Run PR analysis and generate output files."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    check_gh_cli()

    branch = get_current_branch()
    logger.info("Current branch: %s", branch)

    if branch in ("main", "master"):
        print(
            "ERROR: You are on the default branch. "
            "Check out a feature branch with an open PR.",
            file=sys.stderr
        )
        sys.exit(1)

    summary, failed_logs = _collect_pr_data(branch)

    prepare_output_dir()
    write_comment_files(summary.threads)
    write_check_files(summary.checks, failed_logs)

    summary_md = generate_summary_md(summary)
    (OUTPUT_DIR / "summary.md").write_text(summary_md, encoding="utf-8")

    logger.info("")
    logger.info("PR analysis written to: %s", OUTPUT_DIR)
    logger.info("  summary.md")

    unresolved = [
        t for t in summary.threads
        if not t.is_resolved and not t.is_outdated
    ]
    failed = [
        c for c in summary.checks
        if c.conclusion in ("failure", "timed_out", "action_required")
    ]
    if unresolved:
        logger.info("  comments/ (%d files)", len(unresolved))
    if failed:
        logger.info("  checks/ (%d files)", len(failed))


if __name__ == "__main__":
    main()
