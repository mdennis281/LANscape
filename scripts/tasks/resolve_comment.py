"""
Resolve a PR review comment thread via the GitHub GraphQL API.

Requires:
    - gh CLI installed and authenticated

Usage:
    python scripts/tasks/resolve_comment.py --pr 79 --comment-id "PRRT_kwDO..."

Returns the thread state as JSON to stdout after resolution.
"""
# pylint: disable=duplicate-code
import json
import shutil
import subprocess
import sys
from argparse import ArgumentParser

from pydantic import BaseModel


def run_command(
    args: list[str],
    check: bool = True,
    capture: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the result."""
    return subprocess.run(
        args, check=check, capture_output=capture,
        encoding="utf-8", errors="replace", timeout=60
    )


def check_gh_cli() -> None:  # pylint: disable=duplicate-code
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


class ThreadState(BaseModel):
    """Resolution result for a review thread."""
    thread_id: str
    is_resolved: bool


def resolve_thread(thread_id: str) -> ThreadState:
    """Resolve a review thread and return its new state."""
    mutation = """
    mutation($threadId: ID!) {
      resolveReviewThread(input: { threadId: $threadId }) {
        thread {
          id
          isResolved
        }
      }
    }
    """
    result = run_command([
        "gh", "api", "graphql",
        "-F", f"threadId={thread_id}",
        "-f", f"query={mutation}"
    ], check=False)

    if result.returncode != 0:
        print(
            f"ERROR: Failed to resolve thread '{thread_id}'.",
            file=sys.stderr
        )
        print(result.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    data = json.loads(result.stdout)

    errors = data.get("errors")
    if errors:
        print("ERROR: GraphQL errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err.get('message', err)}", file=sys.stderr)
        sys.exit(1)

    thread_data = (
        data.get("data", {})
        .get("resolveReviewThread", {})
        .get("thread", {})
    )

    return ThreadState(
        thread_id=thread_data.get("id", thread_id),
        is_resolved=thread_data.get("isResolved", False),
    )


def main() -> None:
    """Parse args and resolve the specified review thread."""
    parser = ArgumentParser(
        description="Resolve a PR review comment thread."
    )
    parser.add_argument(
        "--pr", type=int, required=True,
        help="PR number (for context/validation)"
    )
    parser.add_argument(
        "--comment-id", type=str, required=True,
        help="GraphQL thread node ID (e.g. PRRT_kwDO...)"
    )
    args = parser.parse_args()

    check_gh_cli()

    state = resolve_thread(args.comment_id)

    # Output the result as JSON to stdout
    print(state.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
