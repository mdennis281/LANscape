"""Lint only Python files changed relative to origin/main.

Pylint's score formula divides errors by total statements across all linted
files. On a large codebase this dilutes the score so much that real issues in
new code don't move the needle. This script narrows the lint target to only
files touched in the current branch, giving an accurate score for the diff.

Usage:
    python scripts/tasks/lint_diff.py [--base <ref>]

Options:
    --base  Git ref to diff against (default: origin/main)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def get_changed_py_files(base_ref: str) -> list[str]:
    """Return .py files changed relative to *base_ref* that still exist on disk."""
    result = subprocess.run(
        ['git', 'diff', '--name-only', '--diff-filter=ACM', base_ref, '--', '*.py'],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=True,
    )
    files = [
        f for f in result.stdout.splitlines()
        if f.strip() and (PROJECT_ROOT / f).exists()
    ]
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description='Pylint diff linter')
    parser.add_argument('--base', default='origin/main',
                        help='Git ref to diff against (default: origin/main)')
    args = parser.parse_args()

    files = get_changed_py_files(args.base)

    if not files:
        print(f'No changed .py files found relative to {args.base}. Nothing to lint.')
        sys.exit(0)

    print(f'Linting {len(files)} changed file(s) vs {args.base}:')
    for f in files:
        print(f'  {f}')
    print()

    python = sys.executable
    result = subprocess.run(
        [python, '-m', 'pylint', '--score=yes', *files],
        cwd=PROJECT_ROOT,
    )
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
