"""
Cleanup old pre-release tags and GitHub releases.

Deletes pre-release tags (pre-releases/*) and their associated GitHub releases
that are older than a configurable threshold (default: 3 months).

Requires:
    - gh CLI authenticated and available on PATH
    - git CLI available on PATH

Usage:
    python scripts/cleanup_prereleases.py [--max-age-days 90] [--dry-run]
"""
import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)

DEFAULT_MAX_AGE_DAYS = 90


class PreReleaseTag(BaseModel):
    """Represents a pre-release git tag with its associated metadata."""
    tag_name: str
    version: str
    commit_date: datetime
    age_days: int
    has_release: bool = False


class CleanupResult(BaseModel):
    """Summary of a cleanup run."""
    tags_deleted: list[str] = []
    releases_deleted: list[str] = []
    tags_failed: list[str] = []
    releases_failed: list[str] = []
    dry_run: bool = False


def run_command(
    args: list[str],
    check: bool = True,
    capture: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(args))
    return subprocess.run(
        args,
        check=check,
        capture_output=capture,
        text=True,
        timeout=60
    )


def get_prerelease_tags() -> list[str]:
    """Get all pre-release tags from the repository."""
    result = run_command(["git", "tag", "--list", "pre-releases/*", "--sort=-version:refname"])
    tags = [t.strip() for t in result.stdout.strip().splitlines() if t.strip()]
    logger.info("Found %d pre-release tags", len(tags))
    return tags


def get_tag_commit_date(tag: str) -> Optional[datetime]:
    """Get the commit date for a given tag."""
    try:
        result = run_command(
            ["git", "log", "-1", "--format=%aI", tag],
            check=True
        )
        date_str = result.stdout.strip()
        if not date_str:
            return None
        return datetime.fromisoformat(date_str)
    except (subprocess.CalledProcessError, ValueError) as exc:
        logger.warning("Could not get date for tag %s: %s", tag, exc)
        return None


def get_github_releases() -> dict[str, str]:
    """Get mapping of tag_name -> release_id for all pre-release GitHub releases."""
    try:
        result = run_command([
            "gh", "release", "list",
            "--json", "tagName,isPrerelease",
            "--limit", "200"
        ])
        releases = json.loads(result.stdout)
        prerelease_tags = {}
        for release in releases:
            tag = release.get("tagName", "")
            if tag.startswith("pre-releases/") and release.get("isPrerelease", False):
                prerelease_tags[tag] = tag
        logger.info("Found %d pre-release GitHub releases", len(prerelease_tags))
        return prerelease_tags
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        logger.warning("Could not list GitHub releases: %s", exc)
        return {}


def build_prerelease_inventory(max_age_days: int) -> list[PreReleaseTag]:
    """Build an inventory of pre-release tags older than max_age_days."""
    now = datetime.now(timezone.utc)
    tags = get_prerelease_tags()
    github_releases = get_github_releases()
    stale_tags: list[PreReleaseTag] = []

    for tag in tags:
        commit_date = get_tag_commit_date(tag)
        if commit_date is None:
            logger.warning("Skipping tag %s: could not determine date", tag)
            continue

        if commit_date.tzinfo is None:
            commit_date = commit_date.replace(tzinfo=timezone.utc)

        age_days = (now - commit_date).days
        if age_days >= max_age_days:
            version = tag.replace("pre-releases/", "")
            stale_tags.append(PreReleaseTag(
                tag_name=tag,
                version=version,
                commit_date=commit_date,
                age_days=age_days,
                has_release=tag in github_releases
            ))

    stale_tags.sort(key=lambda t: t.age_days, reverse=True)
    logger.info(
        "Found %d pre-release tags older than %d days",
        len(stale_tags), max_age_days
    )
    return stale_tags


def delete_github_release(tag_name: str) -> bool:
    """Delete a GitHub release by its tag name."""
    try:
        run_command(["gh", "release", "delete", tag_name, "--yes"], check=True)
        logger.info("Deleted GitHub release: %s", tag_name)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to delete release %s: %s", tag_name, exc)
        return False


def delete_git_tag(tag_name: str) -> bool:
    """Delete a git tag both locally and on the remote."""
    try:
        # Delete remote tag
        run_command(["git", "push", "origin", "--delete", tag_name], check=True)
        logger.info("Deleted remote tag: %s", tag_name)

        # Delete local tag (best effort)
        run_command(["git", "tag", "-d", tag_name], check=False)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to delete tag %s: %s", tag_name, exc)
        return False


def cleanup_prereleases(
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    dry_run: bool = False
) -> CleanupResult:
    """
    Clean up pre-release tags and GitHub releases older than max_age_days.

    Args:
        max_age_days: Delete pre-releases older than this many days.
        dry_run: If True, only log what would be deleted without actually deleting.

    Returns:
        CleanupResult with summary of actions taken.
    """
    result = CleanupResult(dry_run=dry_run)
    stale = build_prerelease_inventory(max_age_days)

    if not stale:
        logger.info("No stale pre-releases found. Nothing to clean up.")
        return result

    mode = "DRY RUN" if dry_run else "CLEANUP"
    logger.info("=== %s: %d stale pre-releases ===", mode, len(stale))

    for tag_info in stale:
        logger.info(
            "  %s (age: %d days, release: %s)",
            tag_info.tag_name,
            tag_info.age_days,
            "yes" if tag_info.has_release else "no"
        )

    if dry_run:
        result.tags_deleted = [t.tag_name for t in stale]
        result.releases_deleted = [t.tag_name for t in stale if t.has_release]
        return result

    # Delete releases first (they reference the tag)
    for tag_info in stale:
        if tag_info.has_release:
            if delete_github_release(tag_info.tag_name):
                result.releases_deleted.append(tag_info.tag_name)
            else:
                result.releases_failed.append(tag_info.tag_name)

    # Then delete tags
    for tag_info in stale:
        if delete_git_tag(tag_info.tag_name):
            result.tags_deleted.append(tag_info.tag_name)
        else:
            result.tags_failed.append(tag_info.tag_name)

    logger.info("=== Cleanup Complete ===")
    logger.info(
        "Tags deleted: %d, Releases deleted: %d",
        len(result.tags_deleted), len(result.releases_deleted)
    )
    if result.tags_failed or result.releases_failed:
        logger.warning(
            "Failures - Tags: %d, Releases: %d",
            len(result.tags_failed), len(result.releases_failed)
        )

    return result


def main() -> None:
    """CLI entrypoint for pre-release cleanup."""
    parser = argparse.ArgumentParser(
        description="Clean up old pre-release tags and GitHub releases."
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"Delete pre-releases older than this many days (default: {DEFAULT_MAX_AGE_DAYS})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show what would be deleted without actually deleting"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    result = cleanup_prereleases(
        max_age_days=args.max_age_days,
        dry_run=args.dry_run
    )

    if result.tags_failed or result.releases_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
