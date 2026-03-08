"""
Tests for scripts.cleanup_prereleases

Covers tag inventory building, release detection, cleanup logic,
and CLI argument parsing. All subprocess/gh calls are mocked.
"""

import subprocess
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import json

from scripts.cleanup_prereleases import (
    get_prerelease_tags,
    get_tag_commit_date,
    get_github_releases,
    build_prerelease_inventory,
    delete_github_release,
    delete_git_tag,
    cleanup_prereleases,
    PreReleaseTag,
    CleanupResult,
    DEFAULT_MAX_AGE_DAYS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 3, 8, 12, 0, 0, tzinfo=timezone.utc)


def _days_ago(days: int) -> datetime:
    """Return a datetime `days` days before NOW."""
    return NOW - timedelta(days=days)


def _iso(dt: datetime) -> str:
    """Format datetime as ISO 8601 string."""
    return dt.isoformat()


def _mock_run(stdout: str = "", returncode: int = 0) -> MagicMock:
    """Build a mock CompletedProcess."""
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


# ---------------------------------------------------------------------------
# get_prerelease_tags
# ---------------------------------------------------------------------------

class TestGetPrereleaseTags:  # pylint: disable=missing-function-docstring
    """Tests for fetching pre-release tags from git."""

    @patch("scripts.cleanup_prereleases.run_command")
    def test_returns_tags(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run(
            "pre-releases/1.0.0a1\npre-releases/1.0.0b1\npre-releases/1.0.0rc1\n"
        )
        tags = get_prerelease_tags()
        assert tags == [
            "pre-releases/1.0.0a1",
            "pre-releases/1.0.0b1",
            "pre-releases/1.0.0rc1",
        ]

    @patch("scripts.cleanup_prereleases.run_command")
    def test_empty_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run("")
        assert get_prerelease_tags() == []

    @patch("scripts.cleanup_prereleases.run_command")
    def test_strips_whitespace(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run("  pre-releases/2.0.0a1  \n\n")
        assert get_prerelease_tags() == ["pre-releases/2.0.0a1"]


# ---------------------------------------------------------------------------
# get_tag_commit_date
# ---------------------------------------------------------------------------

class TestGetTagCommitDate:  # pylint: disable=missing-function-docstring
    """Tests for retrieving commit dates from tags."""

    @patch("scripts.cleanup_prereleases.run_command")
    def test_valid_date(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run("2025-12-01T10:00:00+00:00")
        result = get_tag_commit_date("pre-releases/1.0.0a1")
        assert result == datetime(2025, 12, 1, 10, 0, 0, tzinfo=timezone.utc)

    @patch("scripts.cleanup_prereleases.run_command")
    def test_empty_output_returns_none(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run("")
        assert get_tag_commit_date("pre-releases/1.0.0a1") is None

    @patch("scripts.cleanup_prereleases.run_command")
    def test_command_failure_returns_none(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        assert get_tag_commit_date("pre-releases/bad") is None


# ---------------------------------------------------------------------------
# get_github_releases
# ---------------------------------------------------------------------------

class TestGetGithubReleases:  # pylint: disable=missing-function-docstring
    """Tests for listing GitHub pre-releases via gh CLI."""

    @patch("scripts.cleanup_prereleases.run_command")
    def test_returns_prerelease_tags(self, mock_run: MagicMock) -> None:
        releases_json = json.dumps([
            {"tagName": "pre-releases/1.0.0rc1", "isPrerelease": True},
            {"tagName": "releases/1.0.0", "isPrerelease": False},
            {"tagName": "pre-releases/1.0.0a1", "isPrerelease": True},
        ])
        mock_run.return_value = _mock_run(releases_json)
        result = get_github_releases()
        assert "pre-releases/1.0.0rc1" in result
        assert "pre-releases/1.0.0a1" in result
        assert "releases/1.0.0" not in result

    @patch("scripts.cleanup_prereleases.run_command")
    def test_excludes_non_prerelease(self, mock_run: MagicMock) -> None:
        releases_json = json.dumps([
            {"tagName": "pre-releases/1.0.0b1", "isPrerelease": False},
        ])
        mock_run.return_value = _mock_run(releases_json)
        result = get_github_releases()
        assert len(result) == 0

    @patch("scripts.cleanup_prereleases.run_command")
    def test_command_failure_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh")
        assert not get_github_releases()

    @patch("scripts.cleanup_prereleases.run_command")
    def test_invalid_json_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run("not json")
        assert not get_github_releases()


# ---------------------------------------------------------------------------
# build_prerelease_inventory
# ---------------------------------------------------------------------------

class TestBuildPreReleaseInventory:  # pylint: disable=missing-function-docstring
    """Tests for building the stale pre-release inventory."""

    @patch("scripts.cleanup_prereleases.datetime")
    @patch("scripts.cleanup_prereleases.get_github_releases")
    @patch("scripts.cleanup_prereleases.get_tag_commit_date")
    @patch("scripts.cleanup_prereleases.get_prerelease_tags")
    def test_filters_by_age(
        self,
        mock_tags: MagicMock,
        mock_date: MagicMock,
        mock_releases: MagicMock,
        mock_dt: MagicMock,
    ) -> None:
        mock_dt.now.return_value = NOW
        mock_tags.return_value = [
            "pre-releases/1.0.0a1",  # old
            "pre-releases/2.0.0a1",  # recent
        ]
        mock_date.side_effect = [
            _days_ago(100),  # old
            _days_ago(10),   # recent
        ]
        mock_releases.return_value = {}

        result = build_prerelease_inventory(max_age_days=90)
        assert len(result) == 1
        assert result[0].tag_name == "pre-releases/1.0.0a1"

    @patch("scripts.cleanup_prereleases.datetime")
    @patch("scripts.cleanup_prereleases.get_github_releases")
    @patch("scripts.cleanup_prereleases.get_tag_commit_date")
    @patch("scripts.cleanup_prereleases.get_prerelease_tags")
    def test_marks_has_release(
        self,
        mock_tags: MagicMock,
        mock_date: MagicMock,
        mock_releases: MagicMock,
        mock_dt: MagicMock,
    ) -> None:
        mock_dt.now.return_value = NOW
        mock_tags.return_value = ["pre-releases/1.0.0rc1"]
        mock_date.return_value = _days_ago(120)
        mock_releases.return_value = {"pre-releases/1.0.0rc1": "pre-releases/1.0.0rc1"}

        result = build_prerelease_inventory(max_age_days=90)
        assert len(result) == 1
        assert result[0].has_release is True

    @patch("scripts.cleanup_prereleases.datetime")
    @patch("scripts.cleanup_prereleases.get_github_releases")
    @patch("scripts.cleanup_prereleases.get_tag_commit_date")
    @patch("scripts.cleanup_prereleases.get_prerelease_tags")
    def test_skips_tags_with_no_date(
        self,
        mock_tags: MagicMock,
        mock_date: MagicMock,
        mock_releases: MagicMock,
        mock_dt: MagicMock,
    ) -> None:
        mock_dt.now.return_value = NOW
        mock_tags.return_value = ["pre-releases/1.0.0a1"]
        mock_date.return_value = None
        mock_releases.return_value = {}

        result = build_prerelease_inventory(max_age_days=90)
        assert len(result) == 0

    @patch("scripts.cleanup_prereleases.datetime")
    @patch("scripts.cleanup_prereleases.get_github_releases")
    @patch("scripts.cleanup_prereleases.get_tag_commit_date")
    @patch("scripts.cleanup_prereleases.get_prerelease_tags")
    def test_sorted_oldest_first(
        self,
        mock_tags: MagicMock,
        mock_date: MagicMock,
        mock_releases: MagicMock,
        mock_dt: MagicMock,
    ) -> None:
        mock_dt.now.return_value = NOW
        mock_tags.return_value = [
            "pre-releases/1.0.0a1",
            "pre-releases/1.0.0b1",
        ]
        mock_date.side_effect = [
            _days_ago(100),
            _days_ago(200),
        ]
        mock_releases.return_value = {}

        result = build_prerelease_inventory(max_age_days=90)
        assert len(result) == 2
        assert result[0].tag_name == "pre-releases/1.0.0b1"  # older first
        assert result[1].tag_name == "pre-releases/1.0.0a1"


# ---------------------------------------------------------------------------
# delete_github_release
# ---------------------------------------------------------------------------

class TestDeleteGithubRelease:  # pylint: disable=missing-function-docstring
    """Tests for deleting a GitHub release."""

    @patch("scripts.cleanup_prereleases.run_command")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run()
        assert delete_github_release("pre-releases/1.0.0rc1") is True

    @patch("scripts.cleanup_prereleases.run_command")
    def test_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh")
        assert delete_github_release("pre-releases/1.0.0rc1") is False


# ---------------------------------------------------------------------------
# delete_git_tag
# ---------------------------------------------------------------------------

class TestDeleteGitTag:  # pylint: disable=missing-function-docstring
    """Tests for deleting git tags."""

    @patch("scripts.cleanup_prereleases.run_command")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _mock_run()
        assert delete_git_tag("pre-releases/1.0.0a1") is True
        # Should call push --delete and tag -d
        assert mock_run.call_count == 2

    @patch("scripts.cleanup_prereleases.run_command")
    def test_remote_delete_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        assert delete_git_tag("pre-releases/1.0.0a1") is False


# ---------------------------------------------------------------------------
# cleanup_prereleases (integration-level with mocked inventory)
# ---------------------------------------------------------------------------

class TestCleanupPrereleases:  # pylint: disable=missing-function-docstring
    """Tests for the main cleanup orchestration."""

    @patch("scripts.cleanup_prereleases.delete_git_tag")
    @patch("scripts.cleanup_prereleases.delete_github_release")
    @patch("scripts.cleanup_prereleases.build_prerelease_inventory")
    def test_deletes_tags_and_releases(
        self,
        mock_inventory: MagicMock,
        mock_del_release: MagicMock,
        mock_del_tag: MagicMock,
    ) -> None:
        mock_inventory.return_value = [
            PreReleaseTag(
                tag_name="pre-releases/1.0.0rc1",
                version="1.0.0rc1",
                commit_date=_days_ago(100),
                age_days=100,
                has_release=True,
            ),
            PreReleaseTag(
                tag_name="pre-releases/1.0.0a1",
                version="1.0.0a1",
                commit_date=_days_ago(120),
                age_days=120,
                has_release=False,
            ),
        ]
        mock_del_release.return_value = True
        mock_del_tag.return_value = True

        result = cleanup_prereleases(max_age_days=90)

        assert result.dry_run is False
        assert "pre-releases/1.0.0rc1" in result.releases_deleted
        assert len(result.releases_deleted) == 1
        assert len(result.tags_deleted) == 2
        mock_del_release.assert_called_once_with("pre-releases/1.0.0rc1")

    @patch("scripts.cleanup_prereleases.delete_git_tag")
    @patch("scripts.cleanup_prereleases.delete_github_release")
    @patch("scripts.cleanup_prereleases.build_prerelease_inventory")
    def test_dry_run_does_not_delete(
        self,
        mock_inventory: MagicMock,
        mock_del_release: MagicMock,
        mock_del_tag: MagicMock,
    ) -> None:
        mock_inventory.return_value = [
            PreReleaseTag(
                tag_name="pre-releases/1.0.0a1",
                version="1.0.0a1",
                commit_date=_days_ago(100),
                age_days=100,
                has_release=True,
            ),
        ]

        result = cleanup_prereleases(max_age_days=90, dry_run=True)

        assert result.dry_run is True
        assert len(result.tags_deleted) == 1
        assert len(result.releases_deleted) == 1
        mock_del_release.assert_not_called()
        mock_del_tag.assert_not_called()

    @patch("scripts.cleanup_prereleases.build_prerelease_inventory")
    def test_no_stale_tags(self, mock_inventory: MagicMock) -> None:
        mock_inventory.return_value = []
        result = cleanup_prereleases(max_age_days=90)
        assert not result.tags_deleted
        assert not result.releases_deleted

    @patch("scripts.cleanup_prereleases.delete_git_tag")
    @patch("scripts.cleanup_prereleases.delete_github_release")
    @patch("scripts.cleanup_prereleases.build_prerelease_inventory")
    def test_partial_failure_tracked(
        self,
        mock_inventory: MagicMock,
        mock_del_release: MagicMock,
        mock_del_tag: MagicMock,
    ) -> None:
        mock_inventory.return_value = [
            PreReleaseTag(
                tag_name="pre-releases/1.0.0rc1",
                version="1.0.0rc1",
                commit_date=_days_ago(100),
                age_days=100,
                has_release=True,
            ),
        ]
        mock_del_release.return_value = False  # release deletion fails
        mock_del_tag.return_value = True

        result = cleanup_prereleases(max_age_days=90)

        assert "pre-releases/1.0.0rc1" in result.releases_failed
        assert "pre-releases/1.0.0rc1" in result.tags_deleted


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TestModels:  # pylint: disable=missing-function-docstring
    """Tests for Pydantic model defaults and behavior."""

    def test_prerelease_tag_defaults(self) -> None:
        tag = PreReleaseTag(
            tag_name="pre-releases/1.0.0a1",
            version="1.0.0a1",
            commit_date=NOW,
            age_days=100,
        )
        assert tag.has_release is False

    def test_cleanup_result_defaults(self) -> None:
        result = CleanupResult()
        assert not result.tags_deleted
        assert not result.releases_deleted
        assert not result.tags_failed
        assert not result.releases_failed
        assert result.dry_run is False

    def test_default_max_age_days(self) -> None:
        """Verify the default age threshold is 90 days."""
        assert DEFAULT_MAX_AGE_DAYS == 90
