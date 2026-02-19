"""
Tests for lanscape.core.version_manager

Covers PEP 440 prerelease-aware update detection, PyPI look-ups,
and the installed-version helper.
"""

from unittest.mock import patch, MagicMock
from importlib.metadata import PackageNotFoundError

import pytest

from lanscape.core.version_manager import (
    is_update_available,
    lookup_latest_version,
    get_latest_version,
    get_installed_version,
    LOCAL_VERSION,
    _fetch_pypi_data,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pypi_data(stable_version: str, all_versions: list[str]) -> dict:
    """Build a minimal PyPI JSON response dict."""
    return {
        'info': {'version': stable_version},
        'releases': {v: [] for v in all_versions},
    }


@pytest.fixture(autouse=True)
def _reset_run_once_cache():
    """Clear the @run_once cache on _fetch_pypi_data between tests."""
    # pylint: disable=protected-access
    _fetch_pypi_data._run_once_ran = False
    _fetch_pypi_data._run_once_cache = None
    yield
    _fetch_pypi_data._run_once_ran = False
    _fetch_pypi_data._run_once_cache = None


# ---------------------------------------------------------------------------
# is_update_available
# ---------------------------------------------------------------------------

class TestIsUpdateAvailable:  # pylint: disable=missing-function-docstring
    """Tests for the is_update_available function."""

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_local_version_always_exempt(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = LOCAL_VERSION
        mock_fetch.return_value = _pypi_data('9.9.9', ['9.9.9'])
        assert is_update_available() is False

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_stable_same_version(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '2.9.0'
        mock_fetch.return_value = _pypi_data('2.9.0', ['2.9.0'])
        assert is_update_available() is False

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_stable_newer_stable_available(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '2.9.0'
        mock_fetch.return_value = _pypi_data('3.0.0', ['2.9.0', '3.0.0'])
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_stable_ignores_prereleases(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        """A stable user should NOT be prompted to install a prerelease."""
        mock_installed.return_value = '2.9.0'
        mock_fetch.return_value = _pypi_data('2.9.0', ['2.9.0', '3.0.0a1'])
        assert is_update_available() is False

    # -- Alpha channel --

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_alpha_higher_alpha_shows_update(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0a14'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a14', '3.0.0a15']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_alpha_same_alpha_no_update(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0a14'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a14']
        )
        assert is_update_available() is False

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_alpha_promoted_to_beta(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0a14'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a14', '3.0.0b1']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_alpha_promoted_to_stable(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0a14'
        mock_fetch.return_value = _pypi_data(
            '3.0.0', ['2.9.0', '3.0.0a14', '3.0.0']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_alpha_newer_base_version(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        """3.0.0a5 → 3.1.5 should show update."""
        mock_installed.return_value = '3.0.0a5'
        mock_fetch.return_value = _pypi_data(
            '3.1.5', ['2.9.0', '3.0.0a5', '3.1.5']
        )
        assert is_update_available() is True

    # -- Beta channel --

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_beta_higher_beta_shows_update(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0b2'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0b2', '3.0.0b5']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_beta_does_not_see_alpha(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        """Beta user should NOT be prompted to install an alpha."""
        mock_installed.return_value = '3.0.0b2'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a20', '3.0.0b2']
        )
        assert is_update_available() is False

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_beta_promoted_to_rc(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0b2'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0b2', '3.0.0rc1']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_beta_promoted_to_stable(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0b2'
        mock_fetch.return_value = _pypi_data(
            '3.0.0', ['2.9.0', '3.0.0b2', '3.0.0']
        )
        assert is_update_available() is True

    # -- RC channel --

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_rc_promoted_to_stable(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0rc1'
        mock_fetch.return_value = _pypi_data(
            '3.0.0', ['2.9.0', '3.0.0rc1', '3.0.0']
        )
        assert is_update_available() is True

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_rc_no_update_for_beta(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0rc1'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0b5', '3.0.0rc1']
        )
        assert is_update_available() is False

    # -- Edge cases --

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_pypi_unreachable(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '2.9.0'
        mock_fetch.return_value = None
        assert is_update_available() is False

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_invalid_installed_version(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = 'not-a-version'
        mock_fetch.return_value = _pypi_data('1.0.0', ['1.0.0'])
        assert is_update_available() is False


# ---------------------------------------------------------------------------
# lookup_latest_version
# ---------------------------------------------------------------------------

class TestLookupLatestVersion:  # pylint: disable=missing-function-docstring
    """Tests for the lookup_latest_version function."""

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_stable_only(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a1', '3.0.0b1']
        )
        assert lookup_latest_version() == '2.9.0'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_include_prerelease_finds_latest(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a14', '3.0.0b1']
        )
        assert lookup_latest_version(include_prerelease=True) == '3.0.0b1'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_include_prerelease_stable_is_latest(self, mock_fetch: MagicMock) -> None:
        """When the stable release is the highest, it wins even with include_prerelease."""
        mock_fetch.return_value = _pypi_data(
            '3.0.0', ['2.9.0', '3.0.0a14', '3.0.0']
        )
        assert lookup_latest_version(include_prerelease=True) == '3.0.0'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_pypi_unreachable(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = None
        assert lookup_latest_version() is None

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_skips_dev_releases(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0.dev1', '3.0.0a1']
        )
        # dev releases should be skipped; 3.0.0a1 is the latest pre-release
        assert lookup_latest_version(include_prerelease=True) == '3.0.0a1'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    def test_empty_releases(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = _pypi_data('2.9.0', [])
        assert lookup_latest_version(include_prerelease=True) is None


# ---------------------------------------------------------------------------
# get_latest_version
# ---------------------------------------------------------------------------

class TestGetLatestVersion:  # pylint: disable=missing-function-docstring
    """Tests for the get_latest_version convenience function."""

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_stable_installed_returns_stable(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '2.9.0'
        mock_fetch.return_value = _pypi_data(
            '3.0.0', ['2.9.0', '3.0.0', '3.1.0a1']
        )
        assert get_latest_version() == '3.0.0'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_prerelease_installed_includes_prerelease(
        self, mock_installed: MagicMock, mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = '3.0.0a14'
        mock_fetch.return_value = _pypi_data(
            '2.9.0', ['2.9.0', '3.0.0a14', '3.0.0a16']
        )
        assert get_latest_version() == '3.0.0a16'

    @patch('lanscape.core.version_manager._fetch_pypi_data')
    @patch('lanscape.core.version_manager.get_installed_version')
    def test_local_version_returns_none(
        self, mock_installed: MagicMock, _mock_fetch: MagicMock
    ) -> None:
        mock_installed.return_value = LOCAL_VERSION
        assert get_latest_version() is None


# ---------------------------------------------------------------------------
# get_installed_version
# ---------------------------------------------------------------------------

class TestGetInstalledVersion:  # pylint: disable=missing-function-docstring
    """Tests for the get_installed_version function."""

    @patch('lanscape.core.version_manager.is_local_run', return_value=True)
    def test_local_run_returns_local_version(self, _mock: MagicMock) -> None:
        assert get_installed_version() == LOCAL_VERSION

    @patch('lanscape.core.version_manager.version', side_effect=PackageNotFoundError)
    @patch('lanscape.core.version_manager.is_local_run', return_value=False)
    def test_package_not_found_returns_local(
        self, _mock_local: MagicMock, _mock_version: MagicMock
    ) -> None:
        assert get_installed_version() == LOCAL_VERSION

    @patch('lanscape.core.version_manager.version', return_value='1.2.3')
    @patch('lanscape.core.version_manager.is_local_run', return_value=False)
    def test_returns_installed_version(
        self, _mock_local: MagicMock, _mock_version: MagicMock
    ) -> None:
        assert get_installed_version() == '1.2.3'
