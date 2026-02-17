"""
Tests for the react_proxy module - downloading and serving the React UI.
"""
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import requests

from lanscape.ui.react_proxy.manager import WebappManager, WebappInfo
from lanscape.ui.react_proxy.version_compat import (
    VersionRange,
    parse_version,
    compare_versions,
    is_version_compatible,
    SUPPORTED_UI_VERSIONS
)


@pytest.fixture
def temp_cache_dir():
    """Create a temporary directory for webapp cache."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    # Cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def manager(temp_cache_dir):
    """Create a WebappManager with a temporary cache directory."""
    return WebappManager(cache_dir=temp_cache_dir)


@pytest.fixture
def mock_release_response():
    """Mock GitHub release API response."""
    return {
        'tag_name': 'releases/1.0.0',
        'name': 'LANscape v1.0.0',
        'assets': [
            {
                'name': 'webapp-dist.zip',
                'browser_download_url': 'https://example.com/webapp-dist.zip'
            },
            {
                'name': 'LANscape-Setup.exe',
                'browser_download_url': 'https://example.com/setup.exe'
            }
        ]
    }


class TestWebappManager:
    """Tests for WebappManager class."""

    def test_init_default_cache_dir(self):
        """Test default cache directory is set correctly."""
        manager = WebappManager()
        expected = Path.home() / '.lanscape' / 'webapp'
        assert manager.cache_dir == expected

    def test_init_custom_cache_dir(self, temp_cache_dir):
        """Test custom cache directory is used."""
        manager = WebappManager(cache_dir=temp_cache_dir)
        assert manager.cache_dir == temp_cache_dir

    def test_get_webapp_dir(self, manager, temp_cache_dir):
        """Test webapp directory path."""
        assert manager.get_webapp_dir() == temp_cache_dir / 'dist'

    def test_is_cached_empty(self, manager):
        """Test is_cached returns False when no cache exists."""
        assert manager.is_cached() is False

    def test_is_cached_with_files(self, manager, temp_cache_dir):
        """Test is_cached returns True when cache exists."""
        # Create cache structure
        (temp_cache_dir / 'dist').mkdir(parents=True)
        (temp_cache_dir / 'version.json').write_text('{"version": "1.0.0"}')

        assert manager.is_cached() is True

    def test_get_cached_version_none(self, manager):
        """Test get_cached_version returns None when no version file."""
        assert manager.get_cached_version() is None

    def test_get_cached_version_exists(self, manager, temp_cache_dir):
        """Test get_cached_version returns version from file."""
        temp_cache_dir.mkdir(parents=True, exist_ok=True)
        version_file = temp_cache_dir / 'version.json'
        version_file.write_text('{"version": "1.2.3"}')

        assert manager.get_cached_version() == '1.2.3'

    def test_get_cached_version_invalid_json(self, manager, temp_cache_dir):
        """Test get_cached_version handles invalid JSON."""
        temp_cache_dir.mkdir(parents=True, exist_ok=True)
        version_file = temp_cache_dir / 'version.json'
        version_file.write_text('not valid json')

        assert manager.get_cached_version() is None

    @patch('lanscape.ui.react_proxy.manager.requests.get')
    def test_get_latest_release_info_success(self, mock_get, manager, mock_release_response):
        """Test fetching latest release info from GitHub."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_release_response
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = manager.get_latest_release_info()

        assert result is not None
        assert result['version'] == '1.0.0'
        assert result['download_url'] == 'https://example.com/webapp-dist.zip'
        assert result['tag_name'] == 'releases/1.0.0'

    @patch('lanscape.ui.react_proxy.manager.requests.get')
    def test_get_latest_release_info_no_webapp_asset(self, mock_get, manager):
        """Test handling release without webapp-dist.zip."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'tag_name': 'releases/1.0.0',
            'assets': [
                {'name': 'other-file.zip',
                    'browser_download_url': 'https://example.com/other.zip'}
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = manager.get_latest_release_info()

        assert result is None

    @patch('lanscape.ui.react_proxy.manager.requests.get')
    def test_get_latest_release_info_network_error(self, mock_get, manager):
        """Test handling network errors."""
        mock_get.side_effect = requests.RequestException('Network error')

        result = manager.get_latest_release_info()

        assert result is None

    @patch.object(WebappManager, 'get_cached_version', return_value=None)
    def test_is_update_available_no_cache(self, _mock_version, manager):
        """Test update available when no cache exists."""
        assert manager.is_update_available() is True

    @patch.object(WebappManager, 'get_cached_version', return_value='1.0.0')
    @patch.object(WebappManager, 'get_compatible_release_info', return_value={'version': '1.1.0'})
    @patch('lanscape.ui.react_proxy.manager.is_version_compatible', return_value=True)
    def test_is_update_available_newer_version(
            self, _mock_compat, _mock_latest, _mock_cached, manager):
        """Test update available when newer version exists."""
        assert manager.is_update_available() is True

    @patch.object(WebappManager, 'get_cached_version', return_value='1.0.0')
    @patch.object(WebappManager, 'get_compatible_release_info', return_value={'version': '1.0.0'})
    @patch('lanscape.ui.react_proxy.manager.is_version_compatible', return_value=True)
    def test_is_update_available_current(self, _mock_compat, _mock_latest, _mock_cached, manager):
        """Test no update when version is current."""
        assert manager.is_update_available() is False

    @patch.object(WebappManager, 'get_cached_version', return_value='1.0.0')
    @patch.object(WebappManager, 'get_compatible_release_info', return_value=None)
    @patch('lanscape.ui.react_proxy.manager.is_version_compatible', return_value=True)
    def test_is_update_available_check_fails(
            self, _mock_compat, _mock_latest, _mock_cached, manager):
        """Test no update when version check fails."""
        assert manager.is_update_available() is False

    def test_get_info_no_cache(self, manager):
        """Test get_info returns None when no cache."""
        assert manager.get_info() is None

    @patch.object(WebappManager, 'is_update_available', return_value=False)
    def test_get_info_with_cache(self, _mock_update, manager, temp_cache_dir):
        """Test get_info returns WebappInfo when cached."""
        # Create cache
        (temp_cache_dir / 'dist').mkdir(parents=True)
        (temp_cache_dir / 'version.json').write_text('{"version": "1.0.0"}')

        info = manager.get_info()

        assert info is not None
        assert isinstance(info, WebappInfo)
        assert info.version == '1.0.0'
        assert info.is_current is True

    def test_clear_cache(self, manager, temp_cache_dir):
        """Test clearing the cache."""
        # Create cache
        (temp_cache_dir / 'dist').mkdir(parents=True)
        (temp_cache_dir / 'version.json').write_text('{"version": "1.0.0"}')

        manager.clear_cache()

        assert not temp_cache_dir.exists()


class TestWebappManagerDownload:
    """Tests for WebappManager download functionality."""

    @patch.object(WebappManager, 'is_cached', return_value=True)
    @patch.object(WebappManager, 'is_update_available', return_value=False)
    def test_download_skipped_when_current(self, _mock_update, _mock_cached, manager):
        """Test download is skipped when cache is current."""
        result = manager.download_webapp(force=False)
        assert result is True

    @patch.object(WebappManager, 'get_compatible_release_info', return_value=None)
    def test_download_fails_no_release_info(self, _mock_release, manager):
        """Test download fails when release info unavailable."""
        result = manager.download_webapp(force=True)
        assert result is False


class TestVersionCompatibility:
    """Tests for version compatibility checking."""

    def test_parse_version_basic(self):
        """Test parsing basic semver version."""
        result = parse_version('1.2.3')
        assert result == (1, 2, 3, '')

    def test_parse_version_with_v_prefix(self):
        """Test parsing version with v prefix."""
        result = parse_version('v1.2.3')
        assert result == (1, 2, 3, '')

    def test_parse_version_with_releases_prefix(self):
        """Test parsing version with releases/ prefix."""
        result = parse_version('releases/1.2.3')
        assert result == (1, 2, 3, '')

    def test_parse_version_prerelease(self):
        """Test parsing prerelease version."""
        result = parse_version('1.2.3-beta.1')
        assert result == (1, 2, 3, 'beta.1')

    def test_parse_version_two_parts(self):
        """Test parsing major.minor version."""
        result = parse_version('1.2')
        assert result == (1, 2, 0, '')

    def test_parse_version_invalid(self):
        """Test parsing invalid version."""
        result = parse_version('not-a-version')
        assert result is None

    def test_compare_versions_equal(self):
        """Test comparing equal versions."""
        v1 = parse_version('1.2.3')
        v2 = parse_version('1.2.3')
        assert compare_versions(v1, v2) == 0

    def test_compare_versions_greater_major(self):
        """Test comparing versions with different major."""
        v1 = parse_version('2.0.0')
        v2 = parse_version('1.0.0')
        assert compare_versions(v1, v2) == 1

    def test_compare_versions_less_minor(self):
        """Test comparing versions with different minor."""
        v1 = parse_version('1.1.0')
        v2 = parse_version('1.2.0')
        assert compare_versions(v1, v2) == -1

    def test_compare_versions_prerelease_less_than_release(self):
        """Test that prerelease is less than release."""
        v1 = parse_version('1.0.0-beta')
        v2 = parse_version('1.0.0')
        assert compare_versions(v1, v2) == -1

    def test_version_range_contains(self):
        """Test VersionRange.contains method."""
        range_obj = VersionRange(min_version='1.0.0', max_version='2.0.0')
        assert range_obj.contains('1.0.0') is True
        assert range_obj.contains('1.5.0') is True
        assert range_obj.contains('2.0.0') is True
        assert range_obj.contains('0.9.0') is False
        assert range_obj.contains('2.1.0') is False

    def test_version_range_no_max(self):
        """Test VersionRange with no upper limit."""
        range_obj = VersionRange(min_version='1.0.0', max_version=None)
        assert range_obj.contains('1.0.0') is True
        assert range_obj.contains('10.0.0') is True
        assert range_obj.contains('0.9.0') is False

    def test_version_range_str(self):
        """Test VersionRange string representation."""
        range_with_max = VersionRange(min_version='1.0.0', max_version='2.0.0')
        assert str(range_with_max) == '>=1.0.0, <=2.0.0'

        range_no_max = VersionRange(min_version='1.0.0')
        assert str(range_no_max) == '>=1.0.0'

    def test_is_version_compatible_uses_supported_versions(self):
        """Test is_version_compatible uses SUPPORTED_UI_VERSIONS."""
        # This should use the actual SUPPORTED_UI_VERSIONS constant
        min_version = SUPPORTED_UI_VERSIONS.min_version
        assert is_version_compatible(min_version) is True

    def test_supported_versions_constant_exists(self):
        """Test that SUPPORTED_UI_VERSIONS is properly defined."""
        assert SUPPORTED_UI_VERSIONS is not None
        assert hasattr(SUPPORTED_UI_VERSIONS, 'min_version')
        assert hasattr(SUPPORTED_UI_VERSIONS, 'max_version')
