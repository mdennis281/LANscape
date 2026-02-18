"""
Webapp Manager - Handles downloading, caching, and updating the React webapp build.

Supports version compatibility checking to ensure the downloaded webapp
is compatible with this version of the Python backend.
"""

import json
import logging
import shutil
import zipfile
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass

import requests

from lanscape.ui.react_proxy.version_compat import (
    SUPPORTED_UI_VERSIONS,
    parse_version,
    is_version_compatible
)

log = logging.getLogger('WebappManager')

GITHUB_REPO = 'mdennis281/lanscape-ui'
GITHUB_API_URL = f'https://api.github.com/repos/{GITHUB_REPO}/releases'
GITHUB_LATEST_URL = f'https://api.github.com/repos/{GITHUB_REPO}/releases/latest'
WEBAPP_ASSET_NAME = 'webapp-dist.zip'


@dataclass
class WebappInfo:
    """Information about the cached webapp."""
    version: str
    path: Path
    is_current: bool


class WebappManager:
    """
    Manages the React webapp distribution.

    Downloads the webapp build from GitHub releases and caches it locally.
    Automatically checks for updates and re-downloads when a new version is available.
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the WebappManager.

        Args:
            cache_dir: Directory to store cached webapp. Defaults to ~/.lanscape/webapp/
        """
        if cache_dir is None:
            cache_dir = Path.home() / '.lanscape' / 'webapp'
        self.cache_dir = cache_dir
        self.webapp_dir = cache_dir / 'dist'
        self.version_file = cache_dir / 'version.json'

    def get_cache_dir(self) -> Path:
        """Get the webapp cache directory path."""
        return self.cache_dir

    def get_webapp_dir(self) -> Path:
        """Get the directory containing the webapp static files."""
        return self.webapp_dir

    def is_cached(self) -> bool:
        """Check if a webapp build is cached locally."""
        return self.webapp_dir.exists() and self.version_file.exists()

    def get_cached_version(self) -> Optional[str]:
        """Get the version of the cached webapp, if any."""
        if not self.version_file.exists():
            return None
        try:
            with open(self.version_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('version')
        except (json.JSONDecodeError, IOError):
            return None

    def _fetch_all_releases(self) -> List[dict]:
        """
        Fetch all releases from GitHub.

        Returns:
            List of release data dictionaries.
        """
        try:
            response = requests.get(GITHUB_API_URL, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            log.warning(f'Failed to fetch releases: {e}')
            return []

    def _parse_release_info(self, release_data: dict) -> Optional[dict]:
        """
        Parse release data into a standardized format.

        Args:
            release_data: Raw release data from GitHub API.

        Returns:
            Dictionary with version info, or None if invalid/missing webapp asset.
        """
        tag_name = release_data.get('tag_name', '')
        # Clean up version string (remove tag prefixes)
        version = tag_name
        for prefix in ('releases/', 'pre-releases/', 'webapp/'):
            version = version.replace(prefix, '')

        # Find the webapp-dist.zip asset
        for asset in release_data.get('assets', []):
            if asset['name'] == WEBAPP_ASSET_NAME:
                return {
                    'version': version,
                    'download_url': asset['browser_download_url'],
                    'tag_name': tag_name
                }

        return None

    def get_compatible_release_info(self) -> Optional[dict]:
        """
        Fetch the latest compatible release info from GitHub.

        Searches through releases to find the newest version that falls
        within the supported version range for this backend.

        Returns:
            Dictionary with 'version' and 'download_url' keys, or None if none found.
        """
        releases = self._fetch_all_releases()
        if not releases:
            return None

        compatible_releases = []

        for release_data in releases:
            release_info = self._parse_release_info(release_data)
            if release_info is None:
                continue

            if is_version_compatible(release_info['version']):
                parsed = parse_version(release_info['version'])
                if parsed:
                    compatible_releases.append((parsed, release_info))

        if not compatible_releases:
            log.warning(
                f'No compatible webapp releases found. '
                f'Required: {SUPPORTED_UI_VERSIONS}'
            )
            return None

        # Sort by version (descending) to get the latest compatible
        compatible_releases.sort(key=lambda x: x[0], reverse=True)

        # Use custom comparison for proper sorting
        compatible_releases.sort(
            key=lambda x: x[0][:3],  # Sort by major, minor, patch
            reverse=True
        )

        latest_compatible = compatible_releases[0][1]
        log.debug(f'Found compatible webapp version: {latest_compatible["version"]}')
        return latest_compatible

    def get_latest_release_info(self) -> Optional[dict]:
        """
        Fetch the latest release info from GitHub.

        Returns:
            Dictionary with 'version' and 'download_url' keys, or None if fetch fails.
        """
        try:
            response = requests.get(GITHUB_LATEST_URL, timeout=10)
            response.raise_for_status()
            data = response.json()

            tag_name = data.get('tag_name', '')
            # Clean up version string (remove tag prefixes)
            version = tag_name
            for prefix in ('releases/', 'pre-releases/', 'webapp/'):
                version = version.replace(prefix, '')

            # Find the webapp-dist.zip asset
            for asset in data.get('assets', []):
                if asset['name'] == WEBAPP_ASSET_NAME:
                    return {
                        'version': version,
                        'download_url': asset['browser_download_url'],
                        'tag_name': tag_name
                    }

            log.warning(f'No {WEBAPP_ASSET_NAME} found in latest release')
            return None

        except requests.RequestException as e:
            log.warning(f'Failed to fetch latest release info: {e}')
            return None

    def is_update_available(self) -> bool:
        """Check if a newer compatible version of the webapp is available."""
        cached_version = self.get_cached_version()
        if cached_version is None:
            return True  # No cache means we need to download

        # First check if current cache is even compatible
        if not is_version_compatible(cached_version):
            return True  # Need to get a compatible version

        latest = self.get_compatible_release_info()
        if latest is None:
            return False  # Can't check, assume current is fine

        return cached_version != latest['version']

    def download_webapp(self, force: bool = False) -> bool:
        """
        Download the webapp build from GitHub releases.

        Downloads the latest compatible version based on SUPPORTED_UI_VERSIONS.

        Args:
            force: If True, download even if cached version is current.

        Returns:
            True if download was successful, False otherwise.
        """
        if not force and self.is_cached() and not self.is_update_available():
            log.info('Webapp is already up to date')
            return True

        release_info = self.get_compatible_release_info()
        if release_info is None:
            log.error(
                f'Could not find compatible webapp release. '
                f'Required: {SUPPORTED_UI_VERSIONS}'
            )
            return False

        log.info(f'Downloading webapp v{release_info["version"]}...')

        try:
            # Download the zip file
            response = requests.get(release_info['download_url'], timeout=60, stream=True)
            response.raise_for_status()

            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            zip_path = self.cache_dir / WEBAPP_ASSET_NAME

            # Write zip file
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Clear old webapp directory
            if self.webapp_dir.exists():
                shutil.rmtree(self.webapp_dir)

            # Extract zip
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.webapp_dir)

            # Clean up zip file
            zip_path.unlink()

            # Save version info
            with open(self.version_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'version': release_info['version'],
                    'tag_name': release_info['tag_name']
                }, f)

            log.info(f'Webapp v{release_info["version"]} downloaded successfully')
            return True

        except requests.RequestException as e:
            log.error(f'Failed to download webapp: {e}')
            return False
        except (zipfile.BadZipFile, IOError) as e:
            log.error(f'Failed to extract webapp: {e}')
            return False

    def ensure_webapp(self) -> Optional[Path]:
        """
        Ensure the webapp is available, downloading if necessary.

        Returns:
            Path to the webapp directory, or None if unavailable.
        """
        if self.is_cached():
            # Check for updates in background but use cached version
            if self.is_update_available():
                log.info('Webapp update available, downloading...')
                self.download_webapp()
            return self.webapp_dir

        # No cache, must download
        if self.download_webapp():
            return self.webapp_dir

        return None

    def get_info(self) -> Optional[WebappInfo]:
        """Get information about the current webapp state."""
        if not self.is_cached():
            return None

        return WebappInfo(
            version=self.get_cached_version() or 'unknown',
            path=self.webapp_dir,
            is_current=not self.is_update_available()
        )

    def clear_cache(self) -> None:
        """Remove the cached webapp."""
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            log.info('Webapp cache cleared')
