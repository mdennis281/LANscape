"""
Version compatibility for LANscape React UI.

Defines the supported version range for the React webapp that this
version of the Python backend is compatible with.
"""

from dataclasses import dataclass
from typing import Optional, Tuple
import re


@dataclass
class VersionRange:
    """
    Defines a semver-compatible version range.

    Attributes:
        min_version: Minimum supported version (inclusive)
        max_version: Maximum supported version (inclusive), None means no upper limit
    """
    min_version: str
    max_version: Optional[str] = None

    def contains(self, version: str) -> bool:
        """
        Check if a version falls within this range.

        Args:
            version: Version string to check (e.g., "1.2.3")

        Returns:
            True if version is within range, False otherwise
        """
        parsed = parse_version(version)
        if parsed is None:
            return False

        min_parsed = parse_version(self.min_version)
        if min_parsed is None:
            return False

        if compare_versions(parsed, min_parsed) < 0:
            return False

        if self.max_version is not None:
            max_parsed = parse_version(self.max_version)
            if max_parsed is not None and compare_versions(parsed, max_parsed) > 0:
                return False

        return True

    def __str__(self) -> str:
        if self.max_version:
            return f">={self.min_version}, <={self.max_version}"
        return f">={self.min_version}"


# Supported UI version range for this backend version
# Update these when making breaking API changes
SUPPORTED_UI_VERSIONS = VersionRange(
    min_version="0.1.2",
    max_version=None  # No upper limit - accept all versions >= min
)


def parse_version(version: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Parse a semver version string into components.

    Args:
        version: Version string (e.g., "1.2.3", "1.2.3-beta.1")

    Returns:
        Tuple of (major, minor, patch, prerelease) or None if invalid
    """
    # Handle common prefixes
    version = version.lstrip('v')
    version = version.replace('releases/', '').replace('pre-releases/', '')

    # Match semver pattern: major.minor.patch[-prerelease]
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$', version)
    if not match:
        # Try just major.minor
        match = re.match(r'^(\d+)\.(\d+)$', version)
        if match:
            return (int(match.group(1)), int(match.group(2)), 0, '')
        return None

    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    prerelease = match.group(4) or '' if len(match.groups()) > 3 else ''

    return (major, minor, patch, prerelease)


def compare_versions(v1: Tuple[int, int, int, str], v2: Tuple[int, int, int, str]) -> int:
    """
    Compare two parsed versions.

    Args:
        v1: First version tuple
        v2: Second version tuple

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    # Compare major, minor, patch
    for i in range(3):
        if v1[i] != v2[i]:
            return -1 if v1[i] < v2[i] else 1

    # Compare prerelease (empty string = release, which is greater than any prerelease)
    pre1, pre2 = v1[3], v2[3]
    if pre1 == pre2:
        return 0
    if pre1 == '':
        return 1  # Release > prerelease
    if pre2 == '':
        return -1
    # Both are prereleases, compare lexically
    return -1 if pre1 < pre2 else 1


def is_version_compatible(version: str) -> bool:
    """
    Check if a UI version is compatible with this backend.

    Args:
        version: Version string to check

    Returns:
        True if compatible, False otherwise
    """
    return SUPPORTED_UI_VERSIONS.contains(version)


def get_supported_range() -> VersionRange:
    """Get the supported UI version range."""
    return SUPPORTED_UI_VERSIONS
