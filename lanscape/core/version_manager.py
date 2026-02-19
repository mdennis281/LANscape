"""
Version management module for LANscape.

Handles version checking, update detection, and retrieving package information
from both local installation and PyPI repository.

Uses PEP 440 version ordering via the ``packaging`` library so that
pre-release channels are compared correctly::

    alpha < beta < rc < stable

This means:
- Alpha users see updates to higher alphas, any beta/rc/stable.
- Beta users see updates to higher betas, any rc/stable (never alphas).
- Stable users only see higher stable releases (pre-releases are hidden).
"""

import logging
import traceback
from importlib.metadata import version, PackageNotFoundError
from random import randint

import requests
from packaging.version import Version, InvalidVersion

from lanscape.core.app_scope import is_local_run
from lanscape.core.decorators import run_once

log = logging.getLogger('VersionManager')

PACKAGE = 'lanscape'
LOCAL_VERSION = '0.0.0'


# -- PyPI data fetching (cached for the process lifetime) --

@run_once
def _fetch_pypi_data(package: str = PACKAGE) -> dict | None:
    """
    Fetch the full JSON payload for *package* from PyPI.

    The result is cached by :func:`run_once` so the network call only
    happens once per process.  Downstream helpers pull the fields they
    need from the returned dict.

    Args:
        package: The package name to look up.

    Returns:
        The parsed JSON dict, or ``None`` on any failure.
    """
    no_cache = f'?cachebust={randint(0, 6969)}'
    url = f"https://pypi.org/pypi/{package}/json{no_cache}"
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        return response.json()
    except Exception:
        log.debug(traceback.format_exc())
        log.warning('Unable to fetch package data from PyPI')
        return None


# -- Version look-ups --

def lookup_latest_version(
    package: str = PACKAGE,
    include_prerelease: bool = False
) -> str | None:
    """
    Return the latest version of *package* available on PyPI.

    Args:
        package: The package name to look up.
        include_prerelease: When ``True`` all releases (alpha, beta, rc,
            stable) are considered using PEP 440 ordering.  When ``False``
            only the latest *stable* release is returned.

    Returns:
        A version string, or ``None`` if retrieval fails.
    """
    data = _fetch_pypi_data(package)
    if not data:
        return None

    if not include_prerelease:
        latest = data.get('info', {}).get('version')
        log.debug('Latest stable PyPI version: %s', latest)
        return latest

    # Consider every published release (skip dev releases).
    versions: list[Version] = []
    for ver_str in data.get('releases', {}):
        try:
            v = Version(ver_str)
            if not v.is_devrelease:
                versions.append(v)
        except InvalidVersion:
            continue

    if not versions:
        return None

    latest = max(versions)
    log.debug('Latest PyPI version (prerelease=True): %s', latest)
    return str(latest)


def get_latest_version(package: str = PACKAGE) -> str | None:
    """
    Return the latest version appropriate for the *installed* channel.

    If the installed version is a pre-release the search includes
    pre-releases; otherwise only stable releases are considered.

    Args:
        package: The package name to check.

    Returns:
        The latest applicable version string, or ``None``.
    """
    installed = get_installed_version(package)
    if installed == LOCAL_VERSION:
        return None

    try:
        include_pre = Version(installed).is_prerelease
    except InvalidVersion:
        return None

    return lookup_latest_version(package, include_prerelease=include_pre)


# -- Update detection --

def is_update_available(package: str = PACKAGE) -> bool:
    """
    Check whether a newer version of *package* is available on PyPI.

    PEP 440 ordering is used so that the "bucket" rules are respected
    automatically:

    * ``3.0.0a14`` → ``3.0.0a15`` — **update** (higher alpha)
    * ``3.0.0a14`` → ``3.0.0b1``  — **update** (promoted to beta)
    * ``3.0.0b2``  → ``3.0.0a20`` — **no update** (alpha < beta)
    * ``3.0.0a14`` → ``3.0.0``    — **update** (stable release)
    * ``2.9.0``    → ``3.0.0``    — **update** (higher stable)

    Local development installs (``0.0.0``) are always exempt.

    Args:
        package: The package name to check for updates.

    Returns:
        ``True`` when an update is available, ``False`` otherwise.
    """
    installed_str = get_installed_version(package)
    if installed_str == LOCAL_VERSION:
        return False

    try:
        installed = Version(installed_str)
    except InvalidVersion:
        log.warning('Cannot parse installed version: %s', installed_str)
        return False

    latest_str = lookup_latest_version(
        package, include_prerelease=installed.is_prerelease
    )
    if not latest_str:
        return False

    try:
        latest = Version(latest_str)
    except InvalidVersion:
        log.warning('Cannot parse latest version: %s', latest_str)
        return False

    log.debug('Installed: %s | Latest: %s | Update: %s',
              installed, latest, latest > installed)
    return latest > installed


# -- Installed version --

def get_installed_version(package: str = PACKAGE) -> str:
    """
    Return the locally installed version of *package*.

    Falls back to :data:`LOCAL_VERSION` (``0.0.0``) when running from
    source or when the package metadata cannot be found.

    Args:
        package: The package name to check.

    Returns:
        The installed version string.
    """
    if not is_local_run():
        try:
            return version(package)
        except PackageNotFoundError:
            log.debug(traceback.format_exc())
            log.warning('Cannot find %s installation', package)
    return LOCAL_VERSION
