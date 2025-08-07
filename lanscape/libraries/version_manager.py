"""
Version management module for LANscape.
Handles version checking, update detection, and retrieving package information
from both local installation and PyPI repository.
"""

import logging
import traceback
from importlib.metadata import version, PackageNotFoundError
from random import randint

import requests

from .app_scope import is_local_run

log = logging.getLogger('VersionManager')

PACKAGE = 'lanscape'
LOCAL_VERSION = '0.0.0'

# Used to cache PyPI version during runtime
LATEST_VERSION = None


def is_update_available(package=PACKAGE) -> bool:
    """
    Check if an update is available for the package.

    Compares the installed version with the latest version available on PyPI.
    Ignores pre-release versions (alpha/beta) and local development installs.

    Args:
        package: The package name to check for updates

    Returns:
        Boolean indicating if an update is available
    """
    installed = get_installed_version(package)
    available = lookup_latest_version(package)

    is_update_exempt = (
        'a' in installed, 'b' in installed,  # pre-release
        installed == LOCAL_VERSION
    )
    if any(is_update_exempt):
        return False

    log.debug(f'Installed: {installed} | Available: {available}')
    return installed != available


def lookup_latest_version(package=PACKAGE):
    """
    Retrieve the latest version of the package from PyPI.

    Caches the result for subsequent calls during the same runtime.

    Args:
        package: The package name to lookup

    Returns:
        The latest version string from PyPI or None if retrieval fails
    """
    # Fetch the latest version from PyPI
    global LATEST_VERSION  # pylint: disable=global-statement
    if not LATEST_VERSION:
        no_cache = f'?cachebust={randint(0, 6969)}'
        url = f"https://pypi.org/pypi/{package}/json{no_cache}"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise an exception for HTTP errors
            LATEST_VERSION = response.json()['info']['version']
            log.debug(f'Latest pypi version: {LATEST_VERSION}')
        except BaseException:
            log.debug(traceback.format_exc())
            log.warning('Unable to fetch package version from PyPi')
    return LATEST_VERSION


def get_installed_version(package=PACKAGE):
    """
    Get the installed version of the package.

    Returns the current installed version or a default local version
    if running in development mode or if the package is not found.

    Args:
        package: The package name to check

    Returns:
        The installed version string or LOCAL_VERSION for local development
    """
    if not is_local_run():
        try:
            return version(package)
        except PackageNotFoundError:
            log.debug(traceback.format_exc())
            log.warning(f'Cannot find {package} installation')
    return LOCAL_VERSION
