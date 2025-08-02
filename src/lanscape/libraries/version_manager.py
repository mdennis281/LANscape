import logging
import requests
import traceback
from importlib.metadata import version, PackageNotFoundError
from random import randint

from .app_scope import is_local_run

log = logging.getLogger('VersionManager')

PACKAGE = 'lanscape'
LOCAL_VERSION = '0.0.0'

latest = None  # used to 'remember' pypi version each runtime


def is_update_available(package=PACKAGE) -> bool:
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
    # Fetch the latest version from PyPI
    global latest
    if not latest:
        no_cache = f'?cachebust={randint(0, 6969)}'
        url = f"https://pypi.org/pypi/{package}/json{no_cache}"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise an exception for HTTP errors
            latest = response.json()['info']['version']
            log.debug(f'Latest pypi version: {latest}')
        except BaseException:
            log.debug(traceback.format_exc())
            log.warning('Unable to fetch package version from PyPi')
    return latest


def get_installed_version(package=PACKAGE):
    if not is_local_run():
        try:
            return version(package)
        except PackageNotFoundError:
            log.debug(traceback.format_exc())
            log.warning(f'Cannot find {package} installation')
    return LOCAL_VERSION
