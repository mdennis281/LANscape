import logging 
import requests
import traceback
import pkg_resources
from random import randint

from .app_scope import is_local_run

log = logging.getLogger('VersionManager')

PACKAGE='lanscape'
LOCAL_VERSION = '0.0.0'

latest = None # used to 'remember' pypi version each runtime

def is_update_available(package=PACKAGE) -> bool:
    installed = get_installed_version(package)
    available = lookup_latest_version(package)
    if installed == LOCAL_VERSION: return False # local
    if 'a' in installed: return False # alpha
    if 'b' in installed: return False # beta

    return installed != available

def lookup_latest_version(package=PACKAGE):
    # Fetch the latest version from PyPI
    global latest
    if not latest:
        no_cache = f'?cachebust={randint(0,6969)}'
        url = f"https://pypi.org/pypi/{package}/json{no_cache}"
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for HTTP errors
            latest = response.json()['info']['version']
            log.debug(f'Latest pypi version: {latest}')
        except:
            log.debug(traceback.format_exc())
            log.warning('Unable to fetch package version from PyPi')
    return latest

def get_installed_version(package=PACKAGE):
    if not is_local_run():
        try:
            return pkg_resources.get_distribution(package).version
        except:
            log.debug(traceback.format_exc())
            log.warning(f'Cannot find {package} installation')
    return LOCAL_VERSION
    

