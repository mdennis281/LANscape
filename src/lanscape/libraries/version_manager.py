import requests
import pkg_resources
import logging 
import traceback

log = logging.getLogger('VersionManager')
PACKAGE='lanscape'

latest = None # used to 'remember' pypi version each runtime

def is_update_available(package=PACKAGE) -> bool:
    installed = get_installed_version(package)
    available = lookup_latest_version(package)

    return installed != available

def lookup_latest_version(package=PACKAGE):
    # Fetch the latest version from PyPI
    global latest
    if not latest:
        url = f"https://pypi.org/pypi/{package}/json"
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
    installed_version = None
    try:
        installed_version = pkg_resources.get_distribution(package).version
    except:
        log.debug(traceback.format_exc())
        log.warning(f'Cannot find {package} installation')
    return installed_version

