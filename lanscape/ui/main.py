"""Main entry point for the LANscape application when running as a module."""
import socket


import threading
import time
import logging
import traceback
import os
import requests

from lanscape.libraries.logger import configure_logging
from lanscape.libraries.runtime_args import parse_args
from lanscape.libraries.web_browser import open_webapp
from lanscape.libraries.net_tools import is_arp_supported
from lanscape.libraries.version_manager import get_installed_version, is_update_available
from lanscape.ui.app import start_webserver_daemon, start_webserver
# do this so any logs generated on import are displayed
args = parse_args()
configure_logging(args.loglevel, args.logfile, args.flask_logging)


log = logging.getLogger('core')
# determine if the execution is an instance of a flask reload
# happens on file change with reloader enabled
IS_FLASK_RELOAD = os.environ.get("WERKZEUG_RUN_MAIN")


def main():
    """core entry point for running lanscape as a module."""
    try:
        _main()
    except KeyboardInterrupt:
        log.info('Keyboard interrupt received, terminating...')
        terminate()
    except Exception as e:
        log.critical(f'Unexpected error: {e}')
        log.debug(traceback.format_exc())
        terminate()


def _main():
    if not IS_FLASK_RELOAD:
        log.info(f'LANscape v{get_installed_version()}')
        try_check_update()

    else:
        log.info('Flask reloaded app.')

    args.port = get_valid_port(args.port)

    if not is_arp_supported():
        warn = (
            'ARP is not supported, device discovery is degraded. ',
            'For more information, see the help guide: ',
            'https://github.com/mdennis281/LANscape/blob/main/support/arp-issues.md'
        )
        log.warning(''.join(warn))

    try:
        start_webserver_ui()
        log.info('Exiting...')
    except Exception as e:
        # showing error in debug only because this is handled gracefully
        log.critical(f'Failed to start app. Error: {e}')
        log.debug('Failed to start. Traceback below')
        log.debug(traceback.format_exc())


def try_check_update():
    """Check for updates and log if available."""
    try:
        if is_update_available():
            log.info('An update is available!')
            log.info(
                'Run "pip install --upgrade lanscape --no-cache" to suppress this message.')
    except BaseException:
        log.debug(traceback.format_exc())
        log.warning('Unable to check for updates.')


def open_browser(url: str, wait=2) -> bool:
    """
    Open a browser window to the specified
    url after waiting for the server to start
    """
    try:
        time.sleep(wait)
        log.info(f'Starting UI - http://127.0.0.1:{args.port}')
        return open_webapp(url)

    except BaseException:
        log.debug(traceback.format_exc())
        log.info(f'Unable to open web browser, server running on {url}')
    return False


def start_webserver_ui():
    """Start the web server and open the UI in a browser."""
    uri = f'http://127.0.0.1:{args.port}'

    # running reloader requires flask to run in main thread
    # this decouples UI from main process
    if args.reloader:
        # determine if it was reloaded by flask debug reloader
        # if it was, dont open the browser again
        log.info('Opening UI as daemon')
        if not IS_FLASK_RELOAD:
            threading.Thread(
                target=open_browser,
                args=(uri,),
                daemon=True
            ).start()
        start_webserver(args)
    else:
        flask_thread = start_webserver_daemon(args)
        app_closed = open_browser(uri)

        # depending on env, open_browser may or
        # may not be coupled with the closure of UI
        # (if in browser tab, it's uncoupled)
        if not app_closed or args.persistent:
            # not doing a direct join so i can still
            # terminate the app with ctrl+c
            while flask_thread.is_alive():
                time.sleep(1)


def get_valid_port(port: int):
    """
    Get the first available port starting from the specified port
    """
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
            port += 1


def terminate():
    """send a request to the shutdown flask"""
    log.info('Attempting flask shutdown')
    requests.get(f'http://127.0.0.1:{args.port}/shutdown?type=core', timeout=2)


if __name__ == "__main__":
    main()
