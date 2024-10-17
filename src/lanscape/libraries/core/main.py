
import threading
import webbrowser
import time
import logging
import traceback
import os
from ..logger import configure_logging
from ..runtime_args import parse_args, RuntimeArgs
# do this so any logs generated on import are displayed
args = parse_args()
configure_logging(args.loglevel, args.logfile)

from ..version_manager import get_installed_version, is_update_available
from .webviewer import start_webview
from .app import start_webserver


log = logging.getLogger('core')
# determine if the execution is an instance of a flask reload
# happens on file change with reloader enabled
IS_FLASK_RELOAD = os.environ.get("WERKZEUG_RUN_MAIN")




def main():
    if not IS_FLASK_RELOAD:
        log.info(f'LANscape v{get_installed_version()}')
        try_check_update()
    else: 
        log.info('Flask reloaded app.')
        
        
    try:
        if args.nogui or args.headless:
            no_gui(args)
        else:
            start_webview(
                args
            )
    except Exception:
        # showing error in debug only because this is handled gracefully
        log.debug('Failed to start webview client. Traceback below')
        log.debug(traceback.format_exc())
        if not args.nogui:
            log.error('Unable to start webview client. Try running with flag --nogui')


def try_check_update():
    try: 
        if is_update_available():
            log.info('An update is available!')
            log.info('Run "pip install --upgrade lanscape --no-cache" to supress this message.')
    except:
        log.debug(traceback.format_exc())
        log.warning('Unable to check for updates.')
    

def open_browser(url: str,wait=2):
    """
    Open a browser window to the specified
    url after waiting for the server to start
    """
    def do_open():
        try:
            time.sleep(wait)
            webbrowser.open(url, new=2)
        except:
            srv_url = f"0.0.0.0:{url.split(':')[1]}"
            log.debug(traceback.format_exc())
            log.info(f'unable to open web browser, server running on {srv_url}')

    threading.Thread(target=do_open).start()

def no_gui(args: RuntimeArgs):
    # determine if it was reloaded by flask debug reloader
    # if it was, dont open the browser again
    if not IS_FLASK_RELOAD and not args.headless:
        open_browser(f'http://127.0.0.1:{args.port}')
    if args.headless:
        log.info(f'Started in headless mode on: http://127.0.0.1:{args.port}')
    start_webserver(
        args
    )


if __name__ == "__main__":
    main()
        
