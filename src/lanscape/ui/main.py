
import threading
import time
import logging
import traceback
import os
from ..libraries.logger import configure_logging
from ..libraries.runtime_args import parse_args, RuntimeArgs
from ..libraries.web_browser import open_webapp
# do this so any logs generated on import are displayed
args = parse_args()
configure_logging(args.loglevel, args.logfile, args.flask_logging)

from ..libraries.version_manager import get_installed_version, is_update_available
from .app import start_webserver_dameon, start_webserver
import socket


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
        
    args.port = get_valid_port(args.port)
        
        
    try:
        start_webserver_ui(args)
        log.info('Exiting...')
    except Exception as e:
        # showing error in debug only because this is handled gracefully
        log.critical(f'Failed to start app. Error: {e}')
        log.debug('Failed to start. Traceback below')
        log.debug(traceback.format_exc())



def try_check_update():
    try: 
        if is_update_available():
            log.info('An update is available!')
            log.info('Run "pip install --upgrade lanscape --no-cache" to supress this message.')
    except:
        log.debug(traceback.format_exc())
        log.warning('Unable to check for updates.')
    

def open_browser(url: str, wait=2) -> bool:
    """
    Open a browser window to the specified
    url after waiting for the server to start
    """
    start_time = time.time()
    try:
        time.sleep(wait)
        log.info('Starting UI')
        return open_webapp(url)
        
    except:
        elapsed = time.time() - start_time
        if elapsed > 15:
            # noticing that occasionally there will be a failure
            # when user closes the browser. if it took more then 
            # 15 seconds before the failure, assume that browser
            # was closed by the user & everything is fine
            log.debug(f'Exception after {elapsed:.2f} seconds, assuming browser was closed by user')
            return True
        log.debug(traceback.format_exc())
        log.info(f'Unable to open web browser, server running on {url}')
    return False



def start_webserver_ui(args: RuntimeArgs):
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
        flask_thread = start_webserver_dameon(args)
        app_closed = open_browser(uri)

        # depending on env, open_browser may or
        # may not be coupled with the closure of UI
        # (if in browser tab, it's uncoupled)
        if not app_closed:
            flask_thread.join()
    

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
    import requests
    from ..libraries.web_browser import BROWSER_PID
    log.info('Attempting flask shutdown')
    requests.get(f'http://127.0.0.1:{args.port}/shutdown')


    if BROWSER_PID:
        try:
            os.kill(BROWSER_PID, 9)  # Force kill the browser process
            log.info(f'Killed browser process with PID {BROWSER_PID}')
        except OSError as e:
            log.warning(f'Failed to kill browser process: {e}')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info('Keyboard interrupt received, terminating...')
        terminate()
    except Exception as e:
        log.critical(f'Unexpected error: {e}')
        log.debug(traceback.format_exc())
        terminate()
        
