from .webviewer import start_webview
from .app import start_webserver
from .libraries.subnet_scan import cleanup_old_jobs
import threading
import webbrowser
import argparse
import time
import logging
import traceback
from .libraries.logger import configure_logging
import os

log = logging.getLogger('core')


def main():
    args = parse_args()
    configure_logging(args.loglevel, args.logfile)
    
        
    try:
        if args.nogui:
            no_gui(args)
        else:
            start_webview(
                port=args.port
            )
        if not args.noclean:
            cleanup_old_jobs()
    except Exception:
        # showing error in debug only because this is handled gracefully
        log.debug('Failed to start webview client. Traceback below')
        log.debug(traceback.format_exc())
        if not args.nogui:
            log.error('Unable to start webview client. Try running with flag --nogui')
        

def parse_args():
    parser = argparse.ArgumentParser(description='LANscape')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--port', type=int, default=5001, help='Port to run the webserver on')
    parser.add_argument('--nogui', action='store_true', help='Run in standalone mode')
    parser.add_argument('--noclean', action='store_true', help='Don\'t clean up jobs folder')
    parser.add_argument('--logfile', action='store_true', help='Log output to lanscape.log')
    parser.add_argument('--loglevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the log level')

    return parser.parse_args()

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

def no_gui(args):
    # determine if it was reloaded by flask debug reloader
    # if it was, dont open the browser again
    os.environ.setdefault('NOGUI','True')
    if os.environ.get("WERKZEUG_RUN_MAIN") is None:
        open_browser(f'http://127.0.0.1:{args.port}')
    start_webserver(
        debug=args.debug,
        port=args.port
    )


if __name__ == "__main__":
    main()
        
