from .webviewer import start_webview
from .app import start_webserver
import threading
import webbrowser
import argparse
import time
import logging
import traceback
from .libraries.logger import configure_logging

log = logging.getLogger('core')


def main():
    args = parse_args()
    configure_logging(args.loglevel, args.logtype)
    def no_gui():
        open_browser(f'http://127.0.0.1:{args.port}')
        start_webserver(
            debug=args.debug,
            port=args.port
        )
        
        
        
    try:
        if args.nogui:
            no_gui()
        else:
            start_webview(
                port=args.port
            )
    except Exception:
        # showing error in debug only because this is handled gracefully
        log.debug('Failed to start webview client. Traceback below')
        log.debug(traceback.format_exc())
        log.error('Unable to start webview client. Try running with flag --nogui')
        

def parse_args():
    parser = argparse.ArgumentParser(description='LANscape')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--port', type=int, default=5001, help='Port to run the webserver on')
    parser.add_argument('--nogui', action='store_true', help='Run in standalone mode')
    parser.add_argument('--loglevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the log level')
    parser.add_argument('--logtype', default='console', choices=['console', 'file'], help='Choose log output type: console or file')

    return parser.parse_args()

def open_browser(url: str,wait=2):
    """
    Open a browser window to the specified
    url after waiting for the server to start
    """
    def do_open():
        time.sleep(wait)
        webbrowser.open(url, new=2)

    threading.Thread(target=do_open).start()



if __name__ == "__main__":
    main()
        
