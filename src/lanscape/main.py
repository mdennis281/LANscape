import threading
import webview
import logging
from .app import app


def start_webserver(debug: bool) -> int:
    if not debug:
        disable_flask_logging()
    app.run(host='0.0.0.0', port=5001, debug=debug)

def disable_flask_logging() -> None:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.logger.disabled = True


def start_webview(debug = False) -> None:
    # Start Flask server in a separate thread
    server_thread = threading.Thread(target=start_webserver, args=(debug,))
    server_thread.daemon = True
    server_thread.start()

    # Start the Pywebview window
    webview.create_window('LANscape', 'http://127.0.0.1:5001')
    webview.start()
    
if __name__ == "__main__":
    start_webview()
