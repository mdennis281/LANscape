import threading
import webview
from .app import start_webserver
import sys


debug = sys.argv[1] if len(sys.argv) > 1 else False


def start_webview(debug = False,port:int = 5001) -> None:
    # Start Flask server in a separate thread
    server_thread = threading.Thread(target=start_webserver, args=(debug,port))
    server_thread.daemon = True
    server_thread.start()

    # Start the Pywebview window
    webview.create_window('LANscape', f'http://127.0.0.1:{port}')
    webview.start()


    
if __name__ == "__main__":
    # Start Flask server in a separate thread
    start_webview(True)

