import multiprocessing
import webview
from .app import start_webserver_thread
import sys


debug = sys.argv[1] if len(sys.argv) > 1 else False


def start_webview(debug = False,port:int = 5001) -> None:
    # Start Flask server in a separate thread
    proc = start_webserver_thread(debug, port)

    try:
        # Start the Pywebview window
        webview.create_window('LANscape', f'http://127.0.0.1:{port}')
        webview.start()
    except Exception as e:
        # If the webview fails to start, kill the Flask server
        proc.terminate()
        raise e
    proc.terminate()


    
if __name__ == "__main__":
    # Start Flask server in a separate thread
    start_webview(True)

