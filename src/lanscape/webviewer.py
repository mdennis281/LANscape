import webview
from .app import start_webserver_dameon
import sys



def start_webview(debug = False,port:int = 5001) -> None:
    # Start Flask server in a separate thread
    start_webserver_dameon(debug, port)

    # Start the Pywebview window
    webview.create_window('LANscape', f'http://127.0.0.1:{port}')
    webview.start()


    
if __name__ == "__main__":
    # Start Flask server in a separate thread
    start_webview(True)

