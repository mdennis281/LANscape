import threading
import webview
from .app import app


def start_server() -> int:
    app.run(host='0.0.0.0', port=5001, debug=False)


    
if __name__ == "__main__":
    # Start Flask server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Start the Pywebview window
    webview.create_window('LANscape', 'http://127.0.0.1:5001')
    webview.start()
