import webview
from .app import start_webserver_dameon
from .libraries.runtime_args import RuntimeArgs



def start_webview(args: RuntimeArgs) -> None:
    # Start Flask server in a separate thread
    start_webserver_dameon(args)

    # Start the Pywebview window
    webview.create_window('LANscape', f'http://127.0.0.1:{args.port}')
    webview.start()


    
if __name__ == "__main__":
    # Start Flask server in a separate thread
    start_webview(True)

