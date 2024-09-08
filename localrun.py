import sys
from src.lanscape import main

debug = len(sys.argv) > 1 and sys.argv[1] == '--debug'
print (sys.argv)

if __name__ == "__main__":
    print('debug:', debug)
    main.start_webview(debug)