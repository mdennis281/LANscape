from flask import Flask
import logging
import multiprocessing

app = Flask(__name__)

# Import Blueprints
from .blueprints.api import api_bp
from .blueprints.web import web_bp

# Register Blueprints
app.register_blueprint(api_bp)
app.register_blueprint(web_bp)

    
# Custom Jinja filter
def is_substring_in_values(results: dict, substring: str) -> bool:
    return any(substring.lower() in str(v).lower() for v in results.values()) if substring else True

app.jinja_env.filters['is_substring_in_values'] = is_substring_in_values


## Webserver creation functions
################################

def start_webserver_thread(debug: bool=True, port: int=5001) -> multiprocessing.Process:
    proc = multiprocessing.Process(target=start_webserver, args=(debug,port))
    proc.start()
    return proc

def start_webserver(debug: bool=True, port: int=5001) -> int:
    if not debug:
        disable_flask_logging()
    app.run(host='0.0.0.0', port=port, debug=debug)

def disable_flask_logging() -> None:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.logger.disabled = True

if __name__ == "__main__":
    start_webserver(True)