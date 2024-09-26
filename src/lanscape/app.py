from flask import Flask, render_template
import logging
import traceback
import multiprocessing
import threading
import os
from .libraries.runtime_args import RuntimeArgs
app = Flask(__name__)
log = logging.getLogger('core')

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

## External hook to kill flask server
################################
exiting = False
@app.route("/shutdown")
def exit_app():
    global exiting
    exiting = True
    log.info('Received external exit request. Terminating flask.')
    return "Done"

@app.teardown_request
def teardown(exception):
    if exiting:
        os._exit(0)

## Generalized error handling
################################
@app.errorhandler(500)
def internal_error(e):
    """
    handle internal errors nicely
    """
    tb = traceback.format_exc()
    return render_template('error.html',
                           error=None,
                           traceback=tb), 500

## Webserver creation functions
################################

def start_webserver_dameon(args: RuntimeArgs) -> multiprocessing.Process:
    proc = threading.Thread(target=start_webserver, args=(args,))
    proc.daemon = True # Kill thread when main thread exits
    proc.start()

        


def start_webserver(args: RuntimeArgs) -> int:
    if not args.debug:
        disable_flask_logging()
    app.run(host='0.0.0.0', port=args.port, debug=args.debug)


def disable_flask_logging() -> None:
    flask_log = logging.getLogger('werkzeug')
    flask_log.setLevel(logging.ERROR)
    #app.logger.disabled = True


if __name__ == "__main__":
    start_webserver(True)


