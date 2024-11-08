from flask import Flask, render_template
import multiprocessing
import traceback
import threading
import logging
import os

from ..libraries.runtime_args import RuntimeArgs, parse_args
from ..libraries.version_manager import is_update_available, get_installed_version, lookup_latest_version
from ..libraries.app_scope import is_local_run

app = Flask(
    __name__
)
log = logging.getLogger('core')

## Import and register BPs
################################

from .blueprints.api import api_bp
from .blueprints.web import web_bp

app.register_blueprint(api_bp)
app.register_blueprint(web_bp)
    
## Define global jinja filters
################################

def is_substring_in_values(results: dict, substring: str) -> bool:
    return any(substring.lower() in str(v).lower() for v in results.values()) if substring else True

app.jinja_env.filters['is_substring_in_values'] = is_substring_in_values

## Define global jinja vars
################################

def set_global_safe(key: str, value):
    """ Safely set global vars without worrying about an exception """
    app_globals = app.jinja_env.globals
    try:
        if callable(value): value = value()
        
        app_globals[key] = value
        log.debug(f'jinja_globals[{key}] = {value}')
    except:
        default = app_globals.get(key)
        log.debug(traceback.format_exc())
        log.info(
            f"Unable to set app global var '{key}'"+
            f"defaulting to '{default}'"
        )
        app_globals[key] = default

set_global_safe('app_version',get_installed_version)
set_global_safe('update_available', is_update_available)
set_global_safe('latest_version',lookup_latest_version)
set_global_safe('runtime_args', vars(parse_args()))
set_global_safe('is_local',is_local_run)

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
    app.run(
        host='0.0.0.0', 
        port=args.port, 
        debug=args.reloader,
        use_reloader=args.reloader
    )


if __name__ == "__main__":
    start_webserver(True)


