"""
Flask application for LANscape web UI that provides device discovery and network monitoring.
Handles initialization, routing, error handling, and web server management.
"""
import traceback
import threading
import logging
from flask import Flask, render_template
from lanscape.ui.blueprints.web import web_bp, routes  # pylint: disable=unused-import
from lanscape.ui.blueprints.api import api_bp, tools, port, scan  # pylint: disable=unused-import
from lanscape.libraries.runtime_args import RuntimeArgs, parse_args
from lanscape.libraries.version_manager import (
    is_update_available, get_installed_version, lookup_latest_version
)
from lanscape.libraries.app_scope import is_local_run
from lanscape.libraries.net_tools import is_arp_supported
from lanscape.ui.shutdown_handler import FlaskShutdownHandler

app = Flask(
    __name__
)
log = logging.getLogger('flask')

# Import and register BPs
#################################

app.register_blueprint(api_bp)
app.register_blueprint(web_bp)

# Define global jinja filters
################################


def is_substring_in_values(results: dict, substring: str) -> bool:
    """
    Check if a substring exists in any value of a dictionary.

    Args:
        results: Dictionary to search through values
        substring: String to search for

    Returns:
        Boolean indicating if substring was found in any value
    """
    return any(substring.lower() in str(v).lower() for v in results.values()) if substring else True


app.jinja_env.filters['is_substring_in_values'] = is_substring_in_values

# Define global jinja vars
################################


def set_global_safe(key: str, value):
    """ Safely set global vars without worrying about an exception """
    app_globals = app.jinja_env.globals
    try:
        if callable(value):
            value = value()

        app_globals[key] = value
        log.debug(f'jinja_globals[{key}] = {value}')
    except BaseException:
        default = app_globals.get(key)
        log.debug(traceback.format_exc())
        log.info(
            f"Unable to set app global var '{key}'" +
            f"defaulting to '{default}'"
        )
        app_globals[key] = default


set_global_safe('app_version', get_installed_version)
set_global_safe('update_available', is_update_available)
set_global_safe('latest_version', lookup_latest_version)
set_global_safe('runtime_args', vars(parse_args()))
set_global_safe('is_local', is_local_run)
set_global_safe('is_arp_supported', is_arp_supported)

# External hook to kill flask server
################################

shutdown_handler = FlaskShutdownHandler(app)
shutdown_handler.register_endpoints()

# Generalized error handling
################################


@app.errorhandler(500)
def internal_error(_):
    """
    Handle internal errors by showing a formatted error page with traceback.

    Returns:
        Rendered error template with traceback information
    """
    tb = traceback.format_exc()
    return render_template('error.html',
                           error=None,
                           traceback=tb), 500

# Webserver creation functions
################################


def start_webserver_daemon(args: RuntimeArgs) -> threading.Thread:
    """Start the web server in a daemon thread."""
    proc = threading.Thread(target=start_webserver, args=(args,))
    proc.daemon = True  # Kill thread when main thread exits
    proc.start()
    log.info('Flask server initializing as daemon')
    return proc


def start_webserver(args: RuntimeArgs) -> int:
    """Start webserver (blocking)"""
    run_args = {
        'host': '0.0.0.0',
        'port': args.port,
        'debug': args.reloader,
        'use_reloader': args.reloader
    }
    app.run(**run_args)
