import logging
import os
from flask import request


from lanscape.libraries.runtime_args import parse_args


log = logging.getLogger('shutdown_handler')


class FlaskShutdownHandler:
    """Handles shutdown requests for the Flask application.
    """

    def __init__(self, app):
        self.app = app
        self._exiting = False

    def register_endpoints(self):
        """Register shutdown endpoints to the Flask app."""

        @self.app.route('/shutdown', methods=['POST', 'GET'])
        def shutdown():
            req_type = request.args.get('type')
            self.shutdown_request(req_type)
            return "Done"

        @self.app.teardown_request
        def teardown(_):
            self.exit_if_requested()

    def shutdown_request(self, req_type: str):
        """Handles shutdown requests based on the type of request.
        Args:
            req_type (str): The type of shutdown request.
        """
        if req_type == 'browser-close':
            args = parse_args()
            if args.persistent:
                log.info('Detected browser close, not exiting flask.')
                return "Ignored"
            log.info('Web browser closed, terminating flask. (disable with --persistent)')
        elif req_type == 'core':
            log.info('Core requested exit, terminating flask.')
        else:
            log.info('Received external exit request. Terminating flask.')
        self._exiting = True

    def exit_if_requested(self):
        """Exits the application if a shutdown request has been made."""
        if self._exiting:
            os._exit(0)
