"""Runtime argument handler for LANscape as module"""

from dataclasses import dataclass, fields
import argparse
from typing import Any, Dict, Optional


@dataclass
class RuntimeArgs:
    """Class representing runtime arguments for the application."""
    reloader: bool = False
    port: int = 5001
    logfile: Optional[str] = None
    loglevel: str = 'INFO'
    flask_logging: bool = False
    persistent: bool = False


def parse_args() -> RuntimeArgs:
    """
    Parse command line arguments and return a RuntimeArgs instance.
    """
    parser = argparse.ArgumentParser(description='LANscape')

    parser.add_argument('--reloader', action='store_true',
                        help='Use flask\'s reloader (helpful for local development)')
    parser.add_argument('--port', type=int, default=5001,
                        help='Port to run the webserver on')
    parser.add_argument('--logfile', type=str, default=None,
                        help='Log output to the specified file path')
    parser.add_argument('--loglevel', default='INFO', help='Set the log level')
    parser.add_argument('--flask-logging', action='store_true',
                        help='Enable flask logging (disables click output)')
    parser.add_argument('--persistent', action='store_true',
                        help='Don\'t exit after browser is closed')
    parser.add_argument('--debug', action='store_true',
                        help='Shorthand debug mode (equivalent to "--loglevel DEBUG --reloader")')

    # Parse the arguments
    args = parser.parse_args()

    # Dynamically map argparse Namespace to the Args dataclass
    # Convert the Namespace to a dictionary
    args_dict: Dict[str, Any] = vars(args)
    field_names = {field.name for field in fields(
        RuntimeArgs)}  # Get dataclass field names

    if args.debug:
        args_dict['loglevel'] = 'DEBUG'
        args_dict['reloader'] = True

    # Only pass arguments that exist in the Args dataclass
    filtered_args = {name: args_dict[name]
                     for name in field_names if name in args_dict}

    # Deal with loglevel formatting
    filtered_args['loglevel'] = filtered_args['loglevel'].upper()

    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if filtered_args['loglevel'] not in valid_levels:
        raise ValueError(
            f"Invalid log level: {filtered_args['loglevel']}. Must be one of: {valid_levels}")

    # Return the dataclass instance with the dynamically assigned values
    return RuntimeArgs(**filtered_args)
