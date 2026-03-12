"""Runtime argument handler for LANscape as module"""

import argparse
import sys
from typing import Any, Dict, Optional

from pydantic import BaseModel

from lanscape.core.version_manager import get_installed_version


class RuntimeArgs(BaseModel):
    """Runtime arguments for the application."""
    ui_port: int = 5001
    logfile: Optional[str] = None
    loglevel: str = 'INFO'
    persistent: bool = False
    debug: bool = False
    ws_server: bool = False
    ws_port: int = 8766
    mdns_enabled: bool = True


def was_port_explicit() -> bool:
    """Check if --ui-port was explicitly provided on command line."""
    return any(arg.startswith('--ui-port') for arg in sys.argv)


def was_ws_port_explicit() -> bool:
    """Check if --ws-port was explicitly provided on command line."""
    return any(arg.startswith('--ws-port') for arg in sys.argv)


def parse_args() -> RuntimeArgs:
    """
    Parse command line arguments and return a RuntimeArgs instance.
    """
    parser = argparse.ArgumentParser(description='LANscape')

    parser.add_argument('--version', action='version',
                        version=f'LANscape v{get_installed_version()}')
    parser.add_argument('--ui-port', type=int, default=5001,
                        help='Port for the web UI (default: auto)')
    parser.add_argument('--logfile', type=str, default=None,
                        help='Log output to the specified file path')
    parser.add_argument('--loglevel', default='INFO', help='Set the log level')
    parser.add_argument('--persistent', action='store_true',
                        help='Don\'t auto-shutdown when browser closes')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode (sets loglevel to DEBUG and '
                             'registers debug WebSocket handlers)')
    parser.add_argument('--ws-server', action='store_true',
                        help='Start WebSocket server only (no UI)')
    parser.add_argument('--ws-port', type=int, default=8766,
                        help='Port for WebSocket server (default: 8766)')
    parser.add_argument('--mdns-off', action='store_true',
                        help='Disable mDNS service discovery')

    # Parse the arguments
    args = parser.parse_args()

    # Dynamically map argparse Namespace to the Args dataclass
    # Convert the Namespace to a dictionary
    args_dict: Dict[str, Any] = vars(args)

    field_names = set(RuntimeArgs.model_fields)  # Get model field names

    if args.debug:
        args_dict['loglevel'] = 'DEBUG'

    # --mdns-off -> mdns_enabled=False
    if args_dict.pop('mdns_off', False):
        args_dict['mdns_enabled'] = False

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
