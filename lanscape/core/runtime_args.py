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
    printer_safety: bool = True


# Some CLI flags toggle the OPPOSITE of their dest name (e.g. --mdns-off sets
# mdns_enabled=False). The argparse parser knows the flag and help text, and
# this map lets the metadata helper rewrite those dests back to the RuntimeArgs
# field name so the UI never needs to know about the inversion.
_INVERSE_FLAG_DESTS: Dict[str, str] = {
    'mdns_off': 'mdns_enabled',
    'printer_mayhem': 'printer_safety',
}


def was_port_explicit() -> bool:
    """Check if --ui-port was explicitly provided on command line."""
    return any(arg.startswith('--ui-port') for arg in sys.argv)


def was_ws_port_explicit() -> bool:
    """Check if --ws-port was explicitly provided on command line."""
    return any(arg.startswith('--ws-port') for arg in sys.argv)


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser.

    Extracted so :func:`parse_args` and :func:`get_arg_metadata` share a
    single source of truth for CLI flags and help text — adding a new arg
    here automatically surfaces it in the UI's About modal.
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
                        help='Don\'t auto-shutdown when browser disconnects from WebSocket')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode (sets loglevel to DEBUG and '
                             'registers debug WebSocket handlers)')
    parser.add_argument('--ws-server', action='store_true',
                        help='Start WebSocket server only (no UI)')
    parser.add_argument('--ws-port', type=int, default=8766,
                        help='Port for WebSocket server (default: 8766)')
    parser.add_argument('--mdns-off', action='store_true',
                        help='Disable mDNS service discovery')
    parser.add_argument('--printer-mayhem', action='store_true',
                        help='Allows LANscape to probe printer ports, which may '
                             'cause printers to spam print')

    return parser


def get_arg_metadata() -> Dict[str, Dict[str, Optional[str]]]:
    """Return CLI flag and help text per :class:`RuntimeArgs` field.

    Walks the same argparse parser used at startup, so the returned metadata
    can never drift from the CLI. Inverse-flag dests are rewritten to their
    RuntimeArgs field name (e.g. ``mdns_off`` -> ``mdns_enabled``).

    Returns:
        Dict keyed by RuntimeArgs field name, with ``flag`` and ``help`` strings.
    """
    parser = _build_parser()

    metadata: Dict[str, Dict[str, Optional[str]]] = {}
    # argparse's `_actions` list is private but stable; the public API doesn't
    # expose a way to introspect registered arguments.
    for action in parser._actions:  # pylint: disable=protected-access
        if action.dest in ('help', 'version'):
            continue
        # Prefer the long flag over any short alias.
        flag = next(
            (s for s in action.option_strings if s.startswith('--')),
            action.option_strings[0] if action.option_strings else None,
        )
        key = _INVERSE_FLAG_DESTS.get(action.dest, action.dest)
        metadata[key] = {'flag': flag, 'help': action.help}

    return metadata


def parse_args() -> RuntimeArgs:
    """
    Parse command line arguments and return a RuntimeArgs instance.
    """
    parser = _build_parser()

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

    # --printer-mayhem -> printer_safety=False
    if args_dict.pop('printer_mayhem', False):
        args_dict['printer_safety'] = False

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
