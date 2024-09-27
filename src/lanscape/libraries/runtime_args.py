import argparse
from dataclasses import dataclass, fields
import argparse
from typing import Any, Dict

@dataclass
class RuntimeArgs:
    reloader: bool = False
    port: int = 5001
    nogui: bool = False
    noclean: bool = False
    logfile: bool = False
    loglevel: str = 'INFO'
    headless: bool = False

def parse_args() -> RuntimeArgs:
    parser = argparse.ArgumentParser(description='LANscape')

    parser.add_argument('--reloader', action='store_true', help='Use flask\'s reloader (helpful for local development)')
    parser.add_argument('--port', type=int, default=5001, help='Port to run the webserver on')
    parser.add_argument('--nogui', action='store_true', help='Run in standalone mode')
    parser.add_argument('--noclean', action='store_true', help='Don\'t clean up jobs folder')
    parser.add_argument('--logfile', action='store_true', help='Log output to lanscape.log')
    parser.add_argument('--loglevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the log level')
    parser.add_argument('--headless', action="store_true",help="Similar to nogui, but doesnt try to open a browser. Good for running in a container.")

    # Parse the arguments
    args = parser.parse_args()


    # Dynamically map argparse Namespace to the Args dataclass
    args_dict: Dict[str, Any] = vars(args)  # Convert the Namespace to a dictionary
    field_names = {field.name for field in fields(RuntimeArgs)}  # Get dataclass field names
    
    # Only pass arguments that exist in the Args dataclass
    filtered_args = {name: args_dict[name] for name in field_names if name in args_dict}

    # Return the dataclass instance with the dynamically assigned values
    return RuntimeArgs(**filtered_args)