"""
LANscape React Proxy Module - Serves the bundled React UI.

This module serves the pre-built React webapp that is bundled with the
Python package, alongside the WebSocket API endpoints.
"""

from lanscape.ui.react_proxy.server import start_webapp_server, REACT_BUILD_DIR
from lanscape.ui.react_proxy.discovery import DiscoveryService, DiscoveredInstance

__all__ = [
    'start_webapp_server',
    'REACT_BUILD_DIR',
    'DiscoveryService',
    'DiscoveredInstance',
]
