"""
WebSocket interface for LANscape.

Provides a standalone WebSocket server that exposes all LANscape functionality,
allowing clients to initiate scans, manage port lists, and receive real-time
scan results with delta updates.
"""

from lanscape.ui.ws.server import WebSocketServer, run_server
from lanscape.ui.ws.protocol import (
    WSMessage,
    WSRequest,
    WSResponse,
    WSError,
    WSEvent,
    MessageType
)
from lanscape.ui.ws.delta import DeltaTracker, ScanDeltaTracker

__all__ = [
    'WebSocketServer',
    'run_server',
    'WSMessage',
    'WSRequest',
    'WSResponse',
    'WSError',
    'WSEvent',
    'MessageType',
    'DeltaTracker',
    'ScanDeltaTracker'
]
