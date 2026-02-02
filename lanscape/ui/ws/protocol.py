"""
WebSocket protocol definitions for LANscape.

Defines the message format and types used for communication between
WebSocket clients and the LANscape server.
"""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    """Types of WebSocket messages."""
    # Requests
    REQUEST = "request"
    # Responses
    RESPONSE = "response"
    ERROR = "error"
    # Push notifications (server-initiated)
    EVENT = "event"


class WSMessage(BaseModel):
    """Base WebSocket message structure."""
    type: MessageType
    id: Optional[str] = None  # Message ID for request/response correlation


class WSRequest(WSMessage):
    """
    WebSocket request message from client.

    Attributes:
        action: The action to perform (e.g., 'scan.start', 'port.list')
        params: Optional parameters for the action
    """
    type: MessageType = Field(default=MessageType.REQUEST)
    action: str
    params: Optional[dict[str, Any]] = None


class WSResponse(WSMessage):
    """
    WebSocket response message from server.

    Attributes:
        action: The action this is responding to
        data: The response data
        success: Whether the action was successful
    """
    type: MessageType = Field(default=MessageType.RESPONSE)
    action: str
    data: Any = None
    success: bool = True


class WSError(WSMessage):
    """
    WebSocket error message from server.

    Attributes:
        action: The action that caused the error
        error: Error message
        traceback: Optional full traceback for debugging
    """
    type: MessageType = Field(default=MessageType.ERROR)
    action: Optional[str] = None
    error: str
    traceback: Optional[str] = None


class WSEvent(WSMessage):
    """
    WebSocket event message from server (push notification).

    Used for real-time updates like scan progress and results.

    Attributes:
        event: The event name (e.g., 'scan.progress', 'scan.device_found')
        data: Event data
    """
    type: MessageType = Field(default=MessageType.EVENT)
    event: str
    data: Any = None
