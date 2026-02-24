"""
Base handler class for WebSocket handlers.

Provides common functionality and interface for all handlers.
"""

import asyncio
import logging
import traceback
from typing import Any, Callable, Optional

from lanscape.ui.ws.protocol import WSRequest, WSResponse, WSError


class BaseHandler:
    """
    Base class for WebSocket message handlers.

    Provides registration of action handlers and dispatch logic.
    Subclasses should register their handlers in __init__.
    """

    def __init__(self):
        """Initialize the handler with an empty action registry."""
        self._actions: dict[str, Callable] = {}
        self.log = logging.getLogger(self.__class__.__name__)

    @property
    def prefix(self) -> str:
        """
        The action prefix for this handler.

        Returns:
            String prefix (e.g., 'scan', 'port', 'tools')
        """
        raise NotImplementedError("Subclasses must define a prefix")

    def register(self, action: str, handler: Callable) -> None:
        """
        Register an action handler.

        Args:
            action: The action name (without prefix)
            handler: The callable to handle the action
        """
        full_action = f"{self.prefix}.{action}"
        self._actions[full_action] = handler
        self.log.debug(f"Registered handler for action: {full_action}")

    def can_handle(self, action: str) -> bool:
        """
        Check if this handler can process the given action.

        Args:
            action: The full action name

        Returns:
            True if this handler can process the action
        """
        return action in self._actions

    def get_actions(self) -> list[str]:
        """
        Get all registered actions.

        Returns:
            List of action names this handler supports
        """
        return list(self._actions.keys())

    def invoke(
        self,
        action: str,
        params: dict | None = None,
        send_event: Optional[Callable] = None,
    ) -> Any:
        """
        Invoke a registered handler directly by its short action name.

        This is a synchronous, unwrapped alternative to :meth:`handle`
        intended for unit tests and internal callers that want the raw
        return value without WSResponse wrapping.

        Args:
            action: The short action name (e.g. ``'start'``, not ``'scan.start'``)
            params: Parameters dict passed to the handler
            send_event: Optional event callback

        Returns:
            The raw value returned by the handler callable

        Raises:
            KeyError: If the action is not registered
        """
        full_action = f"{self.prefix}.{action}"
        handler = self._actions.get(full_action)
        if handler is None:
            raise KeyError(f"No handler registered for {full_action}")
        return handler(params or {}, send_event)

    async def handle(
        self,
        request: WSRequest,
        send_event: Optional[Callable] = None
    ) -> WSResponse | WSError:
        """
        Handle a WebSocket request.

        Args:
            request: The incoming request
            send_event: Optional callback to send events to the client

        Returns:
            WSResponse on success, WSError on failure
        """
        action = request.action
        handler = self._actions.get(action)

        if handler is None:
            return WSError(
                id=request.id,
                action=action,
                error=f"Unknown action: {action}"
            )

        try:
            params = request.params or {}
            # Check if handler is async
            if asyncio.iscoroutinefunction(handler):
                result = await handler(params, send_event)
            else:
                result = handler(params, send_event)

            return WSResponse(
                id=request.id,
                action=action,
                data=result,
                success=True
            )
        except Exception as e:
            self.log.error(f"Error handling {action}: {e}")
            self.log.debug(traceback.format_exc())
            return WSError(
                id=request.id,
                action=action,
                error=str(e),
                traceback=traceback.format_exc()
            )

    def _get_param(
        self,
        params: dict[str, Any],
        key: str,
        required: bool = False,
        default: Any = None
    ) -> Any:
        """
        Get a parameter from the params dict with optional validation.

        Args:
            params: The parameters dictionary
            key: The parameter key
            required: Whether the parameter is required
            default: Default value if not present

        Returns:
            The parameter value

        Raises:
            ValueError: If required parameter is missing
        """
        value = params.get(key, default)
        if required and value is None:
            raise ValueError(f"Missing required parameter: {key}")
        return value
