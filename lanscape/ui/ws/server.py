"""
WebSocket server for LANscape.

Provides an async WebSocket server that can run independently of the Flask UI.
Handles client connections, message routing, and real-time scan updates.
"""

import asyncio
import json
import logging
import uuid
from typing import Optional

import websockets
from websockets.server import WebSocketServerProtocol

from lanscape.ui.ws.protocol import (
    WSRequest,
    WSResponse,
    WSError,
    WSEvent
)
from lanscape.ui.ws.handlers import (
    ScanHandler,
    PortHandler,
    ToolsHandler
)


class WebSocketServer:
    """
    Async WebSocket server for LANscape.

    Provides a standalone WebSocket interface to all LANscape functionality.
    Supports real-time scan updates via subscriptions.
    """

    DEFAULT_HOST = 'localhost'
    DEFAULT_PORT = 8766

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        """
        Initialize the WebSocket server.

        Args:
            host: Host to bind to (default: 0.0.0.0)
            port: Port to listen on (default: 8766)
        """
        self.host = host
        self.port = port
        self.log = logging.getLogger('WebSocketServer')

        # Initialize handlers
        self._scan_handler = ScanHandler()
        self._port_handler = PortHandler()
        self._tools_handler = ToolsHandler()

        self._handlers = [
            self._scan_handler,
            self._port_handler,
            self._tools_handler
        ]

        # Active connections
        self._clients: dict[str, WebSocketServerProtocol] = {}

        # Track scans that were running (to detect completion)
        self._previously_running_scans: set[str] = set()

        # Server instance
        self._server = None
        self._running = False

        # Background tasks
        self._update_task: Optional[asyncio.Task] = None

    def get_actions(self) -> list[str]:
        """
        Get all supported actions.

        Returns:
            List of all action names supported by all handlers
        """
        actions = []
        for handler in self._handlers:
            actions.extend(handler.get_actions())
        return actions

    async def start(self) -> None:
        """Start the WebSocket server."""
        self.log.info(f"Starting WebSocket server on ws://{self.host}:{self.port}")

        self._running = True

        # Minimal WebSocket server configuration - let the library handle everything
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port
        )

        # Start the background update task
        self._update_task = asyncio.create_task(self._broadcast_scan_updates())

        self.log.info("WebSocket server started")

    async def stop(self) -> None:
        """Stop the WebSocket server."""
        self.log.info("Stopping WebSocket server...")
        self._running = False

        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Close all client connections
        for client_id, ws in list(self._clients.items()):
            try:
                await ws.close()
            except Exception as e:
                self.log.debug(f"Error closing client {client_id}: {e}")

        self._clients.clear()
        self.log.info("WebSocket server stopped")

    async def serve_forever(self) -> None:
        """Run the server until stopped."""
        await self.start()
        try:
            await self._server.wait_closed()
        except asyncio.CancelledError:
            await self.stop()

    async def _handle_connection(
        self,
        websocket: WebSocketServerProtocol
    ) -> None:
        """
        Handle a new WebSocket connection.

        Args:
            websocket: The WebSocket connection
        """
        client_id = str(uuid.uuid4())
        self._clients[client_id] = websocket
        self.log.info(f"Client connected: {client_id}")

        # Send welcome message with client_id
        await self._send_event(
            websocket,
            'connection.established',
            {'client_id': client_id, 'actions': self.get_actions()}
        )

        try:
            async for message in websocket:
                await self._handle_message(client_id, websocket, message)
        except websockets.ConnectionClosed:
            self.log.info(f"Client disconnected: {client_id}")
        except Exception as e:
            self.log.error(f"Error handling client {client_id}: {e}")
        finally:
            self._cleanup_client(client_id)

    async def _handle_message(
        self,
        client_id: str,
        websocket: WebSocketServerProtocol,
        message: str
    ) -> None:
        """
        Handle an incoming WebSocket message.

        Args:
            client_id: The client identifier
            websocket: The WebSocket connection
            message: The raw message string
        """
        try:
            data = json.loads(message)
            request = WSRequest.model_validate(data)
        except json.JSONDecodeError as e:
            error = WSError(error=f"Invalid JSON: {e}")
            await self._send(websocket, error)
            return
        except Exception as e:
            error = WSError(error=f"Invalid request format: {e}")
            await self._send(websocket, error)
            return

        self.log.debug(f"[{client_id}] Request: {request.action}")

        # Find the appropriate handler
        response = None
        for handler in self._handlers:
            if handler.can_handle(request.action):
                # Create a send_event callback for this client
                async def send_event(event: str, data: dict) -> None:
                    await self._send_event(websocket, event, data)

                response = await handler.handle(request, send_event)
                break

        if response is None:
            response = WSError(
                id=request.id,
                action=request.action,
                error=f"Unknown action: {request.action}. "
                f"Available actions: {self.get_actions()}"
            )

        await self._send(websocket, response)

    async def _send(
        self,
        websocket: WebSocketServerProtocol,
        message: WSResponse | WSError | WSEvent
    ) -> None:
        """
        Send a message to a client.

        Args:
            websocket: The WebSocket connection
            message: The message to send
        """
        try:
            await websocket.send(message.model_dump_json())
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            self.log.error(f"Error sending message: {e}")

    async def _send_event(
        self,
        websocket: WebSocketServerProtocol,
        event: str,
        data: dict
    ) -> None:
        """
        Send an event to a client.

        Args:
            websocket: The WebSocket connection
            event: The event name
            data: The event data
        """
        message = WSEvent(event=event, data=data)
        await self._send(websocket, message)

    async def _broadcast_scan_updates(self) -> None:
        """
        Background task to broadcast scan updates to subscribed clients.

        Sends delta updates every 500ms for active scans.
        """
        while self._running:
            try:
                await asyncio.sleep(0.5)
                await self._send_updates_for_active_scans()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log.error(f"Error in broadcast loop: {e}")

    async def _send_updates_for_active_scans(self) -> None:
        """Send delta updates for all active scans to subscribed clients."""
        # pylint: disable=protected-access
        currently_running = set()

        for scan in self._scan_handler._scan_manager.scans:
            stage = scan.results.stage
            if scan.running or stage == 'terminating':
                # Scan is actively running or in the process of terminating
                currently_running.add(scan.uid)
                await self._send_scan_update_to_subscribers(scan)
            elif scan.uid in self._previously_running_scans:
                # Scan just finished - send final update with appropriate event
                await self._send_scan_finished_to_subscribers(scan)

        # Update tracking set
        self._previously_running_scans = currently_running

    async def _send_scan_finished_to_subscribers(self, scan) -> None:
        """Send scan finished event (complete or terminated) to all subscribed clients."""
        subscribed_clients = self._scan_handler.get_subscriptions(scan.uid)
        actual_stage = scan.results.stage

        # Determine event type based on actual stage
        if actual_stage == 'terminated':
            event_name = 'scan.terminated'
        else:
            event_name = 'scan.complete'

        for client_id in subscribed_clients:
            websocket = self._clients.get(client_id)
            if websocket is None:
                continue

            try:
                # Send final delta with all remaining changes
                # pylint: disable=protected-access
                delta = self._scan_handler._handle_get_delta(
                    {'scan_id': scan.uid, 'client_id': client_id},
                    None
                )
                # Use the actual stage from the scan, not a hardcoded value
                if 'metadata' in delta:
                    delta['metadata']['running'] = False
                    delta['metadata']['stage'] = actual_stage

                await self._send_event(websocket, event_name, delta)
            except Exception as e:
                self.log.debug(f"Error sending {event_name} to {client_id}: {e}")

    async def _send_scan_update_to_subscribers(self, scan) -> None:
        """Send scan update to all subscribed clients."""
        subscribed_clients = self._scan_handler.get_subscriptions(scan.uid)

        for client_id in subscribed_clients:
            websocket = self._clients.get(client_id)
            if websocket is None:
                continue

            await self._try_send_delta_update(websocket, scan.uid, client_id)

    async def _try_send_delta_update(
        self,
        websocket: WebSocketServerProtocol,
        scan_id: str,
        client_id: str
    ) -> None:
        """Try to send a delta update to a client."""
        try:
            # pylint: disable=protected-access
            delta = self._scan_handler._handle_get_delta(
                {'scan_id': scan_id, 'client_id': client_id},
                None
            )

            # Send update if there are device/metadata changes OR if stage is terminating
            # (so clients see the terminating status even without device changes)
            stage = delta.get('metadata', {}).get('stage', '')
            if delta.get('has_changes') or stage == 'terminating':
                await self._send_event(websocket, 'scan.update', delta)
        except Exception as e:
            self.log.debug(f"Error sending update to {client_id}: {e}")

    def _cleanup_client(self, client_id: str) -> None:
        """
        Clean up resources for a disconnected client.

        Args:
            client_id: The client identifier
        """
        self._clients.pop(client_id, None)
        self._scan_handler.cleanup_client(client_id)
        self.log.debug(f"Cleaned up client: {client_id}")


def run_server(host: str = WebSocketServer.DEFAULT_HOST,
               port: int = WebSocketServer.DEFAULT_PORT) -> None:
    """
    Run the WebSocket server.

    This is a convenience function to start the server synchronously.

    Args:
        host: Host to bind to
        port: Port to listen on
    """
    server = WebSocketServer(host, port)
    asyncio.run(server.serve_forever())


if __name__ == '__main__':
    # Configure logging when run directly
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    run_server()
