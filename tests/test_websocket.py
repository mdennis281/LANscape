"""
Unit tests for the LANscape WebSocket interface.

Tests cover:
- Protocol classes (WSRequest, WSResponse, WSError, WSEvent)
- Delta tracking (DeltaTracker, ScanDeltaTracker)
- Handler classes (ScanHandler, PortHandler, ToolsHandler)
- WebSocket server functionality
"""
# pylint: disable=protected-access

import asyncio
import json
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

from lanscape.ui.ws.protocol import (
    WSRequest,
    WSResponse,
    WSError,
    WSEvent,
    MessageType
)
from lanscape.ui.ws.delta import DeltaTracker, ScanDeltaTracker
from lanscape.ui.ws.handlers.base import BaseHandler
from lanscape.ui.ws.handlers.scan import ScanHandler
from lanscape.ui.ws.handlers.port import PortHandler
from lanscape.ui.ws.handlers.tools import ToolsHandler
from lanscape.ui.ws.server import WebSocketServer


# Protocol Tests
###############################################################################

class TestProtocol:
    """Tests for WebSocket protocol message classes."""

    def test_ws_request_creation(self):
        """Test creating a WSRequest message."""
        request = WSRequest(
            id="test-123",
            action="scan.start",
            params={"subnet": "192.168.1.0/24", "port_list": "small"}
        )

        assert request.type == MessageType.REQUEST
        assert request.id == "test-123"
        assert request.action == "scan.start"
        assert request.params["subnet"] == "192.168.1.0/24"

    def test_ws_request_minimal(self):
        """Test creating a WSRequest with minimal parameters."""
        request = WSRequest(action="port.list")

        assert request.type == MessageType.REQUEST
        assert request.action == "port.list"
        assert request.params is None
        assert request.id is None

    def test_ws_response_creation(self):
        """Test creating a WSResponse message."""
        response = WSResponse(
            id="test-123",
            action="scan.start",
            data={"scan_id": "abc-123", "status": "running"},
            success=True
        )

        assert response.type == MessageType.RESPONSE
        assert response.id == "test-123"
        assert response.action == "scan.start"
        assert response.data["scan_id"] == "abc-123"
        assert response.success is True

    def test_ws_error_creation(self):
        """Test creating a WSError message."""
        error = WSError(
            id="test-123",
            action="scan.get",
            error="Scan not found",
            traceback="Traceback..."
        )

        assert error.type == MessageType.ERROR
        assert error.id == "test-123"
        assert error.action == "scan.get"
        assert error.error == "Scan not found"
        assert error.traceback == "Traceback..."

    def test_ws_event_creation(self):
        """Test creating a WSEvent message."""
        event = WSEvent(
            event="scan.update",
            data={"scan_id": "abc-123", "devices": []}
        )

        assert event.type == MessageType.EVENT
        assert event.event == "scan.update"
        assert event.data["scan_id"] == "abc-123"

    def test_ws_request_serialization(self):
        """Test JSON serialization of WSRequest."""
        request = WSRequest(
            id="test-123",
            action="scan.start",
            params={"subnet": "192.168.1.0/24"}
        )

        json_str = request.model_dump_json()
        data = json.loads(json_str)

        assert data["type"] == "request"
        assert data["id"] == "test-123"
        assert data["action"] == "scan.start"
        assert data["params"]["subnet"] == "192.168.1.0/24"

    def test_ws_request_deserialization(self):
        """Test JSON deserialization to WSRequest."""
        data = {
            "type": "request",
            "id": "test-123",
            "action": "scan.start",
            "params": {"subnet": "192.168.1.0/24"}
        }

        request = WSRequest.model_validate(data)

        assert request.type == MessageType.REQUEST
        assert request.id == "test-123"
        assert request.action == "scan.start"


# Delta Tracker Tests
###############################################################################

class TestDeltaTracker:
    """Tests for DeltaTracker class."""

    def test_compute_hash_consistency(self):
        """Test that hash computation is consistent."""
        data = {"ip": "192.168.1.1", "hostname": "test"}

        hash1 = DeltaTracker.compute_hash(data)
        hash2 = DeltaTracker.compute_hash(data)

        assert hash1 == hash2

    def test_compute_hash_different_data(self):
        """Test that different data produces different hashes."""
        data1 = {"ip": "192.168.1.1"}
        data2 = {"ip": "192.168.1.2"}

        hash1 = DeltaTracker.compute_hash(data1)
        hash2 = DeltaTracker.compute_hash(data2)

        assert hash1 != hash2

    def test_update_returns_data_on_first_call(self):
        """Test that update returns data on first call."""
        tracker = DeltaTracker()
        data = {"ip": "192.168.1.1"}

        result = tracker.update("device1", data)

        assert result == data

    def test_update_returns_none_on_no_change(self):
        """Test that update returns None when data hasn't changed."""
        tracker = DeltaTracker()
        data = {"ip": "192.168.1.1"}

        tracker.update("device1", data)
        result = tracker.update("device1", data)

        assert result is None

    def test_update_returns_data_on_change(self):
        """Test that update returns data when it changes."""
        tracker = DeltaTracker()
        data1 = {"ip": "192.168.1.1", "ports": []}
        data2 = {"ip": "192.168.1.1", "ports": [80]}

        tracker.update("device1", data1)
        result = tracker.update("device1", data2)

        assert result == data2

    def test_get_changes(self):
        """Test get_changes returns only changed items."""
        tracker = DeltaTracker()

        # First update - all items are new
        items = {"a": 1, "b": 2, "c": 3}
        changes = tracker.get_changes(items)
        assert changes == items

        # Second update - only b changed
        items = {"a": 1, "b": 5, "c": 3}
        changes = tracker.get_changes(items)
        assert changes == {"b": 5}

    def test_reset_specific_key(self):
        """Test resetting a specific key."""
        tracker = DeltaTracker()
        tracker.update("a", 1)
        tracker.update("b", 2)

        tracker.reset("a")

        assert not tracker.has_key("a")
        assert tracker.has_key("b")

    def test_reset_all(self):
        """Test resetting all keys."""
        tracker = DeltaTracker()
        tracker.update("a", 1)
        tracker.update("b", 2)

        tracker.reset()

        assert not tracker.has_key("a")
        assert not tracker.has_key("b")


class TestScanDeltaTracker:
    """Tests for ScanDeltaTracker class."""

    def test_get_scan_delta_initial(self):
        """Test get_scan_delta returns all data on first call."""
        tracker = ScanDeltaTracker()
        results = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": []},
                {"ip": "192.168.1.2", "ports": [80]}
            ]
        }

        delta = tracker.get_scan_delta(results)

        assert delta["has_changes"] is True
        assert delta["metadata"] is not None
        assert len(delta["devices"]) == 2

    def test_get_scan_delta_no_changes(self):
        """Test get_scan_delta returns no changes when data is same."""
        tracker = ScanDeltaTracker()
        results = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": []}
            ]
        }

        tracker.get_scan_delta(results)
        delta = tracker.get_scan_delta(results)

        assert delta["has_changes"] is False
        assert delta["metadata"] is None
        assert len(delta["devices"]) == 0

    def test_get_scan_delta_device_change(self):
        """Test get_scan_delta detects device changes."""
        tracker = ScanDeltaTracker()
        results1 = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": []}
            ]
        }
        results2 = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": [80]}  # Port changed
            ]
        }

        tracker.get_scan_delta(results1)
        delta = tracker.get_scan_delta(results2)

        assert delta["has_changes"] is True
        assert delta["metadata"] is None  # Metadata unchanged
        assert len(delta["devices"]) == 1
        assert delta["devices"][0]["ip"] == "192.168.1.1"

    def test_get_scan_delta_new_device(self):
        """Test get_scan_delta detects new devices."""
        tracker = ScanDeltaTracker()
        results1 = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": []}
            ]
        }
        results2 = {
            "subnet": "192.168.1.0/24",
            "running": True,
            "devices": [
                {"ip": "192.168.1.1", "ports": []},
                {"ip": "192.168.1.2", "ports": [22]}  # New device
            ]
        }

        tracker.get_scan_delta(results1)
        delta = tracker.get_scan_delta(results2)

        assert delta["has_changes"] is True
        assert len(delta["devices"]) == 1
        assert delta["devices"][0]["ip"] == "192.168.1.2"


# Handler Tests
###############################################################################

class TestBaseHandler:
    """Tests for BaseHandler class."""

    def test_register_action(self):
        """Test registering an action handler."""

        class TestHandler(BaseHandler):
            @property
            def prefix(self):
                return "test"

        handler = TestHandler()
        handler.register("action1", lambda p, s: {"result": "ok"})

        assert handler.can_handle("test.action1")
        assert not handler.can_handle("test.action2")

    def test_get_actions(self):
        """Test getting all registered actions."""

        class TestHandler(BaseHandler):
            @property
            def prefix(self):
                return "test"

        handler = TestHandler()
        handler.register("action1", lambda p, s: {})
        handler.register("action2", lambda p, s: {})

        actions = handler.get_actions()

        assert "test.action1" in actions
        assert "test.action2" in actions

    @pytest.mark.asyncio
    async def test_handle_success(self):
        """Test handling a request successfully."""

        class TestHandler(BaseHandler):
            @property
            def prefix(self):
                return "test"

        handler = TestHandler()
        handler.register("echo", lambda p, s: p)

        request = WSRequest(id="1", action="test.echo", params={"msg": "hello"})
        response = await handler.handle(request)

        assert isinstance(response, WSResponse)
        assert response.success is True
        assert response.data == {"msg": "hello"}

    @pytest.mark.asyncio
    async def test_handle_error(self):
        """Test handling a request that raises an error."""

        class TestHandler(BaseHandler):
            @property
            def prefix(self):
                return "test"

        def failing_handler(params, send_event):
            raise ValueError("Test error")

        handler = TestHandler()
        handler.register("fail", failing_handler)

        request = WSRequest(id="1", action="test.fail")
        response = await handler.handle(request)

        assert isinstance(response, WSError)
        assert "Test error" in response.error

    @pytest.mark.asyncio
    async def test_handle_unknown_action(self):
        """Test handling an unknown action."""

        class TestHandler(BaseHandler):
            @property
            def prefix(self):
                return "test"

        handler = TestHandler()
        request = WSRequest(id="1", action="test.unknown")
        response = await handler.handle(request)

        assert isinstance(response, WSError)
        assert "Unknown action" in response.error


class TestScanHandler:
    """Tests for ScanHandler class."""

    @pytest.fixture
    def mock_scan_manager(self):
        """Create a mock ScanManager."""
        manager = MagicMock()
        manager.scans = []
        return manager

    @pytest.fixture
    def scan_handler(self, mock_scan_manager):
        """Create a ScanHandler with mock manager."""
        return ScanHandler(scan_manager=mock_scan_manager)

    def test_handler_actions_registered(self, scan_handler):
        """Test that all scan actions are registered."""
        actions = scan_handler.get_actions()

        assert "scan.start" in actions
        assert "scan.start_sync" in actions
        assert "scan.get" in actions
        assert "scan.get_delta" in actions
        assert "scan.summary" in actions
        assert "scan.terminate" in actions
        assert "scan.subscribe" in actions
        assert "scan.unsubscribe" in actions
        assert "scan.list" in actions

    def test_handle_start(self, scan_handler, mock_scan_manager):
        """Test starting a scan."""
        mock_scan = MagicMock()
        mock_scan.uid = "test-scan-123"
        mock_scan_manager.new_scan.return_value = mock_scan

        params = {"subnet": "192.168.1.0/24", "port_list": "small"}
        result = scan_handler._handle_start(params, None)

        assert result["scan_id"] == "test-scan-123"
        assert result["status"] == "running"

    def test_handle_get_missing_scan(self, scan_handler, mock_scan_manager):
        """Test getting a non-existent scan."""
        mock_scan_manager.get_scan.return_value = None

        with pytest.raises(ValueError, match="Scan not found"):
            scan_handler._handle_get({"scan_id": "nonexistent"}, None)

    def test_handle_summary(self, scan_handler, mock_scan_manager):
        """Test getting scan summary."""
        mock_scan = MagicMock()
        mock_scan.uid = "test-scan-123"
        mock_scan.running = True
        mock_scan.calc_percent_complete.return_value = 50
        mock_scan.results.stage = "scanning devices"
        mock_scan.results.get_runtime.return_value = 30.5
        mock_scan.results.devices_scanned = 128
        mock_scan.results.devices = [MagicMock(), MagicMock()]
        mock_scan.results.devices_total = 256
        # Mock the to_summary().model_dump() chain
        mock_scan.results.to_summary.return_value.model_dump.return_value = {
            'metadata': {
                'scan_id': 'test-scan-123',
                'subnet': '192.168.1.0/24',
                'port_list': 'common',
                'running': True,
                'stage': 'scanning devices',
                'percent_complete': 50,
                'devices_total': 256,
                'devices_scanned': 128,
                'devices_alive': 2,
            },
            'ports_found': [],
            'services_found': []
        }
        mock_scan_manager.get_scan.return_value = mock_scan

        result = scan_handler._handle_summary({"scan_id": "test-scan-123"}, None)

        assert result["metadata"]["running"] is True
        assert result["metadata"]["percent_complete"] == 50
        assert result["metadata"]["stage"] == "scanning devices"
        assert result["metadata"]["devices_scanned"] == 128
        assert result["metadata"]["devices_alive"] == 2

    def test_handle_subscribe(self, scan_handler, mock_scan_manager):
        """Test subscribing to scan updates."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        result = scan_handler._handle_subscribe(
            {"scan_id": "scan-123", "client_id": "client-abc"},
            None
        )

        assert result["subscribed"] is True
        assert "client-abc" in scan_handler.get_subscriptions("scan-123")

    def test_handle_unsubscribe(self, scan_handler, mock_scan_manager):
        """Test unsubscribing from scan updates."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        # First subscribe
        scan_handler._handle_subscribe(
            {"scan_id": "scan-123", "client_id": "client-abc"},
            None
        )

        # Then unsubscribe
        result = scan_handler._handle_unsubscribe(
            {"scan_id": "scan-123", "client_id": "client-abc"},
            None
        )

        assert result["unsubscribed"] is True
        assert "client-abc" not in scan_handler.get_subscriptions("scan-123")

    def test_cleanup_client(self, scan_handler, mock_scan_manager):
        """Test cleaning up client subscriptions."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        # Subscribe to multiple scans
        scan_handler._handle_subscribe(
            {"scan_id": "scan-1", "client_id": "client-abc"},
            None
        )
        scan_handler._handle_subscribe(
            {"scan_id": "scan-2", "client_id": "client-abc"},
            None
        )

        # Cleanup
        scan_handler.cleanup_client("client-abc")

        assert "client-abc" not in scan_handler.get_subscriptions("scan-1")
        assert "client-abc" not in scan_handler.get_subscriptions("scan-2")


class TestPortHandler:
    """Tests for PortHandler class."""

    @pytest.fixture
    def mock_port_manager(self):
        """Create a mock PortManager."""
        return MagicMock()

    @pytest.fixture
    def port_handler(self, mock_port_manager):
        """Create a PortHandler with mock manager."""
        return PortHandler(port_manager=mock_port_manager)

    def test_handler_actions_registered(self, port_handler):
        """Test that all port actions are registered."""
        actions = port_handler.get_actions()

        assert "port.list" in actions
        assert "port.list_summary" in actions
        assert "port.get" in actions
        assert "port.create" in actions
        assert "port.update" in actions
        assert "port.delete" in actions

    def test_handle_list(self, port_handler, mock_port_manager):
        """Test listing port lists."""
        mock_port_manager.get_port_lists.return_value = ["small", "medium", "large"]

        result = port_handler._handle_list({}, None)

        assert result == ["small", "medium", "large"]

    def test_handle_list_summary(self, port_handler, mock_port_manager):
        """Test listing port lists with counts."""
        mock_port_manager.get_port_lists.return_value = ["small", "medium"]
        mock_port_manager.get_port_list.side_effect = [
            {"22": "ssh", "80": "http"},
            {"22": "ssh", "80": "http", "443": "https", "8080": "http-alt"}
        ]

        result = port_handler._handle_list_summary({}, None)

        assert len(result) == 2
        assert result[0]["name"] == "small"
        assert result[0]["count"] == 2
        assert result[1]["name"] == "medium"
        assert result[1]["count"] == 4

    def test_handle_get(self, port_handler, mock_port_manager):
        """Test getting a port list."""
        mock_port_manager.get_port_list.return_value = {"22": "ssh", "80": "http"}

        result = port_handler._handle_get({"name": "small"}, None)

        assert result == {"22": "ssh", "80": "http"}

    def test_handle_create_success(self, port_handler, mock_port_manager):
        """Test creating a port list successfully."""
        mock_port_manager.create_port_list.return_value = True

        result = port_handler._handle_create(
            {"name": "custom", "ports": {"22": "ssh"}},
            None
        )

        assert result["success"] is True
        assert result["name"] == "custom"

    def test_handle_create_failure(self, port_handler, mock_port_manager):
        """Test creating a port list that fails."""
        mock_port_manager.create_port_list.return_value = False

        with pytest.raises(ValueError, match="Failed to create"):
            port_handler._handle_create(
                {"name": "invalid", "ports": {}},
                None
            )

    def test_handle_delete(self, port_handler, mock_port_manager):
        """Test deleting a port list."""
        mock_port_manager.delete_port_list.return_value = True

        result = port_handler._handle_delete({"name": "custom"}, None)

        assert result["success"] is True


class TestToolsHandler:
    """Tests for ToolsHandler class."""

    @pytest.fixture
    def tools_handler(self):
        """Create a ToolsHandler."""
        return ToolsHandler()

    def test_handler_actions_registered(self, tools_handler):
        """Test that all tools actions are registered."""
        actions = tools_handler.get_actions()

        assert "tools.subnet_test" in actions
        assert "tools.subnet_list" in actions
        assert "tools.config_defaults" in actions
        assert "tools.arp_supported" in actions

    def test_handle_subnet_test_empty(self, tools_handler):
        """Test validating an empty subnet."""
        result = tools_handler._handle_subnet_test({"subnet": ""}, None)

        assert result["valid"] is False
        assert result["count"] == -1

    def test_handle_subnet_test_valid(self, tools_handler):
        """Test validating a valid subnet."""
        result = tools_handler._handle_subnet_test({"subnet": "192.168.1.1"}, None)

        assert result["valid"] is True
        assert result["count"] == 1

    def test_handle_subnet_test_cidr(self, tools_handler):
        """Test validating a CIDR subnet."""
        result = tools_handler._handle_subnet_test({"subnet": "192.168.1.0/30"}, None)

        assert result["valid"] is True
        assert result["count"] == 2  # /30 has 2 usable host IPs

    def test_handle_subnet_test_invalid(self, tools_handler):
        """Test validating an invalid subnet."""
        result = tools_handler._handle_subnet_test({"subnet": "not.a.subnet"}, None)

        assert result["valid"] is False

    def test_handle_subnet_list(self, tools_handler):
        """Test listing subnets."""
        with patch('lanscape.ui.ws.handlers.tools.get_all_network_subnets') as mock:
            mock.return_value = [{"subnet": "192.168.1.0/24", "interface": "eth0"}]

            result = tools_handler._handle_subnet_list({}, None)

            assert len(result) == 1
            assert result[0]["subnet"] == "192.168.1.0/24"

    def test_handle_config_defaults(self, tools_handler):
        """Test getting default configs."""
        with patch('lanscape.ui.ws.handlers.tools.is_arp_supported') as mock:
            mock.return_value = True

            result = tools_handler._handle_config_defaults({}, None)

            assert "balanced" in result
            assert "accurate" in result
            assert "fast" in result

    def test_handle_arp_supported(self, tools_handler):
        """Test checking ARP support."""
        with patch('lanscape.ui.ws.handlers.tools.is_arp_supported') as mock:
            mock.return_value = True
            result = tools_handler._handle_arp_supported({}, None)
            assert result["supported"] is True

            mock.return_value = False
            result = tools_handler._handle_arp_supported({}, None)
            assert result["supported"] is False


# WebSocket Server Tests
###############################################################################

class TestWebSocketServer:
    """Tests for WebSocketServer class."""

    @pytest.fixture
    def server(self):
        """Create a WebSocketServer instance."""
        return WebSocketServer(host="127.0.0.1", port=8766)

    def test_server_initialization(self, server):
        """Test server initializes correctly."""
        assert server.host == "127.0.0.1"
        assert server.port == 8766
        assert len(server._handlers) == 3

    def test_get_actions(self, server):
        """Test getting all supported actions."""
        actions = server.get_actions()

        assert "scan.start" in actions
        assert "port.list" in actions
        assert "tools.subnet_test" in actions

    @pytest.mark.asyncio
    async def test_handle_message_valid(self, server):
        """Test handling a valid message."""
        mock_ws = AsyncMock()

        message = json.dumps({
            "type": "request",
            "action": "port.list",
            "id": "test-1"
        })

        with patch.object(server._port_handler, '_handle_list') as mock_handler:
            mock_handler.return_value = ["small", "medium", "large"]

            await server._handle_message("client-1", mock_ws, message)

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["type"] == "response"
            assert sent_data["success"] is True

    @pytest.mark.asyncio
    async def test_handle_message_invalid_json(self, server):
        """Test handling invalid JSON."""
        mock_ws = AsyncMock()

        await server._handle_message("client-1", mock_ws, "not valid json")

        mock_ws.send.assert_called_once()
        sent_data = json.loads(mock_ws.send.call_args[0][0])
        assert sent_data["type"] == "error"
        assert "Invalid JSON" in sent_data["error"]

    @pytest.mark.asyncio
    async def test_handle_message_unknown_action(self, server):
        """Test handling an unknown action."""
        mock_ws = AsyncMock()

        message = json.dumps({
            "type": "request",
            "action": "unknown.action",
            "id": "test-1"
        })

        await server._handle_message("client-1", mock_ws, message)

        mock_ws.send.assert_called_once()
        sent_data = json.loads(mock_ws.send.call_args[0][0])
        assert sent_data["type"] == "error"
        assert "Unknown action" in sent_data["error"]

    def test_cleanup_client(self, server):
        """Test cleaning up client resources."""
        # Add a client
        server._clients["client-1"] = MagicMock()

        # Cleanup
        server._cleanup_client("client-1")

        assert "client-1" not in server._clients


# Integration Tests
###############################################################################

class TestWebSocketIntegration:
    """Integration tests for the WebSocket interface."""

    @pytest.mark.asyncio
    async def test_server_start_stop(self):
        """Test starting and stopping the server."""
        server = WebSocketServer(host="127.0.0.1", port=18766)

        # Start server
        await server.start()
        assert server._running is True
        assert server._server is not None

        # Stop server
        await server.stop()
        assert server._running is False

    @pytest.mark.asyncio
    async def test_full_scan_event_flow(self):
        """
        Run a full scan via WebSocket, subscribe to updates, and verify scan.update and scan.complete events.
        """
        import websockets
        from tests.test_globals import TEST_SUBNET
        from lanscape.core.scan_config import ScanType

        server = WebSocketServer(host="127.0.0.1", port=18769)
        await server.start()

        try:
            async with websockets.connect("ws://127.0.0.1:18769") as ws:
                # Receive welcome message
                welcome = await asyncio.wait_for(ws.recv(), timeout=5.0)
                welcome_data = json.loads(welcome)
                assert welcome_data["type"] == "event"
                assert welcome_data["event"] == "connection.established"
                client_id = welcome_data["data"]["client_id"]

                # Start a scan (use first subnet from TEST_SUBNET)
                test_subnet = str(TEST_SUBNET).split(",")[0].strip()
                scan_config = {
                    "subnet": test_subnet,
                    "port_list": "small",
                    "lookup_type": [ScanType.ICMP.value, ScanType.POKE_THEN_ARP.value],
                    "t_cnt_isalive": 2,
                    "ping_config": {"timeout": 0.8, "attempts": 2}
                }
                start_req = {
                    "type": "request",
                    "id": "scan-1",
                    "action": "scan.start",
                    "params": scan_config
                }
                await ws.send(json.dumps(start_req))
                start_resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
                start_data = json.loads(start_resp)
                assert start_data["type"] == "response"
                assert start_data["id"] == "scan-1"
                assert start_data["success"] is True
                scan_id = start_data["data"]["scan_id"]

                # Subscribe to scan updates
                subscribe_req = {
                    "type": "request",
                    "id": "sub-1",
                    "action": "scan.subscribe",
                    "params": {"scan_id": scan_id, "client_id": client_id}
                }
                await ws.send(json.dumps(subscribe_req))
                subscribe_resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
                subscribe_data = json.loads(subscribe_resp)
                assert subscribe_data["type"] == "response"
                assert subscribe_data["id"] == "sub-1"
                assert subscribe_data["success"] is True
                assert subscribe_data["data"]["subscribed"] is True

                # Collect scan.update and scan.complete events
                got_update = False
                got_complete = False
                max_events = 30
                for _ in range(max_events):
                    event_msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
                    event_data = json.loads(event_msg)
                    if event_data.get("type") == "event":
                        if event_data.get("event") == "scan.update":
                            got_update = True
                            # Check for percent_complete in metadata
                            assert "metadata" in event_data["data"]
                            assert "percent_complete" in event_data["data"]["metadata"]
                        if event_data.get("event") == "scan.complete":
                            got_complete = True
                            # Should have running: False and stage: complete
                            meta = event_data["data"].get("metadata", {})
                            assert meta.get("running") is False
                            assert meta.get("stage") == "complete"
                            break
                assert got_update, "Did not receive scan.update event"
                assert got_complete, "Did not receive scan.complete event"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_client_connection(self):
        """Test client connection and disconnection."""
        server = WebSocketServer(host="127.0.0.1", port=18767)
        await server.start()

        try:
            import websockets
            async with websockets.connect("ws://127.0.0.1:18767") as ws:
                # Should receive welcome message
                welcome = await asyncio.wait_for(ws.recv(), timeout=5.0)
                data = json.loads(welcome)

                assert data["type"] == "event"
                assert data["event"] == "connection.established"
                assert "client_id" in data["data"]
                assert "actions" in data["data"]
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_request_response(self):
        """Test sending a request and receiving a response."""
        server = WebSocketServer(host="127.0.0.1", port=18768)
        await server.start()

        try:
            import websockets
            async with websockets.connect("ws://127.0.0.1:18768") as ws:
                # Skip welcome message
                await ws.recv()

                # Send request
                request = {
                    "type": "request",
                    "id": "test-1",
                    "action": "tools.subnet_test",
                    "params": {"subnet": "192.168.1.1"}
                }
                await ws.send(json.dumps(request))

                # Receive response
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                data = json.loads(response)

                assert data["type"] == "response"
                assert data["id"] == "test-1"
                assert data["success"] is True
                assert data["data"]["valid"] is True
        finally:
            await server.stop()
