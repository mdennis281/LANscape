"""
Unit tests for the LANscape WebSocket handlers, server, and integration.

Tests cover:
- Handler classes (ScanHandler, PortHandler, ToolsHandler)
- WebSocket server functionality
- End-to-end WebSocket integration
"""
# pylint: disable=protected-access

import asyncio
import json
from unittest.mock import MagicMock, patch, AsyncMock
import pytest
import websockets

from tests.test_globals import TEST_SUBNET
from lanscape.core.scan_config import ScanType
from lanscape.ui.ws.handlers.scan import ScanHandler
from lanscape.ui.ws.handlers.port import PortHandler
from lanscape.ui.ws.handlers.tools import ToolsHandler
from lanscape.ui.ws.server import WebSocketServer


# Handler Tests
###############################################################################

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
        result = scan_handler.invoke("start", params)

        assert result["scan_id"] == "test-scan-123"
        assert result["status"] == "running"

    def test_handle_get_missing_scan(self, scan_handler, mock_scan_manager):
        """Test getting a non-existent scan."""
        mock_scan_manager.get_scan.return_value = None

        with pytest.raises(ValueError, match="Scan not found"):
            scan_handler.invoke("get", {"scan_id": "nonexistent"})

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

        result = scan_handler.invoke("summary", {"scan_id": "test-scan-123"})

        assert result["metadata"]["running"] is True
        assert result["metadata"]["percent_complete"] == 50
        assert result["metadata"]["stage"] == "scanning devices"
        assert result["metadata"]["devices_scanned"] == 128
        assert result["metadata"]["devices_alive"] == 2

    def test_handle_subscribe(self, scan_handler, mock_scan_manager):
        """Test subscribing to scan updates."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        result = scan_handler.invoke(
            "subscribe",
            {"scan_id": "scan-123", "client_id": "client-abc"},
        )

        assert result["subscribed"] is True
        assert "client-abc" in scan_handler.get_subscriptions("scan-123")

    def test_handle_unsubscribe(self, scan_handler, mock_scan_manager):
        """Test unsubscribing from scan updates."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        scan_handler.invoke(
            "subscribe",
            {"scan_id": "scan-123", "client_id": "client-abc"},
        )

        result = scan_handler.invoke(
            "unsubscribe",
            {"scan_id": "scan-123", "client_id": "client-abc"},
        )

        assert result["unsubscribed"] is True
        assert "client-abc" not in scan_handler.get_subscriptions("scan-123")

    def test_cleanup_client(self, scan_handler, mock_scan_manager):
        """Test cleaning up client subscriptions."""
        mock_scan = MagicMock()
        mock_scan_manager.get_scan.return_value = mock_scan

        scan_handler.invoke(
            "subscribe",
            {"scan_id": "scan-1", "client_id": "client-abc"},
        )
        scan_handler.invoke(
            "subscribe",
            {"scan_id": "scan-2", "client_id": "client-abc"},
        )

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
        mock_port_manager.get_port_lists.return_value = [
            "small", "medium", "large"
        ]

        result = port_handler.invoke("list")

        assert result == ["small", "medium", "large"]

    def test_handle_list_summary(self, port_handler, mock_port_manager):
        """Test listing port lists with counts."""
        mock_port_manager.get_port_lists.return_value = ["small", "medium"]
        mock_port_manager.get_port_list.side_effect = [
            {"22": "ssh", "80": "http"},
            {"22": "ssh", "80": "http", "443": "https", "8080": "http-alt"}
        ]

        result = port_handler.invoke("list_summary")

        assert len(result) == 2
        assert result[0]["name"] == "small"
        assert result[0]["count"] == 2
        assert result[1]["name"] == "medium"
        assert result[1]["count"] == 4

    def test_handle_get(self, port_handler, mock_port_manager):
        """Test getting a port list."""
        mock_port_manager.get_port_list.return_value = {
            "22": "ssh", "80": "http"
        }

        result = port_handler.invoke("get", {"name": "small"})

        assert result == {"22": "ssh", "80": "http"}

    def test_handle_create_success(self, port_handler, mock_port_manager):
        """Test creating a port list successfully."""
        mock_port_manager.create_port_list.return_value = True

        result = port_handler.invoke(
            "create",
            {"name": "custom", "ports": {"22": "ssh"}},
        )

        assert result["success"] is True
        assert result["name"] == "custom"

    def test_handle_create_failure(self, port_handler, mock_port_manager):
        """Test creating a port list that fails."""
        mock_port_manager.create_port_list.return_value = False

        with pytest.raises(ValueError, match="Failed to create"):
            port_handler.invoke(
                "create",
                {"name": "invalid", "ports": {}},
            )

    def test_handle_delete(self, port_handler, mock_port_manager):
        """Test deleting a port list."""
        mock_port_manager.delete_port_list.return_value = True

        result = port_handler.invoke("delete", {"name": "custom"})

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
        assert "tools.app_info" in actions

    def test_handle_subnet_test_empty(self, tools_handler):
        """Test validating an empty subnet."""
        result = tools_handler.invoke("subnet_test", {"subnet": ""})

        assert result["valid"] is False
        assert result["count"] == -1

    def test_handle_subnet_test_valid(self, tools_handler):
        """Test validating a valid subnet."""
        result = tools_handler.invoke(
            "subnet_test", {"subnet": "192.168.1.1"}
        )

        assert result["valid"] is True
        assert result["count"] == 1

    def test_handle_subnet_test_cidr(self, tools_handler):
        """Test validating a CIDR subnet."""
        result = tools_handler.invoke(
            "subnet_test", {"subnet": "192.168.1.0/30"}
        )

        assert result["valid"] is True
        assert result["count"] == 2

    def test_handle_subnet_test_invalid(self, tools_handler):
        """Test validating an invalid subnet."""
        result = tools_handler.invoke(
            "subnet_test", {"subnet": "not.a.subnet"}
        )

        assert result["valid"] is False

    def test_handle_subnet_list(self, tools_handler):
        """Test listing subnets."""
        with patch(
            'lanscape.ui.ws.handlers.tools.get_all_network_subnets'
        ) as mock_subnets, patch(
            'lanscape.ui.ws.handlers.tools.smart_select_primary_subnet',
            return_value='192.168.1.0/24',
        ):
            mock_subnets.return_value = [
                {"subnet": "192.168.1.0/24", "interface": "eth0"}
            ]

            result = tools_handler.invoke("subnet_list")

            assert len(result) == 1
            assert result[0]["subnet"] == "192.168.1.0/24"

    def test_handle_subnet_list_primary_sorted_first(self, tools_handler):
        """Test that smart-selected primary subnet is first."""
        subnets = [
            {"subnet": "172.17.0.0/16", "interface": "docker0",
             "address_cnt": 65534},
            {"subnet": "192.168.1.0/24", "interface": "eth0",
             "address_cnt": 254},
            {"subnet": "10.0.0.0/24", "interface": "wlan0",
             "address_cnt": 254},
        ]
        with patch(
            'lanscape.ui.ws.handlers.tools.get_all_network_subnets',
            return_value=subnets,
        ), patch(
            'lanscape.ui.ws.handlers.tools.smart_select_primary_subnet',
            return_value='192.168.1.0/24',
        ):
            result = tools_handler.invoke("subnet_list")

        assert len(result) == 3
        assert result[0]["subnet"] == "192.168.1.0/24"

    def test_handle_config_defaults(self, tools_handler):
        """Test getting default configs."""
        with patch(
            'lanscape.ui.ws.handlers.tools.is_arp_supported'
        ) as mock:
            mock.return_value = True

            result = tools_handler.invoke("config_defaults")

            assert "balanced" in result
            assert "accurate" in result
            assert "fast" in result

    def test_handle_arp_supported(self, tools_handler):
        """Test checking ARP support."""
        with patch(
            'lanscape.ui.ws.handlers.tools.is_arp_supported'
        ) as mock:
            mock.return_value = True
            result = tools_handler.invoke("arp_supported")
            assert result["supported"] is True

            mock.return_value = False
            result = tools_handler.invoke("arp_supported")
            assert result["supported"] is False

    def test_handle_app_info(self, tools_handler):
        """Test getting app info."""
        with patch(
            'lanscape.ui.ws.handlers.tools.get_installed_version',
            return_value='1.2.3',
        ), patch(
            'lanscape.ui.ws.handlers.tools.is_arp_supported',
            return_value=True,
        ), patch(
            'lanscape.ui.ws.handlers.tools.is_update_available',
            return_value=False,
        ), patch(
            'lanscape.ui.ws.handlers.tools.parse_args',
        ) as mock_args:
            mock_args.return_value.ui_port = 5001
            mock_args.return_value.ws_port = 8766
            mock_args.return_value.loglevel = 'INFO'
            mock_args.return_value.persistent = False
            mock_args.return_value.webapp_update = False
            mock_args.return_value.logfile = None

            result = tools_handler.invoke("app_info")

            assert result["name"] == "LANscape"
            assert result["version"] == "1.2.3"
            assert result["arp_supported"] is True
            assert result["update_available"] is False
            assert "runtime_args" in result
            assert result["runtime_args"]["ui_port"] == 5001

    def test_handle_app_info_with_update(self, tools_handler):
        """Test getting app info when update is available."""
        with patch(
            'lanscape.ui.ws.handlers.tools.get_installed_version',
            return_value='1.2.3',
        ), patch(
            'lanscape.ui.ws.handlers.tools.is_arp_supported',
            return_value=True,
        ), patch(
            'lanscape.ui.ws.handlers.tools.is_update_available',
            return_value=True,
        ), patch(
            'lanscape.ui.ws.handlers.tools.get_latest_version',
            return_value='1.3.0',
        ), patch(
            'lanscape.ui.ws.handlers.tools.parse_args',
        ) as mock_args:
            mock_args.return_value.ui_port = 5001
            mock_args.return_value.ws_port = 8766
            mock_args.return_value.loglevel = 'INFO'
            mock_args.return_value.persistent = False
            mock_args.return_value.webapp_update = False
            mock_args.return_value.logfile = None

            result = tools_handler.invoke("app_info")

            assert result["update_available"] is True
            assert result["latest_version"] == "1.3.0"


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
        assert len(server.handlers) == 3

    def test_server_debug_mode(self):
        """Test server registers DebugHandler when debug_mode=True."""
        server = WebSocketServer(host="127.0.0.1", port=8766, debug_mode=True)
        assert len(server.handlers) == 4

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

        with patch.object(
            server.port_handler, '_handle_list'
        ) as mock_handler:
            mock_handler.return_value = ["small", "medium", "large"]

            await server.handle_message("client-1", mock_ws, message)

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["type"] == "response"
            assert sent_data["success"] is True

    @pytest.mark.asyncio
    async def test_handle_message_invalid_json(self, server):
        """Test handling invalid JSON."""
        mock_ws = AsyncMock()

        await server.handle_message(
            "client-1", mock_ws, "not valid json"
        )

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

        await server.handle_message("client-1", mock_ws, message)

        mock_ws.send.assert_called_once()
        sent_data = json.loads(mock_ws.send.call_args[0][0])
        assert sent_data["type"] == "error"
        assert "Unknown action" in sent_data["error"]

    def test_cleanup_client(self, server):
        """Test cleaning up client resources."""
        server.clients["client-1"] = MagicMock()

        server.cleanup_client("client-1")

        assert "client-1" not in server.clients


# Scan Completion Race Condition Tests
###############################################################################

class TestScanCompletionBroadcast:
    """Tests for _send_scan_finished_to_subscribers stage defense."""

    @pytest.fixture
    def server(self):
        """Create a WebSocketServer instance."""
        return WebSocketServer(host="127.0.0.1", port=8766)

    @pytest.mark.asyncio
    async def test_finished_forces_complete_when_stage_stale(self, server):
        """If a scan's stage is still 'testing ports' when the finished event
        fires, the backend must override it to 'complete'."""
        mock_ws = AsyncMock()
        client_id = "client-1"
        server._clients[client_id] = mock_ws

        # Build a mock scan whose stage hasn't caught up yet
        mock_scan = MagicMock()
        mock_scan.uid = "scan-123"
        mock_scan.running = False
        mock_scan.results.stage = "testing ports"  # stale!

        # Register subscription
        server.scan_handler._subscriptions = {"scan-123": {client_id}}
        # Stub _handle_get_delta to return a delta with metadata
        server.scan_handler._handle_get_delta = MagicMock(return_value={
            "scan_id": "scan-123",
            "has_changes": False,
            "metadata": {"percent_complete": 100},
        })

        await server._send_scan_finished_to_subscribers(mock_scan)

        mock_ws.send.assert_called_once()
        sent = json.loads(mock_ws.send.call_args[0][0])

        assert sent["event"] == "scan.complete"
        assert sent["data"]["metadata"]["stage"] == "complete"
        assert sent["data"]["metadata"]["running"] is False

    @pytest.mark.asyncio
    async def test_finished_preserves_terminated_stage(self, server):
        """A terminated scan must keep its 'terminated' stage untouched."""
        mock_ws = AsyncMock()
        client_id = "client-1"
        server._clients[client_id] = mock_ws

        mock_scan = MagicMock()
        mock_scan.uid = "scan-456"
        mock_scan.running = False
        mock_scan.results.stage = "terminated"

        server.scan_handler._subscriptions = {"scan-456": {client_id}}
        server.scan_handler._handle_get_delta = MagicMock(return_value={
            "scan_id": "scan-456",
            "has_changes": False,
            "metadata": {"percent_complete": 50},
        })

        await server._send_scan_finished_to_subscribers(mock_scan)

        sent = json.loads(mock_ws.send.call_args[0][0])
        assert sent["event"] == "scan.terminated"
        assert sent["data"]["metadata"]["stage"] == "terminated"

    @pytest.mark.asyncio
    async def test_active_scan_transitions_to_finished(self, server):
        """_send_updates_for_active_scans detects a newly-finished scan
        and delegates to _send_scan_finished_to_subscribers."""
        mock_scan = MagicMock()
        mock_scan.uid = "scan-789"
        mock_scan.running = False
        mock_scan.results.stage = "complete"

        server._scan_handler._scan_manager.scans = [mock_scan]
        server._previously_running_scans = {"scan-789"}

        with patch.object(
            server, '_send_scan_finished_to_subscribers', new_callable=AsyncMock
        ) as mock_finished:
            await server._send_updates_for_active_scans()
            mock_finished.assert_awaited_once_with(mock_scan)

        # scan-789 should no longer be in the previously_running set
        assert "scan-789" not in server._previously_running_scans


# Integration Tests
###############################################################################

class TestWebSocketIntegration:
    """Integration tests for the WebSocket interface."""

    @pytest.mark.asyncio
    async def test_server_start_stop(self):
        """Test starting and stopping the server."""
        server = WebSocketServer(host="127.0.0.1", port=18766)

        await server.start()
        assert server.running is True

        await server.stop()
        assert server.running is False

    @pytest.mark.asyncio
    async def test_client_connection(self):
        """Test client connection and disconnection."""
        server = WebSocketServer(host="127.0.0.1", port=18767)
        await server.start()

        try:
            async with websockets.connect(
                "ws://127.0.0.1:18767"
            ) as ws:
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
            async with websockets.connect(
                "ws://127.0.0.1:18768"
            ) as ws:
                await ws.recv()  # skip welcome

                request = {
                    "type": "request",
                    "id": "test-1",
                    "action": "tools.subnet_test",
                    "params": {"subnet": "192.168.1.1"}
                }
                await ws.send(json.dumps(request))

                response = await asyncio.wait_for(
                    ws.recv(), timeout=5.0
                )
                data = json.loads(response)

                assert data["type"] == "response"
                assert data["id"] == "test-1"
                assert data["success"] is True
                assert data["data"]["valid"] is True
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_full_scan_event_flow(self):
        """Run a full scan via WebSocket and verify events."""
        server = WebSocketServer(host="127.0.0.1", port=18769)
        await server.start()

        try:
            async with websockets.connect(
                "ws://127.0.0.1:18769"
            ) as ws:
                client_id = await self._recv_client_id(ws)
                await self._start_and_subscribe(
                    ws, client_id
                )
                await self._verify_scan_events(ws)
        finally:
            await server.stop()

    @staticmethod
    async def _recv_client_id(ws) -> str:
        """Receive welcome and extract client_id."""
        welcome = await asyncio.wait_for(ws.recv(), timeout=5.0)
        data = json.loads(welcome)
        assert data["type"] == "event"
        assert data["event"] == "connection.established"
        return data["data"]["client_id"]

    @staticmethod
    async def _start_and_subscribe(ws, client_id: str) -> str:
        """Start a scan, subscribe, and return scan_id."""
        test_subnet = str(TEST_SUBNET).split(",", maxsplit=1)[0].strip()

        start_req = {
            "type": "request",
            "id": "scan-1",
            "action": "scan.start",
            "params": {
                "subnet": test_subnet,
                "port_list": "small",
                "lookup_type": [
                    ScanType.ICMP.value,
                    ScanType.POKE_THEN_ARP.value,
                ],
                "t_cnt_isalive": 2,
                "ping_config": {"timeout": 1.0, "attempts": 2},
            },
        }
        await ws.send(json.dumps(start_req))
        start_resp = await asyncio.wait_for(ws.recv(), timeout=10.0)
        start_data = json.loads(start_resp)
        assert start_data["type"] == "response"
        assert start_data["success"] is True
        scan_id = start_data["data"]["scan_id"]

        sub_req = {
            "type": "request",
            "id": "sub-1",
            "action": "scan.subscribe",
            "params": {
                "scan_id": scan_id,
                "client_id": client_id,
            },
        }
        await ws.send(json.dumps(sub_req))
        sub_resp = await asyncio.wait_for(ws.recv(), timeout=10.0)
        sub_data = json.loads(sub_resp)
        assert sub_data["success"] is True
        assert sub_data["data"]["subscribed"] is True
        return scan_id

    @staticmethod
    async def _verify_scan_events(ws) -> None:
        """Collect events and verify update + complete arrived."""
        got_update = False
        got_complete = False

        for _ in range(100):
            try:
                msg = await asyncio.wait_for(
                    ws.recv(), timeout=60.0
                )
            except asyncio.TimeoutError:
                break
            event = json.loads(msg)
            if event.get("type") != "event":
                continue
            name = event.get("event")
            if name == "scan.update":
                got_update = True
                assert "metadata" in event["data"]
                assert "percent_complete" in event["data"]["metadata"]
            if name == "scan.complete":
                got_complete = True
                meta = event["data"].get("metadata", {})
                assert meta.get("running") is False
                assert meta.get("stage") == "complete"
                break

        assert got_update, "Did not receive scan.update event"
        assert got_complete, "Did not receive scan.complete event"
