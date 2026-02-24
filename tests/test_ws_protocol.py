"""
Unit tests for the LANscape WebSocket protocol and delta tracking.

Tests cover:
- Protocol classes (WSRequest, WSResponse, WSError, WSEvent)
- Delta tracking (DeltaTracker, ScanDeltaTracker)
- BaseHandler registration and dispatch
"""

import json
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
        params = request.model_dump()["params"]
        assert params["subnet"] == "192.168.1.0/24"

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
        data = response.model_dump()["data"]
        assert data["scan_id"] == "abc-123"
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
        data = event.model_dump()["data"]
        assert data["scan_id"] == "abc-123"

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


# BaseHandler Tests
###############################################################################

class TestBaseHandler:
    """Tests for BaseHandler class."""

    @staticmethod
    def _make_handler(prefix_name: str = "test") -> BaseHandler:
        """Create a concrete BaseHandler subclass for testing."""
        class ConcreteHandler(BaseHandler):
            """Test handler implementation."""
            @property
            def prefix(self):
                return prefix_name
        return ConcreteHandler()

    def test_register_action(self):
        """Test registering an action handler."""
        handler = self._make_handler()
        handler.register("action1", lambda p, s: {"result": "ok"})

        assert handler.can_handle("test.action1")
        assert not handler.can_handle("test.action2")

    def test_get_actions(self):
        """Test getting all registered actions."""
        handler = self._make_handler()
        handler.register("action1", lambda p, s: {})
        handler.register("action2", lambda p, s: {})

        actions = handler.get_actions()

        assert "test.action1" in actions
        assert "test.action2" in actions

    def test_invoke(self):
        """Test invoking a handler directly via the public invoke method."""
        handler = self._make_handler()
        handler.register("echo", lambda p, s: p)

        result = handler.invoke("echo", {"msg": "hello"})
        assert result == {"msg": "hello"}

    def test_invoke_unknown_action(self):
        """Test invoking an unregistered action raises KeyError."""
        handler = self._make_handler()

        with pytest.raises(KeyError, match="No handler registered"):
            handler.invoke("nope")

    @pytest.mark.asyncio
    async def test_handle_success(self):
        """Test handling a request successfully."""
        handler = self._make_handler()
        handler.register("echo", lambda p, s: p)

        request = WSRequest(id="1", action="test.echo", params={"msg": "hello"})
        response = await handler.handle(request)

        assert isinstance(response, WSResponse)
        assert response.success is True
        assert response.data == {"msg": "hello"}

    @pytest.mark.asyncio
    async def test_handle_error(self):
        """Test handling a request that raises an error."""
        handler = self._make_handler()

        def failing_handler(params, send_event):
            raise ValueError("Test error")

        handler.register("fail", failing_handler)

        request = WSRequest(id="1", action="test.fail")
        response = await handler.handle(request)

        assert isinstance(response, WSError)
        assert "Test error" in response.error

    @pytest.mark.asyncio
    async def test_handle_unknown_action(self):
        """Test handling an unknown action."""
        handler = self._make_handler()
        request = WSRequest(id="1", action="test.unknown")
        response = await handler.handle(request)

        assert isinstance(response, WSError)
        assert "Unknown action" in response.error
