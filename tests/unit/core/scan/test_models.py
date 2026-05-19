"""
Tests for the Pydantic models in lanscape.core.models.

These tests cover:
- DeviceStage and ScanStage enums
- DeviceErrorInfo and DeviceResult models
- ScanMetadata, ScanResults, ScanDelta, ScanSummary, ScanListItem models
- Serialization/deserialization
- Validation
- Computed fields
- Integration with Device and ScannerResults classes
"""

import socket

import pytest
from pydantic import ValidationError

from lanscape.core.models import (
    DeviceStage,
    ScanStage,
    DeviceErrorInfo,
    DeviceResult,
    ScanMetadata,
    ScanResults,
    ScanDelta,
    ScanSummary,
    ScanListItem,
)
from lanscape.core.net_tools import Device
from lanscape.core.errors import DeviceError


class TestDeviceStageEnum:
    """Tests for DeviceStage enum."""

    def test_device_stage_values(self):
        """Test that DeviceStage has expected values."""
        assert DeviceStage.FOUND.value == "found"
        assert DeviceStage.SCANNING.value == "scanning"
        assert DeviceStage.COMPLETE.value == "complete"

    def test_device_stage_is_string(self):
        """Test that DeviceStage can be used as string."""
        assert str(DeviceStage.FOUND) == "DeviceStage.FOUND"
        assert DeviceStage.FOUND == "found"


class TestScanStageEnum:
    """Tests for ScanStage enum."""

    def test_scan_stage_values(self):
        """Test that ScanStage has expected values."""
        assert ScanStage.INSTANTIATED.value == "instantiated"
        assert ScanStage.SCANNING_DEVICES.value == "scanning devices"
        assert ScanStage.TESTING_PORTS.value == "testing ports"
        assert ScanStage.COMPLETE.value == "complete"
        assert ScanStage.TERMINATING.value == "terminating"
        assert ScanStage.TERMINATED.value == "terminated"

    def test_scan_stage_is_string(self):
        """Test that ScanStage can be used as string."""
        assert ScanStage.COMPLETE == "complete"


class TestDeviceErrorInfo:
    """Tests for DeviceErrorInfo model."""

    def test_create_device_error_info(self):
        """Test creating DeviceErrorInfo with all fields."""
        error = DeviceErrorInfo(
            source="test_method",
            message="Test error message",
            traceback="Traceback info here"
        )
        assert error.source == "test_method"
        assert error.message == "Test error message"
        assert error.traceback == "Traceback info here"

    def test_device_error_info_optional_traceback(self):
        """Test that traceback is optional."""
        error = DeviceErrorInfo(
            source="test_method",
            message="Test error message"
        )
        assert error.traceback is None

    def test_device_error_info_serialization(self):
        """Test serialization to dict."""
        error = DeviceErrorInfo(
            source="test_method",
            message="Test error message"
        )
        data = error.model_dump()
        assert data["source"] == "test_method"
        assert data["message"] == "Test error message"
        assert data["traceback"] is None

    def test_device_error_info_json_mode(self):
        """Test JSON serialization mode."""
        error = DeviceErrorInfo(
            source="test_method",
            message="Test error message"
        )
        data = error.model_dump(mode='json')
        assert isinstance(data, dict)
        assert data["source"] == "test_method"


class TestDeviceResult:
    """Tests for DeviceResult model."""

    def test_create_device_result_minimal(self):
        """Test creating DeviceResult with minimal fields."""
        device = DeviceResult(ip="192.168.1.1")
        assert device.ip == "192.168.1.1"
        assert device.alive is None
        assert device.hostname is None
        assert device.macs == []
        assert device.manufacturer is None
        assert device.ports == []
        assert device.stage == DeviceStage.FOUND
        assert device.services == {}
        assert device.errors == []

    def test_create_device_result_full(self):
        """Test creating DeviceResult with all fields."""
        device = DeviceResult(
            ip="192.168.1.100",
            alive=True,
            hostname="mydevice.local",
            macs=["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
            manufacturer="Apple Inc.",
            ports=[22, 80, 443],
            stage=DeviceStage.COMPLETE,
            ports_scanned=100,
            services={"ssh": [22], "http": [80, 443]},
            errors=[]
        )
        assert device.ip == "192.168.1.100"
        assert device.alive is True
        assert device.hostname == "mydevice.local"
        assert len(device.macs) == 2
        assert device.ports == [22, 80, 443]
        assert device.stage == DeviceStage.COMPLETE

    def test_device_result_computed_mac_addr(self):
        """Test computed mac_addr field returns first MAC."""
        device = DeviceResult(
            ip="192.168.1.1",
            macs=["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        )
        assert device.mac_addr == "AA:BB:CC:DD:EE:FF"

    def test_device_result_computed_mac_addr_empty(self):
        """Test computed mac_addr returns empty string when no MACs."""
        device = DeviceResult(ip="192.168.1.1")
        assert device.mac_addr == ""

    def test_device_result_serialization(self):
        """Test serialization includes computed field."""
        device = DeviceResult(
            ip="192.168.1.1",
            macs=["AA:BB:CC:DD:EE:FF"]
        )
        data = device.model_dump()
        assert "mac_addr" in data
        assert data["mac_addr"] == "AA:BB:CC:DD:EE:FF"

    def test_device_result_with_errors(self):
        """Test DeviceResult with error information."""
        device = DeviceResult(
            ip="192.168.1.1",
            errors=[
                DeviceErrorInfo(source="hostname", message="DNS lookup failed")
            ]
        )
        assert len(device.errors) == 1
        assert device.errors[0].source == "hostname"

    def test_device_result_stage_enum_serialization(self):
        """Test that stage enum serializes to string value."""
        device = DeviceResult(ip="192.168.1.1", stage=DeviceStage.SCANNING)
        data = device.model_dump(mode='json')
        assert data["stage"] == "scanning"

    def test_device_result_validation_ip_required(self):
        """Test that IP is required."""
        with pytest.raises(ValidationError):
            DeviceResult()  # type: ignore


class TestDeviceToResult:
    """Tests for Device.to_result() method."""

    def test_device_to_result_basic(self):
        """Test converting Device to DeviceResult."""
        device = Device(ip="192.168.1.1")
        result = device.to_result()
        assert isinstance(result, DeviceResult)
        assert result.ip == "192.168.1.1"

    def test_device_to_result_with_data(self):
        """Test converting Device with data to DeviceResult."""
        device = Device(
            ip="192.168.1.100",
            alive=True,
            hostname="test.local",
            macs=["AA:BB:CC:DD:EE:FF"],
            manufacturer="Test Corp",
            ports=[22, 80],
            stage="complete",
            services={"ssh": [22]}
        )
        result = device.to_result()
        assert result.ip == "192.168.1.100"
        assert result.alive is True
        assert result.hostname == "test.local"
        assert result.macs == ["AA:BB:CC:DD:EE:FF"]
        assert result.ports == [22, 80]
        assert result.stage == DeviceStage.COMPLETE

    def test_device_to_result_with_errors(self):
        """Test converting Device with caught_errors."""
        device = Device(ip="192.168.1.1")
        # Simulate a caught error
        try:
            raise socket.herror(1, "Host not found")
        except socket.herror as e:
            device.caught_errors.append(DeviceError(e))

        result = device.to_result()
        assert len(result.errors) == 1
        assert "Host not found" in result.errors[0].message

    def test_device_to_result_stage_mapping(self):
        """Test that stage strings map to DeviceStage enum."""
        for stage_str, expected_enum in [
            ("found", DeviceStage.FOUND),
            ("scanning", DeviceStage.SCANNING),
            ("complete", DeviceStage.COMPLETE),
        ]:
            device = Device(ip="192.168.1.1", stage=stage_str)
            result = device.to_result()
            assert result.stage == expected_enum


class TestScanMetadata:
    """Tests for ScanMetadata model."""

    def test_create_scan_metadata_minimal(self):
        """Test creating ScanMetadata with required fields."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=True,
            stage=ScanStage.SCANNING_DEVICES
        )
        assert metadata.scan_id == "test-123"
        assert metadata.subnet == "192.168.1.0/24"
        assert metadata.running is True

    def test_create_scan_metadata_full(self):
        """Test creating ScanMetadata with all fields."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=False,
            stage=ScanStage.COMPLETE,
            percent_complete=100,
            devices_total=254,
            devices_scanned=254,
            devices_alive=10,
            port_list_length=100,
            start_time=1000.0,
            end_time=1060.0,
            run_time=60
        )
        assert metadata.percent_complete == 100
        assert metadata.devices_alive == 10
        assert metadata.run_time == 60

    def test_scan_metadata_stage_serialization(self):
        """Test that stage enum serializes correctly."""
        metadata = ScanMetadata(
            scan_id="test",
            subnet="10.0.0.0/24",
            port_list="common",
            running=True,
            stage=ScanStage.TESTING_PORTS
        )
        data = metadata.model_dump(mode='json')
        assert data["stage"] == "testing ports"


class TestScanResults:
    """Tests for ScanResults model."""

    def test_create_scan_results(self):
        """Test creating ScanResults with minimal data."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=False,
            stage=ScanStage.COMPLETE
        )
        results = ScanResults(
            metadata=metadata,
            devices=[],
            config={"subnet": "192.168.1.0/24"}
        )
        assert results.metadata.scan_id == "test-123"
        assert results.devices == []

    def test_scan_results_with_devices(self):
        """Test ScanResults with device data."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=False,
            stage=ScanStage.COMPLETE
        )
        devices = [
            DeviceResult(ip="192.168.1.1", alive=True),
            DeviceResult(ip="192.168.1.2", alive=True),
        ]
        results = ScanResults(
            metadata=metadata,
            devices=devices,
            config={}
        )
        assert len(results.devices) == 2

    def test_scan_results_serialization(self):
        """Test full serialization of ScanResults."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=False,
            stage=ScanStage.COMPLETE,
            devices_alive=1
        )
        device = DeviceResult(
            ip="192.168.1.1",
            alive=True,
            macs=["AA:BB:CC:DD:EE:FF"]
        )
        results = ScanResults(
            metadata=metadata,
            devices=[device],
            config={"subnet": "192.168.1.0/24"}
        )
        data = results.model_dump(mode='json')

        assert data["metadata"]["scan_id"] == "test-123"
        assert len(data["devices"]) == 1
        assert data["devices"][0]["ip"] == "192.168.1.1"
        assert data["devices"][0]["mac_addr"] == "AA:BB:CC:DD:EE:FF"


class TestScanDelta:
    """Tests for ScanDelta model."""

    def test_create_scan_delta(self):
        """Test creating ScanDelta with device changes."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            percent_complete=50
        )
        delta = ScanDelta(
            scan_id="test-123",
            running=True,
            has_changes=True,
            metadata=metadata,
            devices=[
                DeviceResult(ip="192.168.1.1", alive=True)
            ]
        )
        assert delta.scan_id == "test-123"
        assert len(delta.devices) == 1
        assert delta.has_changes is True

    def test_scan_delta_empty(self):
        """Test ScanDelta with no changes."""
        delta = ScanDelta(
            scan_id="test-123",
            running=True,
            has_changes=False,
            metadata=None,
            devices=[]
        )
        assert len(delta.devices) == 0
        assert delta.has_changes is False


class TestScanSummary:
    """Tests for ScanSummary model."""

    def test_create_scan_summary(self):
        """Test creating ScanSummary."""
        metadata = ScanMetadata(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            port_list="common",
            running=False,
            stage=ScanStage.COMPLETE,
            devices_alive=5
        )
        summary = ScanSummary(
            metadata=metadata,
            ports_found=[22, 80, 443],
            services_found=["ssh", "http"]
        )
        assert summary.metadata.devices_alive == 5
        assert len(summary.ports_found) == 3
        assert "ssh" in summary.services_found


class TestScanListItem:
    """Tests for ScanListItem model."""

    def test_create_scan_list_item(self):
        """Test creating ScanListItem."""
        item = ScanListItem(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            running=True,
            stage=ScanStage.SCANNING_DEVICES,
            percent_complete=25,
            devices_alive=3,
            devices_total=254
        )
        assert item.scan_id == "test-123"
        assert item.percent_complete == 25

    def test_scan_list_item_serialization(self):
        """Test ScanListItem JSON serialization."""
        item = ScanListItem(
            scan_id="test-123",
            subnet="192.168.1.0/24",
            running=False,
            stage=ScanStage.COMPLETE,
            percent_complete=100,
            devices_alive=10,
            devices_total=254
        )
        data = item.model_dump(mode='json')
        assert data["scan_id"] == "test-123"
        assert data["stage"] == "complete"


class TestModelDeserialization:
    """Tests for deserializing models from JSON/dict."""

    def test_device_result_from_dict(self):
        """Test creating DeviceResult from dict."""
        data = {
            "ip": "192.168.1.1",
            "alive": True,
            "hostname": "test.local",
            "macs": ["AA:BB:CC:DD:EE:FF"],
            "ports": [22, 80],
            "stage": "complete"
        }
        device = DeviceResult.model_validate(data)
        assert device.ip == "192.168.1.1"
        assert device.stage == DeviceStage.COMPLETE

    def test_scan_metadata_from_dict(self):
        """Test creating ScanMetadata from dict."""
        data = {
            "scan_id": "test-123",
            "subnet": "192.168.1.0/24",
            "port_list": "common",
            "running": False,
            "stage": "complete",
            "start_time": 1000.0
        }
        metadata = ScanMetadata.model_validate(data)
        assert metadata.scan_id == "test-123"
        assert metadata.stage == ScanStage.COMPLETE
