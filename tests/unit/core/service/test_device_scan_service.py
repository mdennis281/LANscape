"""
Tests for Device.scan_service() error propagation.
Ensures that service-scan errors (timeouts, exceptions, error field)
are properly recorded in device.caught_errors.
"""
from unittest.mock import patch

import pytest

from lanscape.core.net_tools import Device
from lanscape.core.net_tools.device import MacSelector
from lanscape.core.errors import DeviceError
from lanscape.core.service_scan import ServiceScanResult
from lanscape.core.scan_config import ServiceScanConfig


@pytest.fixture
def device() -> Device:
    """Create a basic Device for testing."""
    return Device(ip="192.168.1.100")


@pytest.fixture
def cfg() -> ServiceScanConfig:
    """Create a basic ServiceScanConfig."""
    return ServiceScanConfig(timeout=1.0)


class TestDeviceScanServiceErrorPropagation:
    """Ensure errors from service scanning reach device.caught_errors."""

    def test_scan_service_exception_caught(self, device: Device, cfg: ServiceScanConfig):
        """When scan_service() raises, the error is appended to caught_errors."""
        with patch(
            "lanscape.core.net_tools.device.scan_service",
            side_effect=RuntimeError("connection failed"),
        ):
            device.scan_service(80, cfg)

        assert len(device.caught_errors) == 1
        err = device.caught_errors[0]
        assert isinstance(err, DeviceError)
        assert "connection failed" in str(err)

    def test_scan_service_error_field_propagated(
        self, device: Device, cfg: ServiceScanConfig
    ):
        """When the result carries an error string, it becomes a caught_error."""
        mock_result = ServiceScanResult(
            service="Unknown",
            probes_sent=0,
            probes_received=0,
            error="Timeout scanning 192.168.1.100:80",
        )
        with patch(
            "lanscape.core.net_tools.device.scan_service",
            return_value=mock_result,
        ):
            device.scan_service(80, cfg)

        assert len(device.caught_errors) == 1
        err = device.caught_errors[0]
        assert isinstance(err, DeviceError)
        assert "Timeout" in str(err)

    def test_scan_service_error_field_still_records_service(
        self, device: Device, cfg: ServiceScanConfig
    ):
        """Even with an error, the service/port data is still recorded."""
        mock_result = ServiceScanResult(
            service="Unknown",
            probes_sent=0,
            probes_received=0,
            error="Timeout scanning 192.168.1.100:443",
        )
        with patch(
            "lanscape.core.net_tools.device.scan_service",
            return_value=mock_result,
        ):
            device.scan_service(443, cfg)

        # Error is recorded
        assert len(device.caught_errors) == 1
        # Service mapping is still updated
        assert "Unknown" in device.services
        assert 443 in device.services["Unknown"]
        # Service info is still stored
        assert len(device.service_info) == 1
        assert device.service_info[0].port == 443

    def test_scan_service_no_error_on_success(
        self, device: Device, cfg: ServiceScanConfig
    ):
        """A successful scan should not add anything to caught_errors."""
        mock_result = ServiceScanResult(
            service="HTTP",
            response="HTTP/1.1 200 OK",
            request="GET / HTTP/1.1",
            probes_sent=3,
            probes_received=1,
        )
        with patch(
            "lanscape.core.net_tools.device.scan_service",
            return_value=mock_result,
        ):
            device.scan_service(80, cfg)

        assert len(device.caught_errors) == 0
        assert "HTTP" in device.services
        assert 80 in device.services["HTTP"]

    def test_scan_service_exception_does_not_record_service(
        self, device: Device, cfg: ServiceScanConfig
    ):
        """When scan_service() raises, no service data should be recorded."""
        with patch(
            "lanscape.core.net_tools.device.scan_service",
            side_effect=OSError("network unreachable"),
        ):
            device.scan_service(22, cfg)

        assert len(device.caught_errors) == 1
        assert device.services == {}
        assert device.service_info == []


class TestMacSelector:
    """Tests for MacSelector.choose_mac resilience and correctness."""

    def test_choose_mac_single(self):
        """Single MAC should be returned immediately."""
        sel = MacSelector()
        assert sel.choose_mac(["AA:BB:CC:DD:EE:FF"]) == "AA:BB:CC:DD:EE:FF"

    def test_choose_mac_least_seen(self):
        """Should return the MAC seen the fewest times."""
        sel = MacSelector()
        sel.import_macs(["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"])
        sel.import_macs(["AA:AA:AA:AA:AA:AA"])  # AA seen twice
        result = sel.choose_mac(["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"])
        assert result == "BB:BB:BB:BB:BB:BB"

    def test_choose_mac_unknown_mac_no_keyerror(self):
        """MACs not previously imported should not raise KeyError."""
        sel = MacSelector()
        sel.import_macs(["AA:AA:AA:AA:AA:AA"])
        # CC was never imported — should safely default to count 0
        result = sel.choose_mac(["AA:AA:AA:AA:AA:AA", "CC:CC:CC:CC:CC:CC"])
        assert result == "CC:CC:CC:CC:CC:CC"

    def test_choose_mac_all_unknown(self):
        """All unknown MACs should still return one without error."""
        sel = MacSelector()
        result = sel.choose_mac(["XX:XX:XX:XX:XX:XX", "YY:YY:YY:YY:YY:YY"])
        assert result in ("XX:XX:XX:XX:XX:XX", "YY:YY:YY:YY:YY:YY")

    def test_clear_resets_counts(self):
        """Clear should reset all MAC counts."""
        sel = MacSelector()
        sel.import_macs(["AA:AA:AA:AA:AA:AA"])
        sel.clear()
        assert not sel.macs
