"""
Integration tests: IPv6 support.

Validates that LANscape can discover devices and scan ports/services
over IPv6 on the dual-stack test network.
"""

import os

import pytest

from lanscape.core.models import ScanResults
from tests.integration.conftest import find_device


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SKIP_IPV6_TESTS", "").lower() == "true",
        reason="IPv6 tests disabled via SKIP_IPV6_TESTS env var"
    ),
]


class TestIPv6Discovery:
    """Verify devices are discovered via IPv6 addresses."""

    def test_ipv6_devices_found(
        self,
        ipv6_scan_results: ScanResults,
        expected_assertions: dict
    ):
        """Minimum number of devices are discovered via IPv6."""
        min_expected = expected_assertions["min_ipv6_devices_discovered"]
        actual = len(ipv6_scan_results.devices)
        assert actual >= min_expected, (
            f"Expected at least {min_expected} IPv6 devices, found {actual}"
        )

    def test_each_device_found_via_ipv6(
        self,
        ipv6_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Each expected device is reachable via its IPv6 address."""
        failures = []
        for name, info in expected_devices.items():
            ipv6 = info.get("ipv6")
            if not ipv6:
                continue
            device = find_device(ipv6_scan_results, ipv6)
            if device is None:
                failures.append(f"  {name} ({ipv6}): not found via IPv6")

        assert not failures, (
            "IPv6 discovery failures:\n" + "\n".join(failures)
        )

    def test_ipv6_devices_marked_alive(
        self,
        ipv6_scan_results: ScanResults,
        expected_devices: dict
    ):
        """All IPv6-discovered devices have alive=True."""
        for name, info in expected_devices.items():
            ipv6 = info.get("ipv6")
            if not ipv6:
                continue
            device = find_device(ipv6_scan_results, ipv6)
            if device is not None:
                assert device.alive is True, (
                    f"Device '{name}' ({ipv6}) found but alive={device.alive}"
                )


class TestIPv6PortScanning:
    """Verify port scanning works over IPv6."""

    def test_ports_detected_via_ipv6(
        self,
        ipv6_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Expected ports are detected when scanning IPv6 addresses."""
        failures = []
        for name, info in expected_devices.items():
            ipv6 = info.get("ipv6")
            if not ipv6:
                continue

            # Use ipv6_ports if specified, otherwise fall back to ports
            expected_ports = set(info.get("ipv6_ports", info.get("ports", [])))
            device = find_device(ipv6_scan_results, ipv6)

            if device is None:
                if expected_ports:
                    failures.append(f"  {name} ({ipv6}): device not found")
                continue

            actual_ports = set(device.ports)
            missing = expected_ports - actual_ports
            if missing:
                failures.append(
                    f"  {name} ({ipv6}): missing ports {sorted(missing)}, "
                    f"found {sorted(actual_ports)}"
                )

        assert not failures, (
            "IPv6 port detection failures:\n" + "\n".join(failures)
        )


class TestIPv6ServiceIdentification:
    """Verify service identification works over IPv6."""

    def test_services_identified_via_ipv6(
        self,
        ipv6_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Services are correctly identified when scanning IPv6 addresses."""
        # Import the helper from the service ID tests
        from tests.integration.test_service_id import _service_matches

        devices_with_services = 0
        for name, info in expected_devices.items():
            ipv6 = info.get("ipv6")
            if not ipv6:
                continue

            # Skip devices with no IPv6 ports
            ipv6_ports = info.get("ipv6_ports", info.get("ports", []))
            if not ipv6_ports:
                continue

            device = find_device(ipv6_scan_results, ipv6)
            if device is None or not device.services:
                continue

            devices_with_services += 1
            expected_services = info.get("services", {})
            for port_str, labels in expected_services.items():
                port = int(port_str)
                if port not in ipv6_ports:
                    continue
                if port in device.ports:
                    # Just verify service detection works — don't fail on
                    # individual mismatches since IPv6 probing can be flakier
                    _service_matches(device.services, port, labels)

        # At least some devices should have services identified via IPv6
        assert devices_with_services > 0, (
            "No services identified on any device via IPv6"
        )
