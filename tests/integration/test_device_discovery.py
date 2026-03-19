"""
Integration tests: Device discovery.

Validates that LANscape discovers all expected devices on the test network
via ICMP/ARP cache methods, and that device metadata is populated.
"""

import pytest

from lanscape.core.models import ScanResults
from tests.integration.conftest import find_device


pytestmark = pytest.mark.integration


class TestIPv4Discovery:
    """Verify all service containers are discovered via IPv4 scanning."""

    def test_minimum_devices_found(
        self,
        ipv4_scan_results: ScanResults,
        expected_assertions: dict
    ):
        """Scan discovers at least the minimum expected number of devices."""
        min_expected = expected_assertions["min_devices_discovered"]
        actual = len(ipv4_scan_results.devices)
        assert actual >= min_expected, (
            f"Expected at least {min_expected} devices, found {actual}"
        )

    def test_each_device_discovered(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Each expected device is found in scan results."""
        for name, info in expected_devices.items():
            ip = info["ipv4"]
            device = find_device(ipv4_scan_results, ip)
            assert device is not None, (
                f"Device '{name}' ({ip}) not found in scan results"
            )

    def test_devices_marked_alive(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """All discovered devices have alive=True."""
        for name, info in expected_devices.items():
            ip = info["ipv4"]
            device = find_device(ipv4_scan_results, ip)
            if device is not None:
                assert device.alive is True, (
                    f"Device '{name}' ({ip}) found but alive={device.alive}"
                )

    def test_no_excessive_devices(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """
        Scan doesn't discover an unreasonable number of extra devices.
        Allow some headroom for the gateway and scanner itself.
        """
        expected_count = len(expected_devices)
        # Allow up to 3 extra (gateway, scanner, Docker DNS)
        max_allowed = expected_count + 3
        actual = len(ipv4_scan_results.devices)
        assert actual <= max_allowed, (
            f"Found {actual} devices, expected at most {max_allowed}. "
            f"Extra devices may indicate network leakage."
        )

    def test_mac_addresses_populated(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Discovered devices have MAC addresses from ARP cache."""
        devices_with_macs = 0
        for name, info in expected_devices.items():
            ip = info["ipv4"]
            device = find_device(ipv4_scan_results, ip)
            if device is not None and device.macs:
                devices_with_macs += 1

        # At least some devices should have MACs populated
        assert devices_with_macs > 0, (
            "No devices had MAC addresses populated from ARP cache"
        )
