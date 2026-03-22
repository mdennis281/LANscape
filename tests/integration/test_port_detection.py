"""
Integration tests: Port detection.

Validates that LANscape correctly detects open ports on service containers.
"""

import pytest

from lanscape.core.models import ScanResults
from tests.integration.conftest import find_device


pytestmark = pytest.mark.integration


class TestPortDetection:
    """Verify expected ports are detected on each service container."""

    def test_expected_ports_detected(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Each device has all its expected ports detected."""
        failures = []
        for name, info in expected_devices.items():
            ip = info["ipv4"]
            expected_ports = set(info.get("ports", []))
            device = find_device(ipv4_scan_results, ip)

            if device is None:
                failures.append(f"  {name} ({ip}): device not found")
                continue

            actual_ports = set(device.ports)
            missing = expected_ports - actual_ports
            if missing:
                failures.append(
                    f"  {name} ({ip}): missing ports {sorted(missing)}, "
                    f"found {sorted(actual_ports)}"
                )

        assert not failures, (
            "Port detection failures:\n" + "\n".join(failures)
        )

    def test_web_server_ports(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Web server has HTTP, HTTPS, and alt HTTP ports open."""
        info = expected_devices["web-server"]
        device = find_device(ipv4_scan_results, info["ipv4"])
        assert device is not None, "web-server not found"
        for port in [80, 443, 8080]:
            assert port in device.ports, (
                f"Port {port} not detected on web-server"
            )

    def test_multi_service_ports(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Multi-service host has all expected ports from different services."""
        info = expected_devices["multi-service"]
        device = find_device(ipv4_scan_results, info["ipv4"])
        assert device is not None, "multi-service not found"
        expected = set(info["ports"])
        actual = set(device.ports)
        missing = expected - actual
        assert not missing, (
            f"multi-service missing ports: {sorted(missing)}, found: {sorted(actual)}"
        )

    def test_no_false_positive_ports(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """
        Devices don't report common ports that should be closed.
        Check a few known-closed ports on specific services.
        """
        # SSH server should NOT have HTTP ports open
        ssh_info = expected_devices["ssh-server"]
        ssh_device = find_device(ipv4_scan_results, ssh_info["ipv4"])
        if ssh_device is not None:
            for port in [80, 443, 3306]:
                assert port not in ssh_device.ports, (
                    f"SSH server unexpectedly has port {port} open"
                )

        # Redis should NOT have SSH or HTTP
        redis_info = expected_devices["redis"]
        redis_device = find_device(ipv4_scan_results, redis_info["ipv4"])
        if redis_device is not None:
            for port in [22, 80, 443]:
                assert port not in redis_device.ports, (
                    f"Redis server unexpectedly has port {port} open"
                )
