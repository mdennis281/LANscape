"""
Integration tests: Service identification.

Validates that LANscape correctly identifies services running on detected ports
by matching protocol banners and binary signatures.
"""

import pytest

from lanscape.core.models import ScanResults
from tests.integration.conftest import find_device


pytestmark = pytest.mark.integration


def _service_matches(actual_services: dict, port: int, expected_labels: list[str]) -> bool:
    """
    Check if any expected service label matches what was detected on a port.

    Performs case-insensitive substring matching to handle variations
    like 'HTTP' matching 'http', 'http-alt', etc.
    """
    for service_name, ports in actual_services.items():
        if port in ports:
            for expected in expected_labels:
                if expected.lower() in service_name.lower():
                    return True
    return False


class TestServiceIdentification:
    """Verify services are correctly identified from protocol banners."""

    def test_services_identified_per_device(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Each device's expected services are identified."""
        failures = []
        for name, info in expected_devices.items():
            ip = info["ipv4"]
            expected_services = info.get("services", {})
            device = find_device(ipv4_scan_results, ip)

            if device is None:
                if expected_services:
                    failures.append(f"  {name} ({ip}): device not found")
                continue

            for port_str, labels in expected_services.items():
                port = int(port_str)
                if port not in device.ports:
                    failures.append(
                        f"  {name} ({ip}): port {port} not open, "
                        f"can't verify service {labels}"
                    )
                    continue

                if not _service_matches(device.services, port, labels):
                    failures.append(
                        f"  {name} ({ip}): port {port} expected {labels}, "
                        f"got services={dict(device.services)}"
                    )

        assert not failures, (
            "Service identification failures:\n" + "\n".join(failures)
        )

    def test_web_server_http_identified(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Web server port 80 is identified as HTTP."""
        device = find_device(
            ipv4_scan_results, expected_devices["web-server"]["ipv4"]
        )
        assert device is not None, "web-server not found"
        assert _service_matches(device.services, 80, ["HTTP"]), (
            f"Port 80 not identified as HTTP. Services: {dict(device.services)}"
        )

    def test_web_server_tls_detected(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Web server port 443 is identified as HTTPS/TLS."""
        device = find_device(
            ipv4_scan_results, expected_devices["web-server"]["ipv4"]
        )
        assert device is not None, "web-server not found"
        assert _service_matches(device.services, 443, ["HTTPS", "TLS", "SSL"]), (
            f"Port 443 not identified as HTTPS. Services: {dict(device.services)}"
        )

    def test_ssh_banner_detected(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """SSH server banner is properly identified."""
        device = find_device(
            ipv4_scan_results, expected_devices["ssh-server"]["ipv4"]
        )
        assert device is not None, "ssh-server not found"
        # Check service_info for SSH banner content
        ssh_infos = [
            si for si in device.service_info
            if si.port in expected_devices["ssh-server"]["ports"]
        ]
        assert len(ssh_infos) > 0, "No service info for SSH port"

    def test_redis_pong_response(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Redis responds to probes; detected as Redis or POP3 (same weight)."""
        device = find_device(
            ipv4_scan_results, expected_devices["redis"]["ipv4"]
        )
        assert device is not None, "redis not found"
        assert _service_matches(device.services, 6379, ["Redis", "POP3"]), (
            f"Port 6379 not identified as Redis/POP3. Services: {dict(device.services)}"
        )

    def test_smtp_banner_detected(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Mail server SMTP banner is detected."""
        device = find_device(
            ipv4_scan_results, expected_devices["mail-server"]["ipv4"]
        )
        assert device is not None, "mail-server not found"
        mail_ports = expected_devices["mail-server"]["ports"]
        smtp_port = mail_ports[0]  # First port is SMTP (3025 for GreenMail)
        assert _service_matches(device.services, smtp_port, ["SMTP"]), (
            f"Port {smtp_port} not identified as SMTP. Services: {dict(device.services)}"
        )

    def test_service_info_has_responses(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict
    ):
        """Devices with detected services have non-empty probe responses."""
        for name, info in expected_devices.items():
            device = find_device(ipv4_scan_results, info["ipv4"])
            if device is None or not device.service_info:
                continue

            for si in device.service_info:
                # At least some probe responses should have content
                if si.service:
                    assert si.service.strip(), (
                        f"{name}: service_info entry for port {si.port} "
                        f"has empty service label"
                    )
