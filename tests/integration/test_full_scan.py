"""
Integration tests: Full end-to-end scan with report generation.

Runs a complete scan and generates a human-readable report file
for manual review alongside automated assertions.
"""

from pathlib import Path

import pytest
from tabulate import tabulate

from lanscape.core.models import ScanResults
from tests.integration.conftest import find_device


pytestmark = pytest.mark.integration


def _build_report(
    ipv4_results: ScanResults,
    ipv6_results: ScanResults,
    expected_devices: dict,
) -> str:
    """Generate a human-readable scan comparison report."""
    lines = [
        "=" * 80,
        "LANscape Integration Test Report",
        "=" * 80,
        "",
    ]

    # ── IPv4 Summary ──
    lines.append("── IPv4 Scan Summary ──")
    lines.append(f"  Devices found: {len(ipv4_results.devices)}")
    lines.append(f"  Expected:      {len(expected_devices)}")
    lines.append("")

    # Device detail table
    rows = []
    for name, info in expected_devices.items():
        ip = info["ipv4"]
        device = find_device(ipv4_results, ip)

        expected_ports = sorted(info.get("ports", []))
        if device:
            actual_ports = sorted(device.ports)
            services = ", ".join(
                f"{svc}:{ps}" for svc, ps in device.services.items()
            ) or "none"
            status = "FOUND"
            port_match = "OK" if set(expected_ports) <= set(actual_ports) else "MISSING"
            macs = ", ".join(device.macs) if device.macs else "none"
        else:
            actual_ports = []
            services = "N/A"
            status = "MISSING"
            port_match = "N/A"
            macs = "N/A"

        rows.append([
            name, ip, status,
            str(expected_ports), str(actual_ports),
            port_match, services, macs
        ])

    headers = ["Name", "IPv4", "Status", "Expected Ports", "Actual Ports",
               "Ports OK", "Services", "MACs"]
    lines.append(tabulate(rows, headers=headers, tablefmt="grid"))
    lines.append("")

    # ── IPv6 Summary ──
    lines.append("── IPv6 Scan Summary ──")
    lines.append(f"  Devices found: {len(ipv6_results.devices)}")
    lines.append("")

    ipv6_rows = []
    for name, info in expected_devices.items():
        ipv6 = info.get("ipv6")
        if not ipv6:
            continue
        device = find_device(ipv6_results, ipv6)
        expected_ports = sorted(info.get("ports", []))
        if device:
            actual_ports = sorted(device.ports)
            status = "FOUND"
        else:
            actual_ports = []
            status = "MISSING"

        ipv6_rows.append([name, ipv6, status, str(expected_ports), str(actual_ports)])

    ipv6_headers = ["Name", "IPv6", "Status", "Expected Ports", "Actual Ports"]
    lines.append(tabulate(ipv6_rows, headers=ipv6_headers, tablefmt="grid"))
    lines.append("")

    # ── Unexpected Devices ──
    expected_ips = {info["ipv4"] for info in expected_devices.values()}
    unexpected = [d for d in ipv4_results.devices if d.ip not in expected_ips]
    if unexpected:
        lines.append("── Unexpected Devices ──")
        unexp_rows = [[d.ip, d.hostname or "?", sorted(d.ports)] for d in unexpected]
        lines.append(tabulate(
            unexp_rows, headers=["IP", "Hostname", "Ports"], tablefmt="grid"
        ))
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


class TestFullScan:
    """End-to-end validation of the complete scan pipeline."""

    def test_generate_report(
        self,
        ipv4_scan_results: ScanResults,
        ipv6_scan_results: ScanResults,
        expected_devices: dict,
        results_dir: Path,
    ):
        """Generate a human-readable report and write to results directory."""
        report = _build_report(
            ipv4_scan_results, ipv6_scan_results, expected_devices
        )
        report_path = results_dir / "report.txt"
        report_path.write_text(report, encoding="utf-8")

        # Print to stdout for CI logs
        print("\n" + report)

        # Basic sanity — report was generated
        assert len(report) > 100, "Report seems too short"

    def test_total_port_count(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict,
    ):
        """Total detected ports across all devices meets minimum threshold."""
        total_expected = sum(
            len(info.get("ports", []))
            for info in expected_devices.values()
        )
        total_actual = sum(
            len(d.ports) for d in ipv4_scan_results.devices
        )
        assert total_actual >= total_expected, (
            f"Total open ports ({total_actual}) below expected ({total_expected})"
        )

    def test_service_coverage(
        self,
        ipv4_scan_results: ScanResults,
        expected_devices: dict,
    ):
        """At least some percentage of expected services are identified."""
        total_expected = 0
        total_matched = 0

        for info in expected_devices.values():
            device = find_device(ipv4_scan_results, info["ipv4"])
            if device is None:
                total_expected += len(info.get("services", {}))
                continue

            for port_str in info.get("services", {}):
                total_expected += 1
                port = int(port_str)
                if port in device.ports and device.services:
                    # Check if any service was detected on this port
                    for _svc_name, svc_ports in device.services.items():
                        if port in svc_ports:
                            total_matched += 1
                            break

        if total_expected > 0:
            coverage = total_matched / total_expected
            assert coverage >= 0.5, (
                f"Service coverage too low: {coverage:.0%} "
                f"({total_matched}/{total_expected})"
            )
