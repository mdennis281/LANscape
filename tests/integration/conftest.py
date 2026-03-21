"""
Shared fixtures for LANscape integration tests.

Provides session-scoped scan results and expected device data
loaded from expected_results.yml.
"""

import logging
from pathlib import Path
from typing import Optional

import pytest
import yaml

from lanscape import SubnetScanner, ScanConfig, ScanType, PortManager
from lanscape.core.scan_config import ServiceScanStrategy
from lanscape.core.models import ScanResults, DeviceResult

logger = logging.getLogger(__name__)

INTEGRATION_DIR = Path(__file__).parent
EXPECTED_RESULTS_PATH = INTEGRATION_DIR / "expected_results.yml"
RESULTS_DIR = INTEGRATION_DIR / "results"

INTEGRATION_PORT_LIST = "integration"


def _load_expected() -> dict:
    """Load expected results from YAML."""
    with open(EXPECTED_RESULTS_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _build_integration_port_list() -> None:
    """Create a port list that includes non-standard ports used by test containers."""
    pm = PortManager()
    ports = pm.get_port_list("medium")
    # Add ports not in the medium list but used by integration containers
    extra_ports = {
        "2222": "SSH (non-standard)",
        "3025": "SMTP (GreenMail)",
        "3128": "HTTP Proxy (Squid)",
        "3143": "IMAP (GreenMail)",
    }
    ports.update(extra_ports)

    if INTEGRATION_PORT_LIST in pm.get_port_lists():
        pm.update_port_list(INTEGRATION_PORT_LIST, ports)
    else:
        pm.create_port_list(INTEGRATION_PORT_LIST, ports)


def _cleanup_integration_port_list() -> None:
    """Remove the temporary integration port list."""
    pm = PortManager()
    if INTEGRATION_PORT_LIST in pm.get_port_lists():
        pm.delete_port_list(INTEGRATION_PORT_LIST)


def _run_scan(subnet: str) -> ScanResults:
    """Run a SubnetScanner against the given subnet and return results."""
    config = ScanConfig(
        subnet=subnet,
        port_list=INTEGRATION_PORT_LIST,
        lookup_type=[ScanType.ICMP_THEN_ARP],
        task_scan_ports=True,
        task_scan_port_services=True,
    )
    config.service_scan_config.lookup_type = ServiceScanStrategy.AGGRESSIVE

    # Faster timeouts for isolated Docker network
    config.ping_config.timeout = 0.5
    config.ping_config.ping_count = 2
    config.port_scan_config.timeout = 2.0
    config.port_scan_config.retries = 1

    logger.info("Starting scan on subnet: %s", subnet)
    scanner = SubnetScanner(config)
    scanner.start()
    results = scanner.results.to_results()
    logger.info(
        "Scan complete: %d devices found",
        len(results.devices)
    )
    return results


def find_device(results: ScanResults, ip: str) -> Optional[DeviceResult]:
    """Find a device in scan results by IP address."""
    for device in results.devices:
        if device.ip == ip:
            return device
    return None


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def integration_port_list():
    """Create a custom port list including non-standard ports for test containers."""
    _build_integration_port_list()
    yield
    _cleanup_integration_port_list()


@pytest.fixture(scope="session")
def expected_data() -> dict:
    """Load expected results from YAML."""
    return _load_expected()


@pytest.fixture(scope="session")
def expected_devices(expected_data: dict) -> dict:
    """Return the devices section of expected results."""
    return expected_data["devices"]


@pytest.fixture(scope="session")
def expected_assertions(expected_data: dict) -> dict:
    """Return assertion thresholds."""
    return expected_data["assertions"]


@pytest.fixture(scope="session")
def ipv4_scan_results(expected_data: dict) -> ScanResults:
    """Run a full IPv4 scan against the test network. Session-scoped (runs once)."""
    subnet = expected_data["network"]["ipv4_subnet"]
    return _run_scan(subnet)


@pytest.fixture(scope="session")
def ipv6_scan_results(expected_data: dict) -> ScanResults:
    """
    Run an IPv6 scan against the test network. Session-scoped (runs once).

    Uses explicit IPv6 addresses from expected results since scanning
    a full /64 is impractical.
    """
    devices = expected_data["devices"]
    ipv6_addrs = [
        d["ipv6"] for d in devices.values()
        if "ipv6" in d
    ]
    # Pass as comma-separated list of individual IPs
    subnet = ", ".join(f"{addr}/128" for addr in ipv6_addrs)
    return _run_scan(subnet)


@pytest.fixture(scope="session")
def results_dir() -> Path:
    """Ensure results directory exists."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR
