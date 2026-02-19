"""
Integration tests for core library components of the LANscape application.
Tests scan configuration, network discovery, and subnet selection functionality.
"""

import pytest

from lanscape.core.net_tools import smart_select_primary_subnet, _is_deprioritized_subnet
from lanscape.core.subnet_scan import ScanManager
from lanscape.core.scan_config import ScanConfig, ScanType

from tests.test_globals import (
    TEST_SUBNET,
    MIN_EXPECTED_RUNTIME,
    MIN_EXPECTED_ALIVE_DEVICES
)


@pytest.fixture
def scan_manager():
    """Provide a ScanManager instance for tests."""
    return ScanManager()


# Core Library Integration Tests
###############################

def test_scan_config():
    """
    Test the ScanConfig class serialization and deserialization functionality.
    Verifies that configs can be properly converted to and from dictionaries.
    """
    subnet_val = '192.168.1.1/24'
    do_port_scan = False
    ping_attempts = 3
    arp_timeout = 2.0

    cfg = ScanConfig(
        subnet=subnet_val,
        port_list='small',
    )
    assert len(cfg.parse_subnet()) == 254

    cfg.task_scan_ports = do_port_scan
    cfg.ping_config.attempts = ping_attempts
    cfg.arp_config.timeout = arp_timeout
    cfg.lookup_type = [ScanType.POKE_THEN_ARP]

    data = cfg.to_dict()
    assert isinstance(data['ping_config'], dict)
    assert isinstance(data['arp_config'], dict)

    cfg2 = ScanConfig.from_dict(data)

    # ensure the config was properly converted back
    assert cfg2.subnet == subnet_val
    assert cfg2.port_list == 'small'
    assert cfg2.task_scan_ports == do_port_scan
    assert cfg2.ping_config.attempts == ping_attempts
    assert cfg2.arp_config.timeout == arp_timeout
    assert cfg2.lookup_type == [ScanType.POKE_THEN_ARP]


def test_smart_select_primary_subnet():
    """
    Test the smart_select_primary_subnet functionality without running actual scans.
    Verifies that the subnet detection works on the current system.
    """
    subnet = smart_select_primary_subnet()
    assert subnet is not None
    assert '/' in subnet  # Should be in CIDR format
    # Verify it's a valid subnet format
    parts = subnet.split('/')
    assert len(parts) == 2
    assert int(parts[1]) <= 32  # Valid CIDR mask


def test_smart_select_deprioritizes_virtual_networks():
    """
    Test that smart_select_primary_subnet deprioritizes virtual/system networks.
    WSL, Docker, and loopback networks should be avoided when better options exist.
    """
    # Test with a mix of real and virtual subnets
    mock_subnets = [
        {"subnet": "172.27.64.0/20", "address_cnt": 4094},   # WSL - should be deprioritized
        {"subnet": "192.168.1.0/24", "address_cnt": 254},    # Real LAN - should be selected
        {"subnet": "172.17.0.0/16", "address_cnt": 65534},   # Docker - deprioritized & too large
    ]
    result = smart_select_primary_subnet(mock_subnets)
    assert result == "192.168.1.0/24"

    # Test that deprioritized subnet is still selected if it's the only option
    wsl_only = [{"subnet": "172.27.64.0/20", "address_cnt": 4094}]
    result = smart_select_primary_subnet(wsl_only)
    assert result == "172.27.64.0/20"

    # Test loopback deprioritization
    loopback_mix = [
        {"subnet": "127.0.0.0/8", "address_cnt": 16777214},
        {"subnet": "10.0.0.0/24", "address_cnt": 254},
    ]
    result = smart_select_primary_subnet(loopback_mix)
    assert result == "10.0.0.0/24"


def test_is_deprioritized_subnet():
    """Test the _is_deprioritized_subnet helper function."""
    # WSL default
    assert _is_deprioritized_subnet("172.27.64.0/20") is True
    assert _is_deprioritized_subnet("172.27.70.0/24") is True  # Subset of WSL range

    # Docker default
    assert _is_deprioritized_subnet("172.17.0.0/16") is True
    assert _is_deprioritized_subnet("172.17.0.0/24") is True  # Subset of Docker range

    # Loopback
    assert _is_deprioritized_subnet("127.0.0.0/8") is True
    assert _is_deprioritized_subnet("127.0.0.1/32") is True

    # Normal subnets should NOT be deprioritized
    assert _is_deprioritized_subnet("192.168.1.0/24") is False
    assert _is_deprioritized_subnet("10.0.0.0/24") is False
    assert _is_deprioritized_subnet("172.16.0.0/24") is False  # Not in Docker/WSL range


@pytest.mark.integration
@pytest.mark.slow
def test_scan(scan_manager):
    """
    Test the network scanning functionality with a fixed external subnet.
    Verifies that the scan engine works correctly with external public IPs.
    """
    cfg = ScanConfig(
        subnet=TEST_SUBNET,
        port_list='small',
        lookup_type=[ScanType.ICMP, ScanType.POKE_THEN_ARP],
        t_cnt_isalive=2,   # Limit threads to extend runtime
        ping_config={'timeout': 0.8, 'attempts': 2}  # Reasonable timeout for external IPs
    )
    scan = scan_manager.new_scan(cfg)
    assert scan.running
    scan_manager.wait_until_complete(scan.uid)

    assert not scan.running

    # ensure there are not any remaining running threads
    assert scan.job_stats.running == {}

    cnt_with_hostname = 0
    ips = []
    macs = []
    for d in scan.results.devices:
        if d.hostname:
            cnt_with_hostname += 1
        # ensure there arent dupe mac addresses

        if d.get_mac() in macs:
            print(f"Warning: Duplicate MAC address found: {d.get_mac()}")
        macs.append(d.get_mac())

        # ensure there arent dupe ips
        assert d.ip not in ips
        ips.append(d.ip)

        # device must be alive to be in this list
        assert d.alive

    # For external IPs, we may not find responsive devices but scan should complete
    # The main goal is to test that the scan engine works correctly
    assert scan.results.devices_scanned == scan.results.devices_total

    # Verify scan took measurable time (should be > 0 for real network operations)
    assert scan.results.get_runtime() >= MIN_EXPECTED_RUNTIME

    # For external ranges, alive device count should be within expected bounds
    alive_count = len([d for d in scan.results.devices if d.alive])
    assert MIN_EXPECTED_ALIVE_DEVICES <= alive_count
