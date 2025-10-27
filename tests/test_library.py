"""
Integration tests for core library components of the LANscape application.
Tests scan configuration, network discovery, and subnet selection functionality.
"""

import pytest

from lanscape.core.net_tools import smart_select_primary_subnet
from lanscape.core.subnet_scan import ScanManager
from lanscape.core.scan_config import ScanConfig, ScanType

from tests._helpers import right_size_subnet


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


@pytest.mark.integration
@pytest.mark.slow
def test_scan(scan_manager):
    """
    Test the network scanning functionality with a dynamically selected subnet.
    Verifies that devices can be discovered and that scan results are valid.
    """
    subnet = smart_select_primary_subnet()
    assert subnet is not None

    cfg = ScanConfig(
        subnet=right_size_subnet(subnet),
        t_multiplier=1.0,
        port_list='small',
        lookup_type=[ScanType.POKE_THEN_ARP]
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

    # find at least one device
    assert len(scan.results.devices) > 0

    # ensure everything got scanned
    assert scan.results.devices_scanned == scan.results.devices_total
