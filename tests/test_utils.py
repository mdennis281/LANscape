"""
Unit tests for various utility modules in the LANscape project.
Tests include IP parsing, port management, and decorator functionality.
"""

import ipaddress
import logging
import time

import pytest

from lanscape.core.ip_parser import parse_ip_input
from lanscape.core.errors import SubnetTooLargeError
from lanscape.core import ip_parser
from lanscape.core.decorators import timeout_enforcer
from lanscape.core.net_tools import is_internal_block, scan_config_uses_arp
from lanscape.core.scan_config import ScanConfig, ScanType
from lanscape.core.subnet_scan import ScanManager


# IP Parser Tests
##################

@pytest.mark.parametrize("test_case", [
    'cidr', 'range', 'shorthand', 'mixed'
])
def test_parse_ip_input_cases(ip_test_cases, test_case):
    """Test various IP input parsing formats using parametrized test cases."""
    case_data = ip_test_cases[test_case]
    result = parse_ip_input(case_data['input'])
    expected_ips = [str(ip) for ip in result]
    assert expected_ips == case_data['expected']


def test_parse_cidr_specific():
    """Test CIDR notation parsing with a /30 network."""
    ips = parse_ip_input('192.168.0.0/30')
    expected = ['192.168.0.1', '192.168.0.2']
    assert [str(ip) for ip in ips] == expected


def test_parse_range_length_and_bounds():
    """Test explicit IP range parsing validates length and boundaries."""
    ips = parse_ip_input('10.0.0.1-10.0.0.3')

    assert len(ips) == 3
    assert str(ips[0]) == '10.0.0.1'
    assert str(ips[-1]) == '10.0.0.3'


def test_parse_too_large_subnet():
    """Test that large subnets raise an appropriate exception."""
    with pytest.raises(SubnetTooLargeError):
        parse_ip_input('10.0.0.0/8')


def test_parse_mixed_format_comprehensive():
    """Test parsing a comprehensive mix of CIDR, range, and individual IP formats."""
    ip_input = "10.0.0.1/30, 10.0.0.10-10.0.0.12, 10.0.0.20-22, 10.0.0.50"
    result = ip_parser.parse_ip_input(ip_input)

    expected = [
        ipaddress.IPv4Address("10.0.0.1"),
        ipaddress.IPv4Address("10.0.0.2"),
        ipaddress.IPv4Address("10.0.0.10"),
        ipaddress.IPv4Address("10.0.0.11"),
        ipaddress.IPv4Address("10.0.0.12"),
        ipaddress.IPv4Address("10.0.0.20"),
        ipaddress.IPv4Address("10.0.0.21"),
        ipaddress.IPv4Address("10.0.0.22"),
        ipaddress.IPv4Address("10.0.0.50"),
    ]

    assert result == expected


# Port Manager Tests
####################

def test_port_manager_validate_valid_data(port_manager, valid_port_data):
    """Test that valid port data passes validation."""
    assert port_manager.validate_port_data(valid_port_data) is True


def test_port_manager_validate_simple_case(port_manager):
    """Test basic valid port data case."""
    valid = {"80": "http", "443": "https"}
    assert port_manager.validate_port_data(valid) is True


@pytest.mark.parametrize("invalid_data", [
    {"-1": "negative"},      # Negative port
    {"70000": "too_high"},   # Port out of range
    {"abc": "not_int"},      # Non-integer port
    {"80": 123},             # Service not a string
    {"": "empty_port"},      # Empty port
])
def test_port_manager_validate_invalid_data(port_manager, invalid_data):
    """Test that various invalid port data formats fail validation."""
    assert port_manager.validate_port_data(invalid_data) is False


def test_port_manager_allows_empty_service_name(port_manager):
    """Test that empty service names are actually allowed."""
    valid_empty_service = {"80": ""}
    assert port_manager.validate_port_data(valid_empty_service) is True


# Decorator Tests
#################

def test_timeout_enforcer_no_raise():
    """Test timeout_enforcer with raise_on_timeout=False returns None on timeout."""

    @timeout_enforcer(0.1, raise_on_timeout=False)
    def slow_function():
        time.sleep(0.5)
        return "should_not_return"

    result = slow_function()
    assert result is None


def test_timeout_enforcer_with_raise():
    """Test timeout_enforcer with raise_on_timeout=True raises TimeoutError."""

    @timeout_enforcer(0.1, raise_on_timeout=True)
    def slow_function():
        time.sleep(0.5)
        return "should_not_return"

    with pytest.raises(TimeoutError):
        slow_function()


def test_timeout_enforcer_fast_function():
    """Test timeout_enforcer allows fast functions to complete normally."""

    @timeout_enforcer(1.0, raise_on_timeout=True)
    def fast_function():
        return "completed"

    result = fast_function()
    assert result == "completed"


@pytest.mark.parametrize("timeout,raise_flag,expected_exception", [
    (0.1, True, TimeoutError),
    (0.05, True, TimeoutError),
])
def test_timeout_enforcer_parametrized(timeout, raise_flag, expected_exception):
    """Test timeout_enforcer with different timeout values and raise settings."""

    @timeout_enforcer(timeout, raise_on_timeout=raise_flag)
    def slow_function():
        time.sleep(0.2)
        return "done"

    if raise_flag:
        with pytest.raises(expected_exception):
            slow_function()
    else:
        result = slow_function()
        assert result is None


# Network Utility Tests
########################

def test_is_internal_block_cidr_private():
    """Test is_internal_block with private CIDR subnets."""
    # RFC 1918 private networks
    assert is_internal_block('192.168.1.0/24') is True
    assert is_internal_block('10.0.0.0/24') is True
    assert is_internal_block('172.16.0.0/24') is True

    # Loopback
    assert is_internal_block('127.0.0.1/32') is True


def test_is_internal_block_cidr_public():
    """Test is_internal_block with public CIDR subnets."""
    # Known public networks
    assert is_internal_block('1.1.1.1/28') is False      # Cloudflare DNS
    assert is_internal_block('8.8.8.8/30') is False      # Google DNS
    assert is_internal_block('208.67.222.0/24') is False  # OpenDNS


def test_is_internal_block_single_ip():
    """Test is_internal_block with single IP addresses."""
    # Private IPs
    assert is_internal_block('192.168.1.1') is True
    assert is_internal_block('10.0.0.1') is True
    assert is_internal_block('172.16.0.1') is True
    assert is_internal_block('127.0.0.1') is True

    # Public IPs
    assert is_internal_block('8.8.8.8') is False
    assert is_internal_block('1.1.1.1') is False


def test_is_internal_block_ip_ranges():
    """Test is_internal_block with IP ranges."""
    # Private ranges
    assert is_internal_block('192.168.1.1-192.168.1.10') is True
    assert is_internal_block('10.0.0.1-10.0.0.5') is True
    assert is_internal_block('192.168.1.1-5') is True  # Short form

    # Public ranges
    assert is_internal_block('8.8.8.1-8.8.8.5') is False
    assert is_internal_block('1.1.1.1-1.1.1.5') is False


def test_is_internal_block_comma_separated():
    """Test is_internal_block with comma-separated subnets."""
    # All private
    assert is_internal_block('192.168.1.1, 10.0.0.1') is True
    assert is_internal_block('192.168.1.0/24, 172.16.0.0/24') is True

    # Mixed private and public (should return False)
    assert is_internal_block('192.168.1.1, 8.8.8.8') is False
    assert is_internal_block('192.168.1.0/24, 1.1.1.1/28') is False

    # All public
    assert is_internal_block('8.8.8.8, 1.1.1.1') is False


def test_is_internal_block_large_private_networks():
    """Test is_internal_block with large private networks (should not hit parsing limits)."""
    # Large private networks should work without triggering SubnetTooLargeError
    assert is_internal_block('10.0.0.0/8') is True      # 16M addresses
    assert is_internal_block('172.16.0.0/12') is True   # 1M addresses
    assert is_internal_block('192.168.0.0/16') is True  # 64K addresses


def test_is_internal_block_edge_cases():
    """Test is_internal_block with edge cases and invalid inputs."""
    # Invalid/malformed inputs should return False (safe default)
    assert is_internal_block('invalid.subnet') is False
    assert is_internal_block('999.999.999.999') is False
    assert is_internal_block('') is False
    assert is_internal_block('192.168.1.0/99') is False  # Invalid CIDR mask


@pytest.mark.parametrize("subnet,expected,description", [
    ('192.168.1.0/24', True, 'Private RFC1918'),
    ('10.0.0.0/8', True, 'Private RFC1918 large'),
    ('172.16.0.0/12', True, 'Private RFC1918 medium'),
    ('1.1.1.1/28', False, 'Public Cloudflare DNS'),
    ('8.8.8.8/30', False, 'Public Google DNS'),
    ('127.0.0.1/32', True, 'Loopback'),
    ('192.168.1.1-192.168.1.10', True, 'Private range'),
    ('1.1.1.1-1.1.1.5', False, 'Public range'),
    ('192.168.1.1,10.0.0.1', True, 'Multiple private'),
    ('192.168.1.1,8.8.8.8', False, 'Mixed private/public'),
    ('192.168.1.1', True, 'Single private IP'),
    ('8.8.8.8', False, 'Single public IP'),
    ('invalid', False, 'Invalid input'),
])
def test_is_internal_block_parametrized(subnet, expected, description):
    """Test is_internal_block with comprehensive parametrized test cases."""
    result = is_internal_block(subnet)
    assert result is expected, (
        f"Failed for {description}: {subnet} -> expected {expected}, got {result}"
    )


def test_scan_config_uses_arp():
    """Test scan_config_uses_arp function with different scan configurations."""

    # Test configurations that don't use ARP
    config_icmp = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.ICMP
        ])
    assert scan_config_uses_arp(config_icmp) is False

    # Test configurations that use ARP
    config_arp = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.ARP_LOOKUP])
    assert scan_config_uses_arp(config_arp) is True

    config_poke_arp = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.POKE_THEN_ARP])
    assert scan_config_uses_arp(config_poke_arp) is True

    config_icmp_arp = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.ICMP_THEN_ARP])
    assert scan_config_uses_arp(config_icmp_arp) is True

    # Test mixed configurations
    config_mixed = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.ICMP,
            ScanType.ARP_LOOKUP])
    assert scan_config_uses_arp(config_mixed) is True

    config_mixed_no_arp = ScanConfig(
        subnet='192.168.1.0/24',
        port_list='small',
        lookup_type=[
            ScanType.ICMP])
    assert scan_config_uses_arp(config_mixed_no_arp) is False


def test_scan_manager_arp_warning_integration(caplog):
    """Test that ScanManager warns when ARP scanning is used on external subnets."""

    # Enable logging capture for the ScanManager
    caplog.set_level(logging.WARNING, logger='ScanManager')

    sm = ScanManager()

    # Test 1: ARP scanning on external subnet should generate warning
    external_arp_config = ScanConfig(
        subnet='8.8.8.8/30',  # External subnet
        port_list='small',
        lookup_type=[ScanType.ARP_LOOKUP]  # ARP-based scanning
    )

    scan = sm.new_scan(external_arp_config)
    scan.terminate()  # Stop the scan immediately

    # Check that warning was logged
    assert any(
        'ARP scanning detected for external subnet' in record.message
        for record in caplog.records
    )

    # Clear the log for next test
    caplog.clear()

    # Test 2: ICMP scanning on external subnet should NOT generate warning
    external_icmp_config = ScanConfig(
        subnet='8.8.8.8/30',  # External subnet
        port_list='small',
        lookup_type=[ScanType.ICMP]  # ICMP-based scanning
    )

    scan2 = sm.new_scan(external_icmp_config)
    scan2.terminate()  # Stop the scan immediately

    # Check that no warning was logged
    assert not any('ARP scanning detected' in record.message for record in caplog.records)

    # Clear the log for next test
    caplog.clear()

    # Test 3: ARP scanning on internal subnet should NOT generate warning
    internal_arp_config = ScanConfig(
        subnet='192.168.1.0/24',  # Internal subnet
        port_list='small',
        lookup_type=[ScanType.ARP_LOOKUP]  # ARP-based scanning
    )

    scan3 = sm.new_scan(internal_arp_config)
    scan3.terminate()  # Stop the scan immediately

    # Check that no warning was logged
    assert not any('ARP scanning detected' in record.message for record in caplog.records)
