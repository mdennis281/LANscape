"""
Unit tests for various utility modules in the LANscape project.
Tests include IP parsing, port management, and decorator functionality.
"""

import ipaddress
import time

import pytest

from lanscape.core.ip_parser import parse_ip_input
from lanscape.core.errors import SubnetTooLargeError
from lanscape.core import ip_parser
from lanscape.core.decorators import timeout_enforcer


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
