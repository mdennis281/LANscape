"""
Shared pytest fixtures and configuration for LANscape test suite.
Provides common test utilities, mock objects, and test data.
"""

import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from lanscape.core.port_manager import PortManager
from lanscape.core.scan_config import ScanConfig
from .test_globals import TEST_SUBNET


@pytest.fixture
def port_manager():
    """
    Create a PortManager instance without filesystem dependencies.

    Returns:
        PortManager: Instance with mocked filesystem operations
    """
    # Create instance without running __init__ to avoid filesystem access
    pm = PortManager.__new__(PortManager)
    return pm


@pytest.fixture
def sample_ip_addresses():
    """
    Provide a collection of sample IP addresses for testing.

    Returns:
        list: Collection of IPv4Address objects for testing
    """
    return [
        ipaddress.IPv4Address("192.168.1.1"),
        ipaddress.IPv4Address("192.168.1.2"),
        ipaddress.IPv4Address("10.0.0.1"),
        ipaddress.IPv4Address("10.0.0.2"),
    ]


@pytest.fixture
def valid_port_data():
    """
    Provide valid port data for testing.

    Returns:
        dict: Valid port-to-service mapping
    """
    return {
        "22": "ssh",
        "80": "http",
        "443": "https",
        "8080": "http-proxy",
        "3389": "rdp"
    }


@pytest.fixture
def invalid_port_data():
    """
    Provide various invalid port data cases for testing.

    Returns:
        list: Collection of invalid port data dictionaries
    """
    return [
        {"-1": "negative"},      # Negative port
        {"70000": "too_high"},   # Port out of range
        {"abc": "not_int"},      # Non-integer port
        {"80": 123},             # Service not a string
        {"": "empty_port"},      # Empty port
        # Note: Empty service name appears to be valid based on test results
    ]


@pytest.fixture
def scan_config():
    """
    Create a default ScanConfig for testing.

    Returns:
        ScanConfig: Default configuration instance
    """
    return ScanConfig()


@pytest.fixture
def mock_socket():
    """
    Create a mock socket for network testing.

    Returns:
        MagicMock: Mocked socket object
    """
    with patch('socket.socket') as mock_sock:
        yield mock_sock


@pytest.fixture
def temp_subnet():
    """
    Provide a small test subnet that won't trigger size limits.

    Returns:
        str: CIDR notation for a small test subnet
    """
    return "192.168.1.0/30"


@pytest.fixture
def ip_test_cases():
    """
    Provide comprehensive IP parsing test cases.

    Returns:
        dict: Test cases with inputs and expected outputs
    """
    return {
        'cidr': {
            'input': '192.168.0.0/30',
            'expected': ['192.168.0.1', '192.168.0.2']
        },
        'range': {
            'input': '10.0.0.1-10.0.0.3',
            'expected': ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        },
        'shorthand': {
            'input': '10.0.0.1-3',
            'expected': ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        },
        'mixed': {
            'input': "10.0.0.1/30, 10.0.0.10-10.0.0.12, 10.0.0.20-22, 10.0.0.50",
            'expected': [
                "10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.11",
                "10.0.0.12", "10.0.0.20", "10.0.0.21", "10.0.0.22", "10.0.0.50"
            ]
        }
    }


@pytest.fixture
def mock_successful_socket():
    """
    Create a mock socket that simulates successful connections.

    Returns:
        MagicMock: Mocked socket that always succeeds
    """
    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 0  # Success
        yield mock_socket


@pytest.fixture
def mock_failed_socket():
    """
    Create a mock socket that simulates failed connections.

    Returns:
        MagicMock: Mocked socket that always fails
    """
    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 1  # Connection failed
        yield mock_socket


@pytest.fixture
def sample_port_list():
    """Sample port list for testing."""
    return {'80': 'http', '443': 'https'}


@pytest.fixture
def test_scan_config():
    """Standard scan configuration for testing."""
    return {
        'subnet': TEST_SUBNET,
        'port_list': 'small',
        'lookup_type': ['ICMP', 'POKE_THEN_ARP'],
        't_multiplier': 1.5,  # Slower to ensure measurable runtime
        't_cnt_isalive': 2,   # Limit threads to extend runtime
        'ping_config': {'timeout': 0.8, 'attempts': 2}  # Reasonable timeout for external IPs
    }
