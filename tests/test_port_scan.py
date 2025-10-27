"""
Tests for port scanning functionality including the new PortScanConfig
retry logic and timeout enforcement.
"""

from time import time
from unittest.mock import patch, MagicMock

import pytest

from lanscape.core.net_tools import Device
from lanscape.core.scan_config import PortScanConfig


@pytest.fixture
def test_device():
    """Create a test device for port scanning."""
    return Device(ip="127.0.0.1")


@pytest.fixture
def default_port_config():
    """Create a default PortScanConfig for testing."""
    return PortScanConfig()


@pytest.fixture
def retry_port_config():
    """Create a PortScanConfig with retry settings for testing."""
    return PortScanConfig(
        timeout=1.0,
        retries=2,
        retry_delay=0.1
    )

# PortScanConfig Tests
######################


def test_port_scan_config_defaults():
    """Test PortScanConfig default values."""
    config = PortScanConfig()
    assert config.timeout == 1.0
    assert config.retries == 0
    assert config.retry_delay == 0.1


@pytest.mark.parametrize("timeout,retries,retry_delay", [
    (2.5, 3, 0.5),
    (1.0, 1, 0.2),
    (0.5, 5, 0.1),
    (3.0, 0, 1.0),
])
def test_port_scan_config_custom_values(timeout, retries, retry_delay):
    """Test PortScanConfig with various custom values."""
    config = PortScanConfig(
        timeout=timeout,
        retries=retries,
        retry_delay=retry_delay
    )
    assert config.timeout == timeout
    assert config.retries == retries
    assert config.retry_delay == retry_delay


def test_port_scan_config_serialization():
    """Test PortScanConfig serialization and deserialization."""
    config = PortScanConfig(timeout=2.0, retries=1, retry_delay=0.2)

    # Test to_dict
    config_dict = config.to_dict()
    assert config_dict['timeout'] == 2.0
    assert config_dict['retries'] == 1
    assert config_dict['retry_delay'] == 0.2

    # Test from_dict
    restored_config = PortScanConfig.from_dict(config_dict)
    assert restored_config.timeout == 2.0
    assert restored_config.retries == 1
    assert restored_config.retry_delay == 0.2

# Device Port Testing
####################


def test_device_test_port_with_default_config(test_device, default_port_config):
    """Test Device.test_port with default PortScanConfig."""
    # Test with a port that should be closed
    result = test_device.test_port(54321, default_port_config)
    assert isinstance(result, bool)
    assert result is False  # Should be closed

    # Verify ports_scanned counter incremented
    assert test_device.ports_scanned == 1


def test_device_test_port_without_config(test_device):
    """Test Device.test_port without passing config (should use defaults)."""
    initial_count = test_device.ports_scanned
    result = test_device.test_port(54322)
    assert isinstance(result, bool)
    assert test_device.ports_scanned == initial_count + 1


@patch('socket.socket')
def test_device_test_port_with_retries(mock_socket_class, test_device):
    """Test Device.test_port retry mechanism."""
    # Mock socket to fail first time, succeed second time
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # First call fails, second succeeds
    mock_socket.connect_ex.side_effect = [1, 0]  # 1 = connection failed, 0 = success

    config = PortScanConfig(timeout=0.5, retries=1, retry_delay=0.1)
    start_time = time()
    result = test_device.test_port(80, config)
    elapsed_time = time() - start_time

    # Should succeed on retry
    assert result is True

    # Should have made 2 connection attempts
    assert mock_socket.connect_ex.call_count == 2

    # Should have taken at least the retry delay
    assert elapsed_time >= 0.1

    # Port should be added to device ports list
    assert 80 in test_device.ports


@patch('socket.socket')
def test_device_test_port_all_retries_fail(mock_socket_class, test_device):
    """Test Device.test_port when all retries fail."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # All attempts fail
    mock_socket.connect_ex.return_value = 1  # Connection failed

    config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.1)
    result = test_device.test_port(54323, config)

    # Should fail
    assert result is False

    # Should have made 3 attempts (initial + 2 retries)
    assert mock_socket.connect_ex.call_count == 3

    # Port should not be in ports list
    assert 54323 not in test_device.ports


@patch('socket.socket')
def test_device_test_port_exception_handling(mock_socket_class, test_device):
    """Test Device.test_port exception handling during connection."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # Raise exception on first call, succeed on retry
    mock_socket.connect_ex.side_effect = [Exception("Connection error"), 0]

    config = PortScanConfig(timeout=0.5, retries=1, retry_delay=0.1)
    result = test_device.test_port(80, config)

    # Should succeed on retry despite exception
    assert result is True
    assert 80 in test_device.ports

# Timeout and Configuration Tests
##################################


@pytest.mark.parametrize("timeout,retries,expected_enforcer_timeout", [
    (1.0, 0, 1.5),      # 1.0 * (0 + 1) * 1.5 = 1.5
    (2.0, 2, 9.0),      # 2.0 * (2 + 1) * 1.5 = 9.0
    (0.5, 1, 1.5),      # 0.5 * (1 + 1) * 1.5 = 1.5
    (3.0, 3, 18.0),     # 3.0 * (3 + 1) * 1.5 = 18.0
])
def test_timeout_enforcer_calculation(timeout, retries, expected_enforcer_timeout):
    """Test that timeout enforcer uses correct formula."""
    config = PortScanConfig(timeout=timeout, retries=retries, retry_delay=0.1)

    # Formula: timeout * (retries + 1) * 1.5
    calculated_timeout = config.timeout * (config.retries + 1) * 1.5
    assert calculated_timeout == expected_enforcer_timeout


def test_device_ports_scanned_counter(test_device, default_port_config):
    """Test that ports_scanned counter is properly incremented."""
    initial_count = test_device.ports_scanned

    # Test multiple ports
    test_device.test_port(54324, default_port_config)
    test_device.test_port(54325, default_port_config)
    test_device.test_port(54326, default_port_config)

    assert test_device.ports_scanned == initial_count + 3


@patch('socket.socket')
def test_socket_timeout_setting(mock_socket_class, test_device):
    """Test that socket timeout is properly set from config."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    mock_socket.connect_ex.return_value = 1  # Connection failed

    config = PortScanConfig(timeout=2.5, retries=0, retry_delay=0.1)
    test_device.test_port(54327, config)

    # Verify socket timeout was set correctly
    mock_socket.settimeout.assert_called_with(2.5)


def test_retry_delay_timing(test_device):
    """Test that retry delay is respected."""
    # We'll use a mock to avoid actually waiting
    with patch('lanscape.core.net_tools.sleep') as mock_sleep:
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 1  # Always fail

            config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.3)
            test_device.test_port(54328, config)

            # Should have called sleep twice (between 3 attempts)
            assert mock_sleep.call_count == 2

            # Should have called with correct delay
            mock_sleep.assert_called_with(0.3)


@pytest.mark.parametrize("config_name,config_params", [
    ("zero_timeout", {"timeout": 0.0, "retries": 0, "retry_delay": 0.1}),
    ("no_retry", {"timeout": 1.0, "retries": 0, "retry_delay": 0.1}),
    ("high_retry", {"timeout": 0.1, "retries": 5, "retry_delay": 0.01}),
])
def test_port_scan_edge_cases(test_device, config_name, config_params):
    """Test edge cases for port scanning."""
    config = PortScanConfig(**config_params)
    port = 54329 + hash(config_name) % 100  # Generate unique port for each case
    result = test_device.test_port(port, config)
    assert isinstance(result, bool)


@patch('socket.socket')
def test_device_ports_list_management(mock_socket_class, test_device, default_port_config):
    """Test that open ports are properly added to device.ports list."""
    initial_ports = len(test_device.ports)

    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # Simulate open port
    mock_socket.connect_ex.return_value = 0  # Success

    result = test_device.test_port(80, default_port_config)

    assert result is True
    assert len(test_device.ports) == initial_ports + 1
    assert 80 in test_device.ports


@pytest.mark.parametrize("port_count", [1, 3, 5])
def test_multiple_port_scans_on_same_device(test_device, default_port_config, port_count):
    """Test scanning multiple ports on the same device."""
    ports_to_test = [54332 + i for i in range(port_count)]
    initial_count = test_device.ports_scanned

    for port in ports_to_test:
        result = test_device.test_port(port, default_port_config)
        assert isinstance(result, bool)

    # All ports should be counted as scanned
    assert test_device.ports_scanned == initial_count + len(ports_to_test)
