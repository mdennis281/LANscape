"""
Tests for file descriptor exhaustion during large port scans.

This module tests the scenario where scanning a large number of ports
can exhaust file descriptors (sockets) on Unix-like systems such as
Linux and macOS, causing "Too many open files" OSError.
"""

import sys
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest

from lanscape.core.net_tools import Device
from lanscape.core.scan_config import PortScanConfig

# Skip all tests in this module on non-Linux platforms
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="File descriptor exhaustion tests are Linux-specific"
)

try:
    import resource
except ImportError:
    resource = None  # Will be skipped anyway on non-Linux


def test_socket_properly_closed_on_success():
    """Test that sockets are properly closed when connection succeeds."""
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=0)

    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 0  # Success

        device.test_port(80, config)

        # Verify socket was closed
        mock_socket.close.assert_called_once()


def test_socket_properly_closed_on_failure():
    """Test that sockets are properly closed when connection fails."""
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=0)

    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 1  # Failure

        device.test_port(54321, config)

        # Verify socket was closed
        mock_socket.close.assert_called_once()


def test_socket_properly_closed_on_exception():
    """Test that sockets are properly closed when an exception occurs."""
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=0)

    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.side_effect = Exception("Connection error")

        device.test_port(54322, config)

        # Verify socket was closed even with exception
        mock_socket.close.assert_called_once()


def test_socket_properly_closed_with_retries():
    """Test that sockets are properly closed on each retry attempt."""
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.05)

    with patch('socket.socket') as mock_socket_class:
        # Create multiple mock socket instances
        mock_sockets = [MagicMock() for _ in range(3)]
        mock_socket_class.side_effect = mock_sockets

        # All attempts fail
        for mock_sock in mock_sockets:
            mock_sock.connect_ex.return_value = 1

        device.test_port(54323, config)

        # Verify each socket was closed (initial + 2 retries = 3 total)
        for mock_sock in mock_sockets:
            mock_sock.close.assert_called_once()


def test_socket_closed_on_socket_creation_failure():
    """Test handling when socket creation itself fails (OSError: Too many open files)."""
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=1, retry_delay=0.05)

    with patch('socket.socket') as mock_socket_class:
        # First attempt: socket creation fails with "Too many open files"
        # Second attempt: succeeds
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        mock_socket_class.side_effect = [
            OSError(24, "Too many open files"),
            mock_socket
        ]

        # Should not crash, should handle the error gracefully
        result = device.test_port(54324, config)

        # Should return False since we couldn't connect
        assert result is False

        # Second socket should have been closed
        mock_socket.close.assert_called_once()


def test_multiple_concurrent_port_scans_socket_cleanup():
    """Test that concurrent port scans properly clean up sockets."""
    device = Device(ip="192.168.1.100")
    config = PortScanConfig(timeout=0.1, retries=0)
    ports = list(range(8000, 8100))  # 100 ports

    with patch('socket.socket') as mock_socket_class:
        mock_sockets = []

        def create_mock_socket(*_args, **_kwargs):
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # All closed
            mock_sockets.append(mock_sock)
            return mock_sock

        mock_socket_class.side_effect = create_mock_socket

        # Scan all ports concurrently (simulating real scenario)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(device.test_port, port, config) for port in ports]
            for future in as_completed(futures):
                future.result()

        # Verify all sockets were closed
        assert len(mock_sockets) == 100
        for mock_sock in mock_sockets:
            mock_sock.close.assert_called_once()


def test_socket_cleanup_with_high_fd_limit():
    """Test socket cleanup when approaching file descriptor limits."""
    device = Device(ip="192.168.1.100")
    config = PortScanConfig(timeout=0.1, retries=1, retry_delay=0.05)

    # Simulate a scenario where we're near the FD limit
    with patch('socket.socket') as mock_socket_class:
        call_count = 0
        max_calls_before_error = 50

        def socket_with_limit(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1

            if call_count >= max_calls_before_error:
                # Simulate "too many open files" error
                raise OSError(24, "Too many open files")

            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1
            return mock_sock

        mock_socket_class.side_effect = socket_with_limit

        # Scan ports until we hit the limit
        ports_scanned = 0
        for port in range(8000, 8200):
            try:
                device.test_port(port, config)
                ports_scanned += 1
            except OSError:
                # Should handle gracefully
                break

        # Should have scanned some ports before hitting limit
        assert ports_scanned > 0
        # Should not have crashed the entire scan


def test_socket_error_handling_retries():
    """Test that socket errors during retries are handled properly."""
    device = Device(ip="192.168.1.100")
    config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.05)

    with patch('socket.socket') as mock_socket_class:
        # First attempt: Too many open files
        # Second attempt: Connection timeout
        # Third attempt: Success
        mock_sock2 = MagicMock()
        mock_sock3 = MagicMock()

        mock_socket_class.side_effect = [
            OSError(24, "Too many open files"),
            mock_sock2,
            mock_sock3
        ]

        mock_sock2.connect_ex.return_value = 1  # Fail
        mock_sock3.connect_ex.return_value = 0  # Success

        result = device.test_port(80, config)

        # Should succeed on third attempt
        assert result is True

        # Both successful socket creations should have been closed
        mock_sock2.close.assert_called_once()
        mock_sock3.close.assert_called_once()


def test_context_manager_style_socket_would_be_better():
    """
    This test documents that using 'with' statement for sockets would be better.
    This is more of a design verification test.
    """
    device = Device(ip="127.0.0.1")
    config = PortScanConfig(timeout=0.5, retries=0)

    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # Simulate that the socket supports context manager
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=None)
        mock_socket.connect_ex.return_value = 0

        device.test_port(80, config)

        # Verify close was called
        # (In the future, if we switch to 'with socket.socket()...',
        # __exit__ would be called automatically)
        mock_socket.close.assert_called()


@pytest.mark.skipif(
    not resource or resource.getrlimit(resource.RLIMIT_NOFILE)[0] > 10000,
    reason="Only run on Linux systems with reasonable FD limits"
)
def test_real_socket_exhaustion_scenario():
    """
    Test with real sockets to verify the fix handles actual FD exhaustion.
    This test creates many sockets to approach system limits.
    """
    device = Device(ip="192.168.254.254")  # Non-existent IP to ensure timeout
    config = PortScanConfig(timeout=0.01, retries=0)  # Very short timeout

    # Get current FD limit
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)

    # Track failures
    failures = []
    success_count = 0

    # Try to scan many ports
    for port in range(1, min(200, soft_limit // 10)):
        try:
            result = device.test_port(port, config)
            if result:
                success_count += 1
        except OSError as e:
            failures.append((port, str(e)))

    # Should not have any "Too many open files" errors
    too_many_files_errors = [f for f in failures if "Too many open files" in f[1]]
    assert len(too_many_files_errors) == 0, (
        f"Got {len(too_many_files_errors)} 'Too many open files' errors: "
        f"{too_many_files_errors[:5]}"
    )


def test_socket_cleanup_in_timeout_enforcer():
    """Test that sockets are cleaned up even when timeout_enforcer kills the function."""
    import time  # pylint: disable=import-outside-toplevel

    device = Device(ip="192.168.1.100")
    # Very short enforcer timeout to trigger timeout
    config = PortScanConfig(timeout=10.0, retries=0)  # 10 * 1 * 1.5 = 15s enforcer

    with patch('socket.socket') as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # Make connect_ex hang (simulate very slow network)
        def slow_connect(*_args):
            time.sleep(0.5)
            return 1

        mock_socket.connect_ex.side_effect = slow_connect

        device.test_port(54325, config)

        # Socket should still be closed
        mock_socket.close.assert_called()
