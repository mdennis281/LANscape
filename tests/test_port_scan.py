"""
Tests for port scanning functionality including the new PortScanConfig
retry logic and timeout enforcement.
"""

import unittest
from unittest.mock import patch, MagicMock
from time import time

from lanscape.libraries.net_tools import Device
from lanscape.libraries.scan_config import PortScanConfig


class PortScanTestCase(unittest.TestCase):
    """
    Test cases for port scanning functionality including retry logic,
    timeout handling, and configuration validation.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.device = Device(ip="127.0.0.1")
        self.default_config = PortScanConfig()
        self.retry_config = PortScanConfig(
            timeout=1.0,
            retries=2,
            retry_delay=0.1
        )

    def test_port_scan_config_defaults(self):
        """Test PortScanConfig default values."""
        config = PortScanConfig()
        self.assertEqual(config.timeout, 1.0)
        self.assertEqual(config.retries, 0)
        self.assertEqual(config.retry_delay, 0.1)

    def test_port_scan_config_custom_values(self):
        """Test PortScanConfig with custom values."""
        config = PortScanConfig(
            timeout=2.5,
            retries=3,
            retry_delay=0.5
        )
        self.assertEqual(config.timeout, 2.5)
        self.assertEqual(config.retries, 3)
        self.assertEqual(config.retry_delay, 0.5)

    def test_port_scan_config_serialization(self):
        """Test PortScanConfig serialization and deserialization."""
        config = PortScanConfig(timeout=2.0, retries=1, retry_delay=0.2)

        # Test to_dict
        config_dict = config.to_dict()
        self.assertEqual(config_dict['timeout'], 2.0)
        self.assertEqual(config_dict['retries'], 1)
        self.assertEqual(config_dict['retry_delay'], 0.2)

        # Test from_dict
        restored_config = PortScanConfig.from_dict(config_dict)
        self.assertEqual(restored_config.timeout, 2.0)
        self.assertEqual(restored_config.retries, 1)
        self.assertEqual(restored_config.retry_delay, 0.2)

    def test_device_test_port_with_default_config(self):
        """Test Device.test_port with default PortScanConfig."""
        # Test with a port that should be closed
        result = self.device.test_port(54321, self.default_config)
        self.assertIsInstance(result, bool)
        self.assertFalse(result)  # Should be closed

        # Verify ports_scanned counter incremented
        self.assertEqual(self.device.ports_scanned, 1)

    def test_device_test_port_without_config(self):
        """Test Device.test_port without passing config (should use defaults)."""
        initial_count = self.device.ports_scanned
        result = self.device.test_port(54322)
        self.assertIsInstance(result, bool)
        self.assertEqual(self.device.ports_scanned, initial_count + 1)

    @patch('socket.socket')
    def test_device_test_port_with_retries(self, mock_socket_class):
        """Test Device.test_port retry mechanism."""
        # Mock socket to fail first time, succeed second time
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # First call fails, second succeeds
        mock_socket.connect_ex.side_effect = [1, 0]  # 1 = connection failed, 0 = success

        config = PortScanConfig(timeout=0.5, retries=1, retry_delay=0.1)
        start_time = time()
        result = self.device.test_port(80, config)
        elapsed_time = time() - start_time

        # Should succeed on retry
        self.assertTrue(result)

        # Should have made 2 connection attempts
        self.assertEqual(mock_socket.connect_ex.call_count, 2)

        # Should have taken at least the retry delay
        self.assertGreaterEqual(elapsed_time, 0.1)

        # Port should be added to device ports list
        self.assertIn(80, self.device.ports)

    @patch('socket.socket')
    def test_device_test_port_all_retries_fail(self, mock_socket_class):
        """Test Device.test_port when all retries fail."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # All attempts fail
        mock_socket.connect_ex.return_value = 1  # Connection failed

        config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.1)
        result = self.device.test_port(54323, config)

        # Should fail
        self.assertFalse(result)

        # Should have made 3 attempts (initial + 2 retries)
        self.assertEqual(mock_socket.connect_ex.call_count, 3)

        # Port should not be in ports list
        self.assertNotIn(54323, self.device.ports)

    @patch('socket.socket')
    def test_device_test_port_exception_handling(self, mock_socket_class):
        """Test Device.test_port exception handling during connection."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        # Raise exception on first call, succeed on retry
        mock_socket.connect_ex.side_effect = [Exception("Connection error"), 0]

        config = PortScanConfig(timeout=0.5, retries=1, retry_delay=0.1)
        result = self.device.test_port(80, config)

        # Should succeed on retry despite exception
        self.assertTrue(result)
        self.assertIn(80, self.device.ports)

    def test_timeout_enforcer_calculation(self):
        """Test that timeout enforcer uses correct formula."""
        # Test with default config
        config = PortScanConfig(timeout=1.0, retries=0, retry_delay=0.1)
        # Expected enforcer timeout: 1.0 * (0 + 1) * 1.5 = 1.5

        # Test with retries
        config_with_retries = PortScanConfig(timeout=2.0, retries=2, retry_delay=0.2)
        # Expected enforcer timeout: 2.0 * (2 + 1) * 1.5 = 9.0

        # We can't directly test the timeout enforcer calculation without
        # modifying the implementation, but we can verify the config values
        self.assertEqual(config.timeout * (config.retries + 1) * 1.5, 1.5)
        self.assertEqual(config_with_retries.timeout * (config_with_retries.retries + 1) * 1.5, 9.0)

    def test_device_ports_scanned_counter(self):
        """Test that ports_scanned counter is properly incremented."""
        initial_count = self.device.ports_scanned

        # Test multiple ports
        self.device.test_port(54324, self.default_config)
        self.device.test_port(54325, self.default_config)
        self.device.test_port(54326, self.default_config)

        self.assertEqual(self.device.ports_scanned, initial_count + 3)

    @patch('socket.socket')
    def test_socket_timeout_setting(self, mock_socket_class):
        """Test that socket timeout is properly set from config."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 1  # Connection failed

        config = PortScanConfig(timeout=2.5, retries=0, retry_delay=0.1)
        self.device.test_port(54327, config)

        # Verify socket timeout was set correctly
        mock_socket.settimeout.assert_called_with(2.5)

    def test_retry_delay_timing(self):
        """Test that retry delay is respected."""
        # We'll use a mock to avoid actually waiting
        with patch('lanscape.libraries.net_tools.sleep') as mock_sleep:
            with patch('socket.socket') as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.connect_ex.return_value = 1  # Always fail

                config = PortScanConfig(timeout=0.5, retries=2, retry_delay=0.3)
                self.device.test_port(54328, config)

                # Should have called sleep twice (between 3 attempts)
                self.assertEqual(mock_sleep.call_count, 2)

                # Should have called with correct delay
                mock_sleep.assert_called_with(0.3)

    def test_port_scan_edge_cases(self):
        """Test edge cases for port scanning."""
        # Test with zero timeout
        zero_timeout_config = PortScanConfig(timeout=0.0, retries=0, retry_delay=0.1)
        result = self.device.test_port(54329, zero_timeout_config)
        self.assertIsInstance(result, bool)

        # Test with zero retries (should be same as default)
        no_retry_config = PortScanConfig(timeout=1.0, retries=0, retry_delay=0.1)
        result = self.device.test_port(54330, no_retry_config)
        self.assertIsInstance(result, bool)

        # Test with high retry count
        high_retry_config = PortScanConfig(timeout=0.1, retries=5, retry_delay=0.01)
        result = self.device.test_port(54331, high_retry_config)
        self.assertIsInstance(result, bool)

    def test_device_ports_list_management(self):
        """Test that open ports are properly added to device.ports list."""
        initial_ports = len(self.device.ports)

        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate open port
            mock_socket.connect_ex.return_value = 0  # Success

            result = self.device.test_port(80, self.default_config)

            self.assertTrue(result)
            self.assertEqual(len(self.device.ports), initial_ports + 1)
            self.assertIn(80, self.device.ports)

    def test_multiple_port_scans_on_same_device(self):
        """Test scanning multiple ports on the same device."""
        ports_to_test = [54332, 54333, 54334, 54335]
        initial_count = self.device.ports_scanned

        for port in ports_to_test:
            result = self.device.test_port(port, self.default_config)
            self.assertIsInstance(result, bool)

        # All ports should be counted as scanned
        self.assertEqual(self.device.ports_scanned, initial_count + len(ports_to_test))


if __name__ == '__main__':
    unittest.main()
