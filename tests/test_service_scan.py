"""
Dedicated tests for service scanning functionality.
Tests the service_scan module including async probing, service identification,
and configuration handling.
"""

import asyncio
import unittest
from unittest.mock import patch, AsyncMock, MagicMock

from lanscape.libraries.service_scan import (
    scan_service,
    get_port_probes,
    _try_probe,
    _multi_probe_generic,
    PRINTER_PORTS,
    asyncio_logger_suppression
)
from lanscape.libraries.scan_config import ServiceScanConfig, ServiceScanStrategy


class ServiceScanTestCase(unittest.TestCase):
    """
    Test cases for service scanning functionality including probe generation,
    async operations, and service identification.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.default_config = ServiceScanConfig()
        self.lazy_config = ServiceScanConfig(
            timeout=1.0,
            lookup_type=ServiceScanStrategy.LAZY,
            max_concurrent_probes=3
        )
        self.aggressive_config = ServiceScanConfig(
            timeout=5.0,
            lookup_type=ServiceScanStrategy.AGGRESSIVE,
            max_concurrent_probes=20
        )

    def test_service_scan_strategy_enum(self):
        """Test ServiceScanStrategy enum values."""
        self.assertEqual(ServiceScanStrategy.LAZY.value, 'LAZY')
        self.assertEqual(ServiceScanStrategy.BASIC.value, 'BASIC')
        self.assertEqual(ServiceScanStrategy.AGGRESSIVE.value, 'AGGRESSIVE')

    def test_get_port_probes_lazy_strategy(self):
        """Test probe generation for LAZY strategy."""
        probes = get_port_probes(80, ServiceScanStrategy.LAZY)

        self.assertIsInstance(probes, list)
        self.assertGreater(len(probes), 0)

        # Should include basic probes
        self.assertIn(None, probes)  # Banner grab
        self.assertIn(b"\r\n", probes)  # Basic nudge
        self.assertIn(b"HELP\r\n", probes)  # Help command

        # Should include HTTP probes for web-related ports
        http_probes = [p for p in probes if p and b"HTTP" in p]
        self.assertGreater(len(http_probes), 0)

    def test_get_port_probes_basic_strategy(self):
        """Test probe generation for BASIC strategy."""
        probes_22 = get_port_probes(22, ServiceScanStrategy.BASIC)  # SSH port
        probes_80 = get_port_probes(80, ServiceScanStrategy.BASIC)  # HTTP port
        probes_443 = get_port_probes(443, ServiceScanStrategy.BASIC)  # HTTPS port

        for probes in [probes_22, probes_80, probes_443]:
            self.assertIsInstance(probes, list)
            self.assertGreater(len(probes), 0)

    def test_get_port_probes_aggressive_strategy(self):
        """Test probe generation for AGGRESSIVE strategy."""
        probes = get_port_probes(80, ServiceScanStrategy.AGGRESSIVE)

        self.assertIsInstance(probes, list)
        self.assertGreater(len(probes), 0)

        # Aggressive should have more probes than lazy
        lazy_probes = get_port_probes(80, ServiceScanStrategy.LAZY)
        self.assertGreaterEqual(len(probes), len(lazy_probes))

    def test_printer_ports_detection(self):
        """Test that printer ports are properly handled."""
        self.assertIn(9100, PRINTER_PORTS)  # Standard printer port
        self.assertIn(631, PRINTER_PORTS)   # IPP port

        # Test service scan on printer ports
        for port in PRINTER_PORTS:
            result = scan_service("127.0.0.1", port, self.default_config)
            self.assertEqual(result, "Printer")

    def test_scan_service_invalid_target(self):
        """Test service scanning against invalid targets."""
        # Test with non-existent IP
        result = scan_service("192.168.254.254", 80, self.lazy_config)
        self.assertIn(result, ["Unknown"])

        # Test with invalid port
        result = scan_service("127.0.0.1", 99999, self.lazy_config)  # Port out of range
        self.assertIn(result, ["Unknown"])

    def test_scan_service_timeout_configurations(self):
        """Test service scanning with different timeout settings."""
        short_timeout_config = ServiceScanConfig(timeout=0.1)
        long_timeout_config = ServiceScanConfig(timeout=10.0)

        # Both should complete without crashing
        result1 = scan_service("127.0.0.1", 54321, short_timeout_config)
        result2 = scan_service("127.0.0.1", 54322, long_timeout_config)

        self.assertIsInstance(result1, str)
        self.assertIsInstance(result2, str)

    def test_concurrent_probe_limits(self):
        """Test that concurrent probe limits are respected."""
        low_concurrency = ServiceScanConfig(
            max_concurrent_probes=1,
            lookup_type=ServiceScanStrategy.BASIC,
            timeout=2.0
        )
        high_concurrency = ServiceScanConfig(
            max_concurrent_probes=50,
            lookup_type=ServiceScanStrategy.AGGRESSIVE,
            timeout=2.0
        )

        # Both should work without issues
        result1 = scan_service("127.0.0.1", 54323, low_concurrency)
        result2 = scan_service("127.0.0.1", 54324, high_concurrency)

        self.assertIsInstance(result1, str)
        self.assertIsInstance(result2, str)

    def test_try_probe_success(self):
        """Test _try_probe with successful connection."""
        async def run_test():
            with patch('asyncio.open_connection') as mock_open_connection:
                # Create simplified mocks
                mock_reader = AsyncMock()
                mock_reader.read.return_value = b"HTTP/1.1 200 OK\r\n"

                mock_writer = MagicMock()
                mock_writer.drain = AsyncMock()
                mock_writer.wait_closed = AsyncMock()
                mock_open_connection.return_value = (mock_reader, mock_writer)

                result = await _try_probe("127.0.0.1", 80, "GET / HTTP/1.0\r\n\r\n")
                self.assertIsInstance(result, str)
                self.assertIn("HTTP", result)

        asyncio.run(run_test())

    def test_try_probe_connection_refused(self):
        """Test _try_probe with connection refused."""
        async def run_test():
            with patch('asyncio.open_connection') as mock_open_connection:
                mock_open_connection.side_effect = ConnectionRefusedError()

                result = await _try_probe("127.0.0.1", 54325)
                self.assertIsNone(result)

        asyncio.run(run_test())

    def test_try_probe_timeout(self):
        """Test _try_probe with timeout."""
        async def run_test():
            with patch('asyncio.open_connection') as mock_open_connection:
                mock_open_connection.side_effect = asyncio.TimeoutError()

                result = await _try_probe("127.0.0.1", 80, timeout=0.1)
                self.assertIsNone(result)

        asyncio.run(run_test())

    def test_multi_probe_generic_no_response(self):
        """Test _multi_probe_generic with no responses."""
        async def run_test():
            config = ServiceScanConfig(timeout=0.5, lookup_type=ServiceScanStrategy.LAZY)

            # Use a high port that should be closed
            result = await _multi_probe_generic("127.0.0.1", 54326, config)
            self.assertIsNone(result)

        asyncio.run(run_test())

    def test_asyncio_logger_suppression(self):
        """Test that asyncio logger suppression works."""
        # This should not raise any exceptions
        asyncio_logger_suppression()

        # Verify that asyncio logger level was changed
        import logging
        asyncio_logger = logging.getLogger("asyncio")
        self.assertGreaterEqual(asyncio_logger.level, logging.WARNING)

    def test_service_scan_integration(self):
        """Integration test for full service scanning workflow."""
        # Test with different strategies on localhost
        strategies = [
            ServiceScanStrategy.LAZY,
            ServiceScanStrategy.BASIC,
            ServiceScanStrategy.AGGRESSIVE
        ]

        for strategy in strategies:
            config = ServiceScanConfig(
                timeout=1.0,
                lookup_type=strategy,
                max_concurrent_probes=5
            )

            # Test on a high port that should be closed
            result = scan_service("127.0.0.1", 54327 + hash(strategy.value) % 1000, config)
            self.assertIsInstance(result, str)
            self.assertTrue(len(result) > 0)  # Should return something (likely "Unknown")

    def test_service_config_validation(self):
        """Test ServiceScanConfig validation and edge cases."""
        # Test with minimum values
        min_config = ServiceScanConfig(
            timeout=0.1,
            max_concurrent_probes=1
        )
        result = scan_service("127.0.0.1", 54328, min_config)
        self.assertIsInstance(result, str)

        # Test with maximum reasonable values
        max_config = ServiceScanConfig(
            timeout=30.0,
            max_concurrent_probes=100
        )
        # Don't actually run this one as it would take too long
        self.assertEqual(max_config.timeout, 30.0)
        self.assertEqual(max_config.max_concurrent_probes, 100)

    def test_probe_payload_types(self):
        """Test different types of probe payloads."""
        probes = get_port_probes(80, ServiceScanStrategy.BASIC)

        # Should have mix of None, bytes, and string payloads
        has_none = any(p is None for p in probes)
        has_bytes = any(isinstance(p, bytes) for p in probes)

        self.assertTrue(has_none, "Should include None for banner grab")
        self.assertTrue(has_bytes, "Should include bytes payloads")


if __name__ == '__main__':
    unittest.main()
