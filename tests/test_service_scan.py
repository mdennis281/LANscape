"""
Dedicated tests for service scanning functionality.
Tests the service_scan module including async probing, service identification,
and configuration handling.
"""
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from lanscape.core.service_scan import (
    scan_service,
    get_port_probes,
    _try_probe,
    _multi_probe_generic,
    PRINTER_PORTS,
    ServiceScanResult
)
from lanscape.core.scan_config import ServiceScanConfig, ServiceScanStrategy


# Service Scan Configuration Fixtures
######################################

@pytest.fixture
def default_config():
    """Default service scan configuration."""
    return ServiceScanConfig()


@pytest.fixture
def lazy_config():
    """Lazy service scan configuration."""
    return ServiceScanConfig(
        timeout=1.0,
        lookup_type=ServiceScanStrategy.LAZY,
        max_concurrent_probes=3
    )


@pytest.fixture
def aggressive_config():
    """Aggressive service scan configuration."""
    return ServiceScanConfig(
        timeout=5.0,
        lookup_type=ServiceScanStrategy.AGGRESSIVE,
        max_concurrent_probes=20
    )

# Strategy and Probe Generation Tests
####################################


def test_service_scan_strategy_enum():
    """Test ServiceScanStrategy enum values."""
    assert ServiceScanStrategy.LAZY.value == 'LAZY'
    assert ServiceScanStrategy.BASIC.value == 'BASIC'
    assert ServiceScanStrategy.AGGRESSIVE.value == 'AGGRESSIVE'


def test_get_port_probes_lazy_strategy():
    """Test probe generation for LAZY strategy."""
    probes = get_port_probes(80, ServiceScanStrategy.LAZY)

    assert isinstance(probes, list)
    assert len(probes) > 0

    # Should include basic probes
    assert None in probes  # Banner grab
    assert b"\r\n" in probes  # Basic nudge
    assert b"HELP\r\n" in probes  # Help command

    # Should include HTTP probes for web-related ports
    http_probes = [p for p in probes if p and b"HTTP" in p]
    assert len(http_probes) > 0


@pytest.mark.parametrize("port", [22, 80, 443])
def test_get_port_probes_basic_strategy(port):
    """Test probe generation for BASIC strategy."""
    probes = get_port_probes(port, ServiceScanStrategy.BASIC)
    assert isinstance(probes, list)
    assert len(probes) > 0


def test_get_port_probes_aggressive_strategy():
    """Test probe generation for AGGRESSIVE strategy."""
    probes = get_port_probes(80, ServiceScanStrategy.AGGRESSIVE)

    assert isinstance(probes, list)
    assert len(probes) > 0

    # Aggressive should have more probes than lazy
    lazy_probes = get_port_probes(80, ServiceScanStrategy.LAZY)
    assert len(probes) >= len(lazy_probes)


def test_printer_ports_detection(default_config):
    """Test that printer ports are properly handled."""
    assert 9100 in PRINTER_PORTS  # Standard printer port
    assert 631 in PRINTER_PORTS   # IPP port

    # Test service scan on printer ports
    for port in PRINTER_PORTS:
        result = scan_service("127.0.0.1", port, default_config)
        assert isinstance(result, ServiceScanResult)
        assert result.service == "Printer"


# Service Scanning Tests
#######################

def test_scan_service_invalid_target(lazy_config):
    """Test service scanning against invalid targets."""
    # Test with non-existent IP
    result = scan_service("192.168.254.254", 80, lazy_config)
    assert isinstance(result, ServiceScanResult)
    assert result.service == "Unknown"

    # Test with invalid port
    result = scan_service("127.0.0.1", 99999, lazy_config)  # Port out of range
    assert isinstance(result, ServiceScanResult)
    assert result.service == "Unknown"


def test_scan_service_timeout_configurations():
    """Test service scanning with different timeout settings."""
    short_timeout_config = ServiceScanConfig(timeout=0.1)
    long_timeout_config = ServiceScanConfig(timeout=10.0)

    # Both should complete without crashing
    result1 = scan_service("127.0.0.1", 54321, short_timeout_config)
    result2 = scan_service("127.0.0.1", 54322, long_timeout_config)

    assert isinstance(result1, ServiceScanResult)
    assert isinstance(result2, ServiceScanResult)


def test_concurrent_probe_limits():
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

    assert isinstance(result1, ServiceScanResult)
    assert isinstance(result2, ServiceScanResult)


# Async Probe Tests
##################

def test_try_probe_success():
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
            # _try_probe now returns tuple of (bytes, str)
            assert isinstance(result, tuple)
            raw_bytes, decoded_str = result
            assert isinstance(raw_bytes, bytes)
            assert isinstance(decoded_str, str)
            assert "HTTP" in decoded_str

    asyncio.run(run_test())


def test_try_probe_connection_refused():
    """Test _try_probe with connection refused."""
    async def run_test():
        with patch('asyncio.open_connection') as mock_open_connection:
            mock_open_connection.side_effect = ConnectionRefusedError()

            result = await _try_probe("127.0.0.1", 54325)
            # _try_probe now returns tuple of (None, None) on failure
            assert isinstance(result, tuple)
            assert result == (None, None)

    asyncio.run(run_test())


def test_try_probe_timeout():
    """Test _try_probe with timeout."""
    async def run_test():
        with patch('asyncio.open_connection') as mock_open_connection:
            mock_open_connection.side_effect = asyncio.TimeoutError()

            result = await _try_probe("127.0.0.1", 80, timeout=0.1)
            # _try_probe now returns tuple of (None, None) on failure
            assert isinstance(result, tuple)
            assert result == (None, None)

    asyncio.run(run_test())


def test_multi_probe_generic_no_response():
    """Test _multi_probe_generic with no responses."""
    async def run_test():
        config = ServiceScanConfig(timeout=0.5, lookup_type=ServiceScanStrategy.LAZY)

        # Use a high port that should be closed
        result = await _multi_probe_generic("127.0.0.1", 54326, config)
        # Now returns ProbeResult with statistics
        assert result.response is None
        assert result.probes_sent > 0
        assert result.probes_received == 0

    asyncio.run(run_test())


@pytest.mark.integration
def test_service_scan_integration():
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
        assert isinstance(result, ServiceScanResult)
        assert len(result.service) > 0  # Should return something (likely "Unknown")


# Configuration Tests
#####################

def test_service_config_validation():
    """Test ServiceScanConfig validation and edge cases."""
    # Test with minimum values
    min_config = ServiceScanConfig(
        timeout=0.1,
        max_concurrent_probes=1
    )
    result = scan_service("127.0.0.1", 54328, min_config)
    assert isinstance(result, ServiceScanResult)

    # Test with maximum reasonable values
    max_config = ServiceScanConfig(
        timeout=30.0,
        max_concurrent_probes=100
    )
    # Don't actually run this one as it would take too long
    assert max_config.timeout == 30.0
    assert max_config.max_concurrent_probes == 100


def test_probe_payload_types():
    """Test different types of probe payloads."""
    probes = get_port_probes(80, ServiceScanStrategy.BASIC)

    # Should have mix of None, bytes, and string payloads
    has_none = any(p is None for p in probes)
    has_bytes = any(isinstance(p, bytes) for p in probes)

    assert has_none, "Should include None for banner grab"
    assert has_bytes, "Should include bytes payloads"
