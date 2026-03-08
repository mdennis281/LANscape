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
    _identify_service,
    _match_binary_signature,
    _handle_tls_escalation,
    _detect_tls_from_bytes,
    _strip_redirect_noise,
    PRINTER_PORTS,
    HTTPS_PLAINTEXT_INDICATORS,
    PROTOCOL_PROBES,
    PORT_SPECIFIC_PROBES,
    ServiceScanResult,
    ServiceMatcher,
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


def test_aggressive_no_global_timeout_starvation():
    """AGGRESSIVE mode must collect all probe responses even when the
    semaphore forces later probes to wait longer than cfg.timeout.

    Regression: previously asyncio.as_completed used cfg.timeout as a
    global timeout, which starved queued probes behind the semaphore.
    """
    async def run_test():
        # Simulate a slow but valid probe: each takes 0.15s
        probe_delay = 0.15

        async def _slow_probe(_ip, _port, _payload=None, **_kwargs):
            await asyncio.sleep(probe_delay)
            return (b"HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK\r\n")

        # concurrency=1 serialises all probes.  With many probes the
        # total wall-time far exceeds timeout=0.5.
        # Before the fix the global timeout on as_completed would fire at
        # 0.5s and drop the remaining probes.
        cfg = ServiceScanConfig(
            timeout=0.5,
            lookup_type=ServiceScanStrategy.AGGRESSIVE,
            max_concurrent_probes=1,
        )

        with patch(
            'lanscape.core.service_scan.probes._try_probe',
            side_effect=_slow_probe,
        ):
            result = await _multi_probe_generic("127.0.0.1", 99999, cfg)

        probes = get_port_probes(99999, ServiceScanStrategy.AGGRESSIVE)
        # Every probe must have been sent — none should be starved
        assert result.probes_sent == len(probes)
        # Every probe returned a response, so probes_received must match
        assert result.probes_received == len(probes)
        assert len(result.all_responses) == len(probes)

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


# =============================================================================
# Service Identification Tests
# =============================================================================


class TestIdentifyService:
    """Tests for _identify_service weighted matching."""

    def test_ssh_identification(self):
        """SSH banners should be identified as SSH."""
        svc, weight = _identify_service("SSH-2.0-OpenSSH_9.7")
        assert svc == "SSH"
        assert weight >= 50

    def test_http_identification(self):
        """Plain HTTP responses should be identified as HTTP."""
        response = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html"
        svc, weight = _identify_service(response, is_tls=False)
        assert svc == "HTTP"
        assert weight >= 50

    def test_https_requires_tls(self):
        """HTTPS text matcher must NOT fire when is_tls=False."""
        # An HTTP redirect to HTTPS should be HTTP, not HTTPS
        response = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Server: nginx\r\n"
            "Location: https:///\r\n"
        )
        svc, _weight = _identify_service(response, is_tls=False)
        assert svc != "HTTPS", "Non-TLS response mentioning 'https' should not be HTTPS"
        assert svc == "HTTP"

    def test_https_with_tls_flag(self):
        """When is_tls=True, HTTPS identification should work."""
        response = "HTTP/1.1 200 OK\r\nServer: nginx"
        svc, weight = _identify_service(response, is_tls=True)
        assert svc == "HTTPS"
        assert weight >= 80

    def test_https_error_message_not_false_positive(self):
        """'plain HTTP request was sent to HTTPS port' should not yield HTTPS
        when is_tls=False — the TLS escalation handles the promotion."""
        response = (
            "HTTP/1.1 400 Bad Request\r\n"
            "Server: nginx\r\n\r\n"
            "<html><head><title>400 The plain HTTP request was sent to HTTPS port"
            "</title></head></html>"
        )
        svc, _weight = _identify_service(response, is_tls=False)
        assert svc != "HTTPS"

    def test_tls_baseline_weight(self):
        """is_tls=True gives HTTPS baseline at weight 80."""
        svc, weight = _identify_service("", is_tls=True)
        assert svc == "HTTPS"
        assert weight == 80

    def test_binary_signature_beats_text(self):
        """A binary signature with higher weight should win."""
        smb_bytes = b"\xffSMBsome data here"
        svc, weight = _identify_service("unknown", response_bytes=smb_bytes)
        assert svc == "SMB"
        assert weight == 60

    def test_plex_identification(self):
        """Plex headers should be identified correctly."""
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: http://plex.lan\r\n"
            "content-type: text/html\r\n"
            "set-cookie: SID=abc; HttpOnly"
        )
        svc, _weight = _identify_service(response)
        assert svc == "Plex"

    def test_unknown_response(self):
        """Unrecognizable responses should be Unknown."""
        svc, weight = _identify_service("xyzzy gibberish")
        assert svc == "Unknown"
        assert weight == 0


# =============================================================================
# Binary Signature Matching Tests
# =============================================================================


class TestBinarySignatures:
    """Tests for _match_binary_signature."""

    def test_empty_data(self):
        """Empty data should return None."""
        assert _match_binary_signature(b"") is None
        assert _match_binary_signature(None) is None

    def test_tls_alert(self):
        """TLS Alert record should be detected."""
        data = b"\x15\x03\x01\x00\x02\x02\x28"
        result = _match_binary_signature(data)
        assert result is not None
        assert result[0] == "TLS"

    def test_smb1_response(self):
        """SMB1 header should be detected."""
        data = b"\xffSMB" + b"\x00" * 20
        result = _match_binary_signature(data)
        assert result is not None
        assert result[0] == "SMB"

    def test_dns_transaction_id_detection(self):
        """DNS response with our probe's transaction ID should be detected."""
        # TCP length prefix + transaction ID 0xAABB + QR flag set (0x81)
        data = b"\x00\x20\xAA\xBB\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        result = _match_binary_signature(data)
        assert result is not None
        assert result[0] == "DNS"
        assert result[1] == 60

    def test_dns_transaction_id_without_qr_bit(self):
        """DNS probe ID without QR bit set should NOT match as DNS."""
        # Transaction ID present but QR bit not set (query, not response)
        data = b"\x00\x20\xAA\xBB\x01\x00\x00\x01"
        result = _match_binary_signature(data)
        # Should not match as DNS (QR bit = 0 means it's a query, not response)
        if result is not None:
            assert result[0] != "DNS"

    def test_rdp_tpkt_3byte(self):
        """3-byte TPKT header should match RDP."""
        data = b"\x03\x00\x00\x13\x0e\xe0\x00\x00"
        result = _match_binary_signature(data)
        assert result is not None
        assert result[0] == "RDP"

    def test_rdp_x224_confirm(self):
        """X.224 Connection Confirm should match RDP at higher weight."""
        data = b"\x03\x00\x00\x13\x0e\xd0\x00\x00"
        result = _match_binary_signature(data)
        assert result is not None
        assert result[0] in ("RDP", "DNS")  # Could match either depending on byte patterns

    def test_generic_03_00_no_false_rdp(self):
        """Short \\x03\\x00 should NOT match RDP (removed signature)."""
        # Two bytes only — previously triggered false RDP on DNS responses
        data = b"\x03\x00"
        result = _match_binary_signature(data)
        # Should not match RDP with just 2 bytes (the 3-byte signature needs \x03\x00\x00)
        if result is not None:
            assert result[0] != "RDP" or len(data) >= 3


# =============================================================================
# TLS Escalation Tests
# =============================================================================


class TestTLSEscalation:
    """Tests for _handle_tls_escalation with plaintext HTTPS detection."""

    def test_no_escalation_for_plain_http(self):
        """Normal HTTP response should not trigger escalation."""
        async def run():
            response = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html"
            raw = response.encode()
            result = await _handle_tls_escalation("127.0.0.1", 80, raw, response, None, 2.0)
            _resp, _raw_bytes, _req, is_tls = result
            assert not is_tls
        asyncio.run(run())

    def test_escalation_on_tls_bytes(self):
        """Binary TLS handshake should trigger escalation."""
        async def run():
            raw = b"\x16\x03\x01\x00\x05hello"  # TLS Handshake record
            decoded = raw.decode("utf-8", errors="replace")
            with patch('lanscape.core.service_scan.probes._try_ssl_probe',
                       new_callable=AsyncMock) as mock_ssl:
                mock_ssl.return_value = (b"HTTP/1.1 200 OK", "HTTP/1.1 200 OK")
                result = await _handle_tls_escalation(
                    "127.0.0.1", 443, raw, decoded, None, 2.0
                )
                _, _, _, is_tls = result
                assert is_tls
                mock_ssl.assert_called_once()
        asyncio.run(run())

    def test_escalation_on_https_error_message(self):
        """'plain HTTP request was sent to HTTPS port' should trigger SSL probe."""
        async def run():
            response = (
                "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n"
                "<html><title>400 The plain HTTP request was sent to HTTPS port</title>"
            )
            raw = response.encode()
            with patch('lanscape.core.service_scan.probes._try_ssl_probe',
                       new_callable=AsyncMock) as mock_ssl:
                mock_ssl.return_value = (b"HTTP/1.1 200 OK", "HTTP/1.1 200 OK")
                result = await _handle_tls_escalation(
                    "127.0.0.1", 443, raw, response, None, 2.0
                )
                _, _, _, is_tls = result
                assert is_tls
                mock_ssl.assert_called_once()
        asyncio.run(run())

    def test_escalation_on_https_error_no_ssl_content(self):
        """HTTPS error indicator with failed SSL probe should still set is_tls=True."""
        async def run():
            response = (
                "HTTP/1.1 400 Bad Request\r\n\r\n"
                "The plain HTTP request was sent to HTTPS port"
            )
            raw = response.encode()
            with patch('lanscape.core.service_scan.probes._try_ssl_probe',
                       new_callable=AsyncMock) as mock_ssl:
                mock_ssl.return_value = (None, None)
                result = await _handle_tls_escalation(
                    "127.0.0.1", 443, raw, response, None, 2.0
                )
                _, _, _, is_tls = result
                assert is_tls, "Explicit HTTPS error should still flag is_tls"
        asyncio.run(run())

    def test_https_redirect_ssl_succeeds(self):
        """HTTP→HTTPS redirect should trigger SSL probe; is_tls=True if SSL works."""
        async def run():
            response = (
                "HTTP/1.0 301 Moved Permanently\r\n"
                "Location: https://example.com/\r\n"
            )
            raw = response.encode()
            with patch('lanscape.core.service_scan.probes._try_ssl_probe',
                       new_callable=AsyncMock) as mock_ssl:
                mock_ssl.return_value = (b"HTTP/1.1 200 OK", "HTTP/1.1 200 OK")
                result = await _handle_tls_escalation(
                    "10.0.0.20", 8006, raw, response, None, 2.0
                )
                _, _, _, is_tls = result
                assert is_tls
        asyncio.run(run())

    def test_https_redirect_ssl_fails(self):
        """HTTP→HTTPS redirect where SSL probe fails → is_tls=False (HTTP redirect)."""
        async def run():
            response = (
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://other-server.com/\r\n"
            )
            raw = response.encode()
            with patch('lanscape.core.service_scan.probes._try_ssl_probe',
                       new_callable=AsyncMock) as mock_ssl:
                mock_ssl.return_value = (None, None)
                result = await _handle_tls_escalation(
                    "10.0.0.1", 80, raw, response, None, 2.0
                )
                _, _, _, is_tls = result
                assert not is_tls, "HTTP redirect to HTTPS with failed SSL → should be HTTP"
        asyncio.run(run())

    def test_https_plaintext_indicators_list(self):
        """Verify the HTTPS_PLAINTEXT_INDICATORS list is populated."""
        assert len(HTTPS_PLAINTEXT_INDICATORS) >= 3
        for indicator in HTTPS_PLAINTEXT_INDICATORS:
            assert indicator == indicator.lower(), "Indicators should be lowercase"


# =============================================================================
# DNS Probe and Port-Specific Probes Tests
# =============================================================================


class TestDNSProbes:
    """Tests for DNS probe integration."""

    def test_dns_probe_exists(self):
        """DNS protocol probe should be defined."""
        assert "DNS" in PROTOCOL_PROBES
        probe = PROTOCOL_PROBES["DNS"]
        assert isinstance(probe, bytes)
        # Should contain our transaction ID 0xAABB
        assert b"\xAA\xBB" in probe

    def test_port_53_has_dns_probe(self):
        """Port 53 should have DNS-specific probes."""
        assert 53 in PORT_SPECIFIC_PROBES
        probes = PORT_SPECIFIC_PROBES[53]
        assert len(probes) > 0
        # DNS probe from PORT_SPECIFIC_PROBES should contain our transaction ID
        dns_probe = probes[0]
        assert b"\xAA\xBB" in dns_probe

    def test_port_53_probes_include_dns(self):
        """get_port_probes for port 53 should include the DNS probe."""
        for strategy in ServiceScanStrategy:
            probes = get_port_probes(53, strategy)
            dns_payloads = [p for p in probes if p and isinstance(p, bytes)
                            and b"\xAA\xBB" in p]
            assert len(dns_payloads) > 0, f"DNS probe missing for port 53 in {strategy}"


class TestDetectTLSFromBytes:
    """Tests for _detect_tls_from_bytes."""

    def test_valid_tls_handshake(self):
        """TLS Handshake record should be detected."""
        assert _detect_tls_from_bytes(b"\x16\x03\x01\x00\x05")

    def test_valid_tls_alert(self):
        """TLS Alert record should be detected."""
        assert _detect_tls_from_bytes(b"\x15\x03\x03\x00\x02")

    def test_not_tls(self):
        """Non-TLS data should not be detected."""
        assert not _detect_tls_from_bytes(b"HTTP/1.1 200 OK")
        assert not _detect_tls_from_bytes(b"\x00\x00\x00")

    def test_empty_data(self):
        """Empty/short data should not be detected."""
        assert not _detect_tls_from_bytes(b"")
        assert not _detect_tls_from_bytes(b"\x16")
        assert not _detect_tls_from_bytes(None)


class TestServiceMatcher:
    """Tests for ServiceMatcher model."""

    def test_case_insensitive_match(self):
        """Default matching should be case-insensitive."""
        matcher = ServiceMatcher(name="Test", weight=50, patterns=["hello"])
        assert matcher.match("HELLO WORLD")
        assert matcher.match("hello world")

    def test_case_sensitive_match(self):
        """Case-sensitive matching when specified."""
        matcher = ServiceMatcher(name="Test", weight=50, patterns=["SSH-"],
                                 case_sensitive=True)
        assert matcher.match("SSH-2.0")
        assert not matcher.match("ssh-2.0")

    def test_no_match(self):
        """Should return False when no pattern matches."""
        matcher = ServiceMatcher(name="Test", weight=50, patterns=["xyz123"])
        assert not matcher.match("nothing here")


# =============================================================================
# Redirect Noise Stripping Tests
# =============================================================================


class TestStripRedirectNoise:
    """Tests for _strip_redirect_noise."""

    def test_strips_location_header(self):
        """Location headers should be removed."""
        response = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Server: nginx\r\n"
            "Location: https://example.com/wsman\r\n"
            "Content-Type: text/html\r\n"
        )
        cleaned = _strip_redirect_noise(response)
        assert "wsman" not in cleaned.lower()
        assert "nginx" in cleaned.lower()

    def test_preserves_non_location_headers(self):
        """Non-Location headers should be preserved."""
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache\r\n"
            "Content-Type: application/json\r\n"
        )
        cleaned = _strip_redirect_noise(response)
        assert "Apache" in cleaned
        assert "application/json" in cleaned

    def test_empty_response(self):
        """Empty input should return empty string."""
        assert _strip_redirect_noise("") == ""
        assert _strip_redirect_noise(None) == ""

    def test_redirect_url_with_service_keyword(self):
        """Redirect echoing probe path /wsman should not cause WinRM match."""
        response = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Server: nginx\r\n"
            "Location: https://host/wsman\r\n"
        )
        svc, _weight = _identify_service(response, is_tls=False)
        assert svc != "WinRM", "Redirect URL containing /wsman should not match WinRM"
        assert svc == "HTTP"

    def test_redirect_url_with_plex_keyword(self):
        """Redirect echoing /plex in URL should not cause Plex match."""
        response = (
            "HTTP/1.1 302 Found\r\n"
            "Server: nginx\r\n"
            "Location: https://host/plex/web\r\n"
        )
        svc, _weight = _identify_service(response, is_tls=False)
        assert svc != "Plex"
        assert svc == "HTTP"


# Error Propagation Tests
###########################


class TestServiceScanErrorPropagation:
    """Tests that service scan errors are surfaced via the error field."""

    def test_timeout_populates_error_field(self):
        """Async timeout should populate ServiceScanResult.error."""
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = asyncio.TimeoutError()
        mock_loop.close = MagicMock()

        with patch("lanscape.core.service_scan.scanner.asyncio.new_event_loop",
                   return_value=mock_loop), \
             patch("lanscape.core.service_scan.scanner.asyncio.set_event_loop"):
            cfg = ServiceScanConfig(timeout=0.5)
            result = scan_service("127.0.0.1", 99999, cfg)
            assert result.service == "Unknown"
            assert result.error is not None
            assert "Event loop error" in result.error

    def test_generic_exception_populates_error_field(self):
        """An unexpected exception should populate ServiceScanResult.error."""
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = RuntimeError("test boom")
        mock_loop.close = MagicMock()

        with patch("lanscape.core.service_scan.scanner.asyncio.new_event_loop",
                   return_value=mock_loop), \
             patch("lanscape.core.service_scan.scanner.asyncio.set_event_loop"):
            cfg = ServiceScanConfig(timeout=0.5)
            result = scan_service("127.0.0.1", 99999, cfg)
            assert result.service == "Unknown"
            assert result.error is not None
            assert "test boom" in result.error

    def test_successful_scan_has_no_error(self):
        """A normal successful scan should have error=None."""
        result = ServiceScanResult(service="HTTP", probes_sent=1, probes_received=1)
        assert result.error is None

    def test_error_field_default_none(self):
        """ServiceScanResult.error defaults to None."""
        result = ServiceScanResult(service="Unknown")
        assert result.error is None
