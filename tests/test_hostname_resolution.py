"""
Unit tests for hostname resolution in Device._get_hostname().

Tests cover:
- Standard reverse DNS lookup
- mDNS fallback via avahi-resolve-address
- NetBIOS fallback via nmblookup
- Platform-specific behavior (Windows skips fallbacks)
- Graceful handling when tools are not installed
"""
# pylint: disable=protected-access,unused-argument

from unittest.mock import patch, MagicMock
import subprocess
import socket

import pytest

from lanscape.core.net_tools import Device


class TestGetHostname:
    """Tests for Device._get_hostname()."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="192.168.1.100", alive=True)

    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    def test_reverse_dns_success(self, mock_dns, device):
        """Reverse DNS succeeds — should return hostname immediately."""
        mock_dns.return_value = ('myrouter.local', [], ['192.168.1.100'])

        result = device._get_hostname()

        assert result == 'myrouter.local'
        mock_dns.assert_called_once_with('192.168.1.100')

    @patch('lanscape.core.net_tools.platform.system', return_value='Windows')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    def test_windows_no_fallbacks(self, mock_dns, mock_platform, device):
        """On Windows, if DNS fails, should return None without trying fallbacks."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result is None

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    @patch('subprocess.run')
    def test_mdns_fallback_success(self, mock_run, mock_dns, mock_platform, device):
        """mDNS fallback resolves hostname when DNS fails on Linux."""
        mock_dns.side_effect = socket.herror('Host not found')
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.168.1.100\tlivingroom-pi.local\n'
        )

        result = device._get_hostname()

        assert result == 'livingroom-pi.local'

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    @patch('subprocess.run')
    def test_mdns_strips_trailing_dot(self, mock_run, mock_dns, mock_platform, device):
        """mDNS result with trailing dot is stripped."""
        mock_dns.side_effect = socket.herror('Host not found')
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.168.1.100\tdevice.local.\n'
        )

        result = device._get_hostname()

        assert result == 'device.local'

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    def test_netbios_fallback_success(self, mock_dns, mock_platform, device):
        """NetBIOS fallback resolves hostname when DNS and mDNS fail."""
        mock_dns.side_effect = socket.herror('Host not found')

        # avahi not found, nmblookup succeeds
        def mock_subprocess_run(cmd, **_kwargs):
            if cmd[0] == 'avahi-resolve-address':
                raise FileNotFoundError()
            if cmd[0] == 'nmblookup':
                return MagicMock(
                    returncode=0,
                    stdout=(
                        'Looking up status of 192.168.1.100\n'
                        '\tDESKTOP-ABC  <00> -         B <UNIQUE>\n'
                        '\tWORKGROUP    <00> - <GROUP>  B <ACTIVE>\n'
                    )
                )
            return MagicMock(returncode=1, stdout='')

        with patch('subprocess.run', side_effect=mock_subprocess_run):
            result = device._get_hostname()

        assert result == 'DESKTOP-ABC'

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    def test_all_methods_fail(self, mock_dns, mock_platform, device):
        """All resolution methods fail — should return None."""
        mock_dns.side_effect = socket.herror('Host not found')

        def mock_subprocess_run(cmd, **_kwargs):
            raise FileNotFoundError()

        with patch('subprocess.run', side_effect=mock_subprocess_run):
            result = device._get_hostname()

        assert result is None

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    def test_mdns_timeout(self, mock_dns, mock_platform, device):
        """mDNS times out — should fall through to NetBIOS."""
        mock_dns.side_effect = socket.herror('Host not found')

        def mock_subprocess_run(cmd, **_kwargs):
            if cmd[0] == 'avahi-resolve-address':
                raise subprocess.TimeoutExpired(cmd, 3)
            raise FileNotFoundError()

        with patch('subprocess.run', side_effect=mock_subprocess_run):
            result = device._get_hostname()

        assert result is None

    @patch('lanscape.core.net_tools.platform.system', return_value='Linux')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    @patch('subprocess.run')
    def test_mdns_empty_output(self, mock_run, mock_dns, mock_platform, device):
        """mDNS returns empty output — should fall through."""
        mock_dns.side_effect = socket.herror('Host not found')
        mock_run.return_value = MagicMock(returncode=1, stdout='')

        # Both fallbacks fail
        result = device._get_hostname()

        assert result is None

    @patch('lanscape.core.net_tools.platform.system', return_value='Darwin')
    @patch('lanscape.core.net_tools.socket.gethostbyaddr')
    @patch('subprocess.run')
    def test_macos_tries_fallbacks(self, mock_run, mock_dns, mock_platform, device):
        """macOS should also attempt mDNS/NetBIOS fallbacks."""
        mock_dns.side_effect = socket.herror('Host not found')
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.168.1.100\tmacbook.local\n'
        )

        result = device._get_hostname()

        assert result == 'macbook.local'


class TestResolveMdns:
    """Tests for Device._resolve_mdns() directly."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="10.0.0.5", alive=True)

    @patch('subprocess.run')
    def test_avahi_not_installed(self, mock_run, device):
        """Gracefully handles avahi-resolve not being installed."""
        mock_run.side_effect = FileNotFoundError()

        assert device._resolve_mdns() is None

    @patch('subprocess.run')
    def test_avahi_nonzero_exit(self, mock_run, device):
        """Handles avahi-resolve returning an error."""
        mock_run.return_value = MagicMock(returncode=2, stdout='')

        assert device._resolve_mdns() is None


class TestResolveNetbios:
    """Tests for Device._resolve_netbios() directly."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="10.0.0.5", alive=True)

    @patch('subprocess.run')
    def test_nmblookup_not_installed(self, mock_run, device):
        """Gracefully handles nmblookup not being installed."""
        mock_run.side_effect = FileNotFoundError()

        assert device._resolve_netbios() is None

    @patch('subprocess.run')
    def test_nmblookup_no_unique_entry(self, mock_run, device):
        """Handles nmblookup output without a UNIQUE <00> entry."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='Looking up status of 10.0.0.5\n\tNo reply\n'
        )

        assert device._resolve_netbios() is None

    @patch('subprocess.run')
    def test_nmblookup_wildcard_name(self, mock_run, device):
        """Ignores wildcard (*) NetBIOS names."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='\t*               <00> -         B <UNIQUE>\n'
        )

        assert device._resolve_netbios() is None
