"""
Unit tests for ARP command generation and MAC address extraction.

Tests the platform-specific ARP command selection and MAC address parsing
from both traditional 'arp' and modern 'ip neigh' command outputs.
"""
# pylint: disable=protected-access
from unittest.mock import patch

import pytest

from lanscape.core import system_compat
from lanscape.core.device_alive import ArpCacheLookup
from lanscape.core.mac_lookup import MacResolver


@pytest.fixture(autouse=True)
def reset_linux_arp_cache():
    """Reset the Linux ARP command cache before each test."""
    # Reset the run_once cache for get_linux_arp_command
    if hasattr(system_compat.get_linux_arp_command, '_run_once_ran'):
        system_compat.get_linux_arp_command._run_once_ran = False
        system_compat.get_linux_arp_command._run_once_cache = None
    yield
    if hasattr(system_compat.get_linux_arp_command, '_run_once_ran'):
        system_compat.get_linux_arp_command._run_once_ran = False
        system_compat.get_linux_arp_command._run_once_cache = None


class TestArpCacheLookupPlatformCommand:
    """Tests for ArpCacheLookup._get_platform_arp_command"""

    @patch('lanscape.core.system_compat.psutil')
    def test_windows_uses_arp_a(self, mock_psutil):
        """Windows should use 'arp -a' command."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False

        result = ArpCacheLookup._get_platform_arp_command()
        assert result == ['arp', '-a']

    @patch('lanscape.core.system_compat.shutil.which')
    @patch('lanscape.core.system_compat.psutil')
    def test_linux_uses_ip_neigh_when_available(self, mock_psutil, mock_which):
        """Linux should use 'ip neigh show' when ip command is available."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        mock_which.side_effect = lambda cmd: '/usr/sbin/ip' if cmd == 'ip' else None

        result = ArpCacheLookup._get_platform_arp_command()
        assert result == ['ip', 'neigh', 'show']

    @patch('lanscape.core.system_compat.shutil.which')
    @patch('lanscape.core.system_compat.psutil')
    def test_linux_falls_back_to_arp(self, mock_psutil, mock_which):
        """Linux should fall back to 'arp -n' when ip command is not available."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        mock_which.side_effect = lambda cmd: '/usr/sbin/arp' if cmd == 'arp' else None

        result = ArpCacheLookup._get_platform_arp_command()
        assert result == ['arp', '-n']

    @patch('lanscape.core.system_compat.shutil.which')
    @patch('lanscape.core.system_compat.psutil')
    def test_linux_prefers_ip_over_arp(self, mock_psutil, mock_which):
        """Linux should prefer ip command even when both are available."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        # Both commands available
        mock_which.side_effect = lambda cmd: f'/usr/sbin/{cmd}'

        result = ArpCacheLookup._get_platform_arp_command()
        assert result == ['ip', 'neigh', 'show']

    @patch('lanscape.core.system_compat.shutil.which')
    @patch('lanscape.core.system_compat.psutil')
    def test_linux_raises_when_no_arp_command(self, mock_psutil, mock_which):
        """Linux should raise RuntimeError when neither ip nor arp is available."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        mock_which.return_value = None

        with pytest.raises(RuntimeError, match="No suitable ARP command found"):
            ArpCacheLookup._get_platform_arp_command()

    @patch('lanscape.core.system_compat.psutil')
    def test_macos_uses_arp_n(self, mock_psutil):
        """macOS should use 'arp -n' command."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True

        result = ArpCacheLookup._get_platform_arp_command()
        assert result == ['arp', '-n']


class TestArpCacheLookupMacExtraction:
    """Tests for ArpCacheLookup._extract_mac_address"""

    def test_extract_from_arp_output_colon_format(self):
        """Extract MAC from traditional arp output with colon separators."""
        arp_output = "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"
        result = ArpCacheLookup._extract_mac_address(arp_output)
        assert result == ['aa:bb:cc:dd:ee:ff']

    def test_extract_from_arp_output_dash_format(self):
        """Extract MAC from Windows arp output with dash separators."""
        arp_output = "192.168.1.1  00-11-22-33-44-55  dynamic"
        result = ArpCacheLookup._extract_mac_address(arp_output)
        assert result == ['00:11:22:33:44:55']

    def test_extract_from_ip_neigh_output(self):
        """Extract MAC from 'ip neigh show' output."""
        ip_neigh_output = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        result = ArpCacheLookup._extract_mac_address(ip_neigh_output)
        assert result == ['aa:bb:cc:dd:ee:ff']

    def test_extract_multiple_macs(self):
        """Extract multiple MACs from output with multiple entries."""
        output = """
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE
        """
        result = ArpCacheLookup._extract_mac_address(output)
        assert len(result) == 2
        assert 'aa:bb:cc:dd:ee:ff' in result
        assert '11:22:33:44:55:66' in result

    def test_extract_no_mac_found(self):
        """Returns empty list when no MAC address found."""
        result = ArpCacheLookup._extract_mac_address("no mac here")
        assert result == []


class TestMacResolverARP:
    """Tests for MacResolver._get_mac_by_neighbor_cache"""

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command', return_value='arp -a 192.168.1.1')
    def test_windows_uses_arp_a(self, _mock_cmd, mock_check_output):
        """Windows should use 'arp -a' command."""
        mock_check_output.return_value = b"192.168.1.1  00-11-22-33-44-55  dynamic"

        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache("192.168.1.1")

        mock_check_output.assert_called_once()
        call_args = mock_check_output.call_args
        assert "arp -a 192.168.1.1" in call_args[0][0]
        assert '00:11:22:33:44:55' in result

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command',
           return_value='ip neigh show 192.168.1.1')
    def test_linux_uses_ip_neigh_when_available(self, _mock_cmd, mock_check_output):
        """Linux should use 'ip neigh show' when ip command is available."""
        mock_check_output.return_value = b"192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"

        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache("192.168.1.1")

        mock_check_output.assert_called_once()
        call_args = mock_check_output.call_args
        assert "ip neigh show 192.168.1.1" in call_args[0][0]
        assert 'aa:bb:cc:dd:ee:ff' in result

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command', return_value='arp -n 192.168.1.1')
    def test_linux_falls_back_to_arp(self, _mock_cmd, mock_check_output):
        """Linux should fall back to 'arp' when ip command is not available."""
        mock_check_output.return_value = b"192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"

        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache("192.168.1.1")

        mock_check_output.assert_called_once()
        call_args = mock_check_output.call_args
        assert "arp -n 192.168.1.1" in call_args[0][0]
        assert 'aa:bb:cc:dd:ee:ff' in result

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command', return_value='arp 192.168.1.1')
    def test_macos_uses_arp(self, _mock_cmd, mock_check_output):
        """macOS should use 'arp' command."""
        mock_check_output.return_value = b"? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"

        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache("192.168.1.1")

        mock_check_output.assert_called_once()
        call_args = mock_check_output.call_args
        assert "arp 192.168.1.1" in call_args[0][0]
        assert 'aa:bb:cc:dd:ee:ff' in result

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command',
           return_value='ip neigh show 192.168.1.1')
    def test_handles_command_failure(self, _mock_cmd, mock_check_output):
        """Should return empty list and log error on command failure."""
        mock_check_output.side_effect = Exception("Command failed")

        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache("192.168.1.1")

        assert result == []
        assert len(resolver.caught_errors) == 1
