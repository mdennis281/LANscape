"""
Unit tests for cross-protocol IP address resolution (alt_ip_resolver).

Covers:
- EUI-64 link-local derivation from MAC addresses
- Neighbor-cache correlation (IPv4->IPv6 and IPv6->IPv4)
- DNS-based alternate IP lookup
- Deduplication and exclusion logic
- Top-level resolve_alt_ips orchestration
- Graceful fallback on errors
- System-compat helpers: neighbor dump commands, NDP ping, interface scopes
"""
# pylint: disable=protected-access,import-outside-toplevel,unused-argument

import ipaddress
import socket
from unittest.mock import patch

from lanscape.core.alt_ip_resolver import (
    resolve_alt_ips,
    _eui64_link_local,
    _alt_ips_from_dns,
    _deduplicate,
    _prime_ndp_cache,
)
from lanscape.core.system_compat import (
    extract_ips_for_mac,
    get_neighbor_dump_command,
    get_ipv6_interface_scopes,
    get_ndp_ping_command,
)


# ===========================================================================
# EUI-64 link-local derivation
# ===========================================================================


class TestEui64LinkLocal:
    """Tests for _eui64_link_local()."""

    def test_standard_mac(self):
        """Derive EUI-64 link-local from a well-known MAC."""
        # MAC aa:bb:cc:dd:ee:ff
        # Flip bit: aa -> a8
        # Insert ff:fe -> a8:bb:cc:ff:fe:dd:ee:ff
        # Groups: a8bb:ccff:fedd:eeff
        result = _eui64_link_local('aa:bb:cc:dd:ee:ff')
        assert result is not None
        assert result.startswith('fe80::')
        assert 'ff:fe' in result or 'fedd' in result.lower()

    def test_zeros_mac(self):
        """Derive EUI-64 from all-zeros unicast MAC."""
        result = _eui64_link_local('00:00:00:00:00:00')
        assert result is not None
        assert result.startswith('fe80::')

    def test_known_derivation(self):
        """Verify against a known EUI-64 calculation.

        MAC: 02:42:ac:11:00:02
        Flip universal/local bit: 02 ^ 02 = 00
        Insert ff:fe: 00:42:ac:ff:fe:11:00:02
        Groups: 0042:acff:fe11:0002
        Expected: fe80::42:acff:fe11:2
        """
        result = _eui64_link_local('02:42:ac:11:00:02')
        assert result is not None
        assert ipaddress.ip_address(result) == ipaddress.ip_address(
            'fe80::42:acff:fe11:2'
        )

    def test_multicast_mac_returns_none(self):
        """Multicast MACs (bit 0 of first octet set) should return None."""
        result = _eui64_link_local('01:00:5e:00:00:01')
        assert result is None

    def test_broadcast_mac_returns_none(self):
        """Broadcast MAC ff:ff:ff:ff:ff:ff should return None."""
        result = _eui64_link_local('ff:ff:ff:ff:ff:ff')
        assert result is None

    def test_dash_separator(self):
        """MACs with dash separators should be handled."""
        result = _eui64_link_local('AA-BB-CC-DD-EE-FF')
        assert result is not None
        assert result.startswith('fe80::')

    def test_invalid_mac_returns_none(self):
        """Invalid MAC string returns None."""
        assert _eui64_link_local('not-a-mac') is None
        assert _eui64_link_local('') is None
        assert _eui64_link_local('aa:bb:cc') is None

    def test_uppercase_mac(self):
        """Uppercase MACs should work identically."""
        lower = _eui64_link_local('aa:bb:cc:dd:ee:ff')
        upper = _eui64_link_local('AA:BB:CC:DD:EE:FF')
        assert lower == upper


# ===========================================================================
# Neighbor-cache IP extraction
# ===========================================================================


class TestExtractIpsForMac:
    """Tests for extract_ips_for_mac() (system_compat)."""

    def test_linux_ip_neigh_v6(self):
        """Parse Linux 'ip -6 neigh show' output for IPv6."""
        output = (
            "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "2001:db8::100 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
            "fe80::2 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
        )
        result = extract_ips_for_mac(output, 'aa:bb:cc:dd:ee:ff', want_v6=True)
        assert 'fe80::1' in result
        assert '2001:db8::100' in result
        assert 'fe80::2' not in result  # different MAC

    def test_linux_ip_neigh_v4(self):
        """Parse Linux 'ip -4 neigh show' output for IPv4."""
        output = (
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
            "192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 DELAY\n"
        )
        result = extract_ips_for_mac(output, 'aa:bb:cc:dd:ee:ff', want_v6=False)
        assert '192.168.1.1' in result
        assert '10.0.0.5' in result
        assert '192.168.1.2' not in result

    def test_windows_arp_output(self):
        """Parse Windows 'arp -a' output with dash separators."""
        output = (
            "  192.168.1.1         aa-bb-cc-dd-ee-ff     dynamic\n"
            "  192.168.1.100       11-22-33-44-55-66     dynamic\n"
        )
        result = extract_ips_for_mac(output, 'aa:bb:cc:dd:ee:ff', want_v6=False)
        assert '192.168.1.1' in result
        assert '192.168.1.100' not in result

    def test_no_matching_mac(self):
        """Output with no matching MAC returns empty."""
        output = "10.0.0.1 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
        result = extract_ips_for_mac(output, 'aa:bb:cc:dd:ee:ff', want_v6=False)
        assert not result

    def test_loopback_excluded(self):
        """Loopback addresses should be excluded."""
        output = "127.0.0.1 dev lo lladdr aa:bb:cc:dd:ee:ff PERMANENT\n"
        result = extract_ips_for_mac(output, 'aa:bb:cc:dd:ee:ff', want_v6=False)
        assert not result

    def test_empty_output(self):
        """Empty output returns empty list."""
        assert not extract_ips_for_mac('', 'aa:bb:cc:dd:ee:ff', want_v6=True)


# ===========================================================================
# Neighbor dump command generation
# ===========================================================================


class TestNeighborDumpCommand:
    """Tests for get_neighbor_dump_command() (system_compat)."""

    @patch('lanscape.core.system_compat.psutil')
    def test_windows_v6(self, mock_psutil):
        """Windows IPv6 dump uses netsh."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmd = get_neighbor_dump_command(want_v6=True)
        assert 'netsh' in cmd
        assert 'ipv6' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_linux_v6(self, mock_psutil):
        """Linux IPv6 dump uses ip -6 neigh show."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        cmd = get_neighbor_dump_command(want_v6=True)
        assert cmd == 'ip -6 neigh show'

    @patch('lanscape.core.system_compat.psutil')
    def test_linux_v4(self, mock_psutil):
        """Linux IPv4 dump uses ip -4 neigh show."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        cmd = get_neighbor_dump_command(want_v6=False)
        assert cmd == 'ip -4 neigh show'

    @patch('lanscape.core.system_compat.psutil')
    def test_macos_v6(self, mock_psutil):
        """macOS IPv6 dump uses ndp."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True
        cmd = get_neighbor_dump_command(want_v6=True)
        assert 'ndp' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_macos_v4(self, mock_psutil):
        """macOS IPv4 dump uses arp."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True
        cmd = get_neighbor_dump_command(want_v6=False)
        assert 'arp' in cmd


# ===========================================================================
# NDP cache priming
# ===========================================================================


class TestNdpCachePriming:
    """Tests for _prime_ndp_cache and related helpers."""

    def setup_method(self):
        """Reset the global priming flag before each test."""
        import lanscape.core.alt_ip_resolver as mod
        mod._ndp_primed = False

    @patch('lanscape.core.system_compat.psutil')
    def test_get_scopes_windows(self, mock_psutil):
        """Windows scopes are parsed from netsh interface indices."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False

        netsh_output = (
            "Idx     Met  MTU  State        Name\n"
            "---  ------  ---  ----------  -----\n"
            "  1      75  999  connected   Loopback Pseudo-Interface 1\n"
            " 10      25  1500  connected   Ethernet\n"
            "  8      25  1500  disconnected  Wi-Fi\n"
        )
        with patch('lanscape.core.system_compat.subprocess.check_output',
                   return_value=netsh_output.encode()):
            scopes = get_ipv6_interface_scopes()
        # Loopback excluded, disconnected excluded
        assert '10' in scopes
        assert '1' not in scopes
        assert '8' not in scopes

    @patch('lanscape.core.system_compat.psutil')
    def test_get_scopes_linux(self, mock_psutil):
        """Linux scopes are interface names with IPv6 and up status."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False

        mock_psutil.net_if_addrs.return_value = {
            'eth0': [type('A', (), {'family': socket.AF_INET6,
                                    'address': 'fe80::1'})()],
            'lo': [type('A', (), {'family': socket.AF_INET6,
                                  'address': '::1'})()],
        }
        mock_psutil.net_if_stats.return_value = {
            'eth0': type('S', (), {'isup': True})(),
            'lo': type('S', (), {'isup': True})(),
        }

        scopes = get_ipv6_interface_scopes()
        assert 'eth0' in scopes
        assert 'lo' not in scopes  # ::1 loopback excluded

    @patch('lanscape.core.system_compat.psutil')
    def test_ndp_ping_command_windows(self, mock_psutil):
        """Windows NDP ping uses ping -6."""
        mock_psutil.WINDOWS = True
        mock_psutil.MACOS = False
        cmd = get_ndp_ping_command('ff02::1%10')
        assert 'ping -6' in cmd
        assert 'ff02::1%10' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_ndp_ping_command_linux(self, mock_psutil):
        """Linux NDP ping uses ping -6."""
        mock_psutil.WINDOWS = False
        mock_psutil.MACOS = False
        cmd = get_ndp_ping_command('ff02::1%eth0')
        assert 'ping -6' in cmd
        assert 'ff02::1%eth0' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_ndp_ping_command_macos(self, mock_psutil):
        """macOS NDP ping uses ping6."""
        mock_psutil.WINDOWS = False
        mock_psutil.MACOS = True
        cmd = get_ndp_ping_command('ff02::1%en0')
        assert 'ping6' in cmd

    @patch('lanscape.core.alt_ip_resolver.subprocess.run')
    @patch('lanscape.core.alt_ip_resolver.get_ipv6_interface_scopes',
           return_value=['10', '20'])
    @patch('lanscape.core.alt_ip_resolver.time.sleep')
    def test_prime_ndp_cache_pings_all_scopes(self, mock_sleep, mock_scopes, mock_run):
        """Priming should ping ff02::1 on every discovered scope."""
        _prime_ndp_cache()
        assert mock_run.call_count == 2
        mock_sleep.assert_called_once()

    @patch('lanscape.core.alt_ip_resolver.subprocess.run')
    @patch('lanscape.core.alt_ip_resolver.get_ipv6_interface_scopes',
           return_value=['10'])
    @patch('lanscape.core.alt_ip_resolver.time.sleep')
    def test_prime_ndp_cache_runs_once(self, mock_sleep, mock_scopes, mock_run):
        """Priming should only run once (idempotent)."""
        _prime_ndp_cache()
        _prime_ndp_cache()
        _prime_ndp_cache()
        assert mock_run.call_count == 1

    @patch('lanscape.core.alt_ip_resolver.get_ipv6_interface_scopes',
           return_value=[])
    def test_prime_no_interfaces(self, mock_scopes):
        """No interfaces should not raise an error."""
        _prime_ndp_cache()  # Should complete without error

    @patch('lanscape.core.alt_ip_resolver._prime_ndp_cache')
    @patch('lanscape.core.alt_ip_resolver.subprocess.check_output',
           return_value=b'fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n')
    @patch('lanscape.core.alt_ip_resolver.get_neighbor_dump_command',
           return_value='ip -6 neigh show')
    def test_neighbor_cache_primes_for_v6(self, mock_cmd, mock_check, mock_prime):
        """Looking for IPv6 entries should trigger NDP priming."""
        from lanscape.core.alt_ip_resolver import _alt_ips_from_neighbor_cache
        _alt_ips_from_neighbor_cache('aa:bb:cc:dd:ee:ff', scanning_v6=False)
        mock_prime.assert_called_once()

    @patch('lanscape.core.alt_ip_resolver._prime_ndp_cache')
    @patch('lanscape.core.alt_ip_resolver.subprocess.check_output',
           return_value=b'192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n')
    @patch('lanscape.core.alt_ip_resolver.get_neighbor_dump_command',
           return_value='ip -4 neigh show')
    def test_neighbor_cache_skips_prime_for_v4(self, mock_cmd, mock_check, mock_prime):
        """Looking for IPv4 entries should NOT trigger NDP priming."""
        from lanscape.core.alt_ip_resolver import _alt_ips_from_neighbor_cache
        _alt_ips_from_neighbor_cache('aa:bb:cc:dd:ee:ff', scanning_v6=True)
        mock_prime.assert_not_called()


# ===========================================================================
# DNS-based alt-IP lookup
# ===========================================================================


class TestAltIpsFromDns:
    """Tests for _alt_ips_from_dns()."""

    @patch('lanscape.core.alt_ip_resolver.socket.getaddrinfo')
    def test_returns_ipv6_for_hostname(self, mock_getaddrinfo):
        """DNS lookup returns IPv6 addresses for a hostname."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 0, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fe80::1', 0, 0, 0)),
        ]
        result = _alt_ips_from_dns('myhost.local', socket.AF_INET6)
        assert '2001:db8::1' in result
        assert 'fe80::1' in result

    @patch('lanscape.core.alt_ip_resolver.socket.getaddrinfo')
    def test_returns_ipv4_for_hostname(self, mock_getaddrinfo):
        """DNS lookup returns IPv4 addresses for a hostname."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0)),
        ]
        result = _alt_ips_from_dns('myhost.local', socket.AF_INET)
        assert '192.168.1.1' in result

    @patch('lanscape.core.alt_ip_resolver.socket.getaddrinfo')
    def test_dns_failure_returns_empty(self, mock_getaddrinfo):
        """DNS failure returns empty list gracefully."""
        mock_getaddrinfo.side_effect = socket.gaierror('Name or service not known')
        result = _alt_ips_from_dns('nonexistent.local', socket.AF_INET6)
        assert not result

    def test_none_hostname_handled(self):
        """None hostname shouldn't be passed, but empty string is safe."""
        result = _alt_ips_from_dns('', socket.AF_INET6)
        assert isinstance(result, list)


# ===========================================================================
# Deduplication
# ===========================================================================


class TestDeduplicate:
    """Tests for _deduplicate()."""

    def test_removes_primary_ip(self):
        """The device's own IP should be excluded."""
        result = _deduplicate(
            ['192.168.1.1', 'fe80::1', '192.168.1.1'],
            exclude='192.168.1.1'
        )
        assert '192.168.1.1' not in result
        assert 'fe80::1' in result

    def test_removes_duplicates(self):
        """Duplicate IPs should be collapsed."""
        result = _deduplicate(
            ['fe80::1', 'fe80::1', '2001:db8::1'],
            exclude='192.168.1.1'
        )
        assert result == ['fe80::1', '2001:db8::1']

    def test_normalises_ipv6(self):
        """Expanded and compressed IPv6 forms are treated as equal."""
        result = _deduplicate(
            ['fe80::1', 'fe80:0000:0000:0000:0000:0000:0000:0001'],
            exclude='10.0.0.1'
        )
        assert len(result) == 1
        assert result[0] == 'fe80::1'

    def test_invalid_ip_skipped(self):
        """Invalid IP strings are silently skipped."""
        result = _deduplicate(
            ['not-an-ip', 'fe80::1'],
            exclude='10.0.0.1'
        )
        assert result == ['fe80::1']

    def test_empty_input(self):
        """Empty list returns empty."""
        assert not _deduplicate([], exclude='10.0.0.1')


# ===========================================================================
# Top-level resolve_alt_ips orchestration
# ===========================================================================


class TestResolveAltIps:
    """Tests for the top-level resolve_alt_ips() function."""

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local',
           return_value='fe80::a8bb:ccff:fedd:eeff')
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache',
           return_value=['2001:db8::100'])
    def test_ipv4_scan_finds_ipv6(self, mock_cache, mock_eui, mock_dns):
        """IPv4 scan should find IPv6 via neighbor cache and EUI-64."""
        result = resolve_alt_ips(
            '192.168.1.1', ['aa:bb:cc:dd:ee:ff'], None
        )
        assert '2001:db8::100' in result
        assert 'fe80::a8bb:ccff:fedd:eeff' in result
        mock_cache.assert_called_once()
        mock_eui.assert_called_once_with('aa:bb:cc:dd:ee:ff')

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns',
           return_value=['192.168.1.50'])
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache',
           return_value=['192.168.1.1'])
    def test_ipv6_scan_finds_ipv4(self, mock_cache, mock_dns):
        """IPv6 scan should find IPv4 via neighbor cache and DNS."""
        result = resolve_alt_ips(
            '2001:db8::1', ['aa:bb:cc:dd:ee:ff'], 'myhost.local'
        )
        assert '192.168.1.1' in result
        assert '192.168.1.50' in result
        # EUI-64 should NOT be called for IPv6 scans
        mock_cache.assert_called_once()

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local', return_value=None)
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_no_alt_ips_found(self, mock_cache, mock_eui, mock_dns):
        """Returns empty list when no alternate IPs are found."""
        result = resolve_alt_ips('192.168.1.1', ['aa:bb:cc:dd:ee:ff'], None)
        assert not result

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local', return_value=None)
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_empty_macs_no_error(self, mock_cache, mock_eui, mock_dns):
        """Empty MAC list should not cause errors."""
        result = resolve_alt_ips('192.168.1.1', [], None)
        assert not result
        mock_cache.assert_not_called()
        mock_eui.assert_not_called()

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local', return_value=None)
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_no_hostname_skips_dns(self, mock_cache, mock_eui, mock_dns):
        """None hostname should skip DNS lookup entirely."""
        resolve_alt_ips('192.168.1.1', ['aa:bb:cc:dd:ee:ff'], None)
        mock_dns.assert_not_called()

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns')
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local', return_value=None)
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_hostname_triggers_dns(self, mock_cache, mock_eui, mock_dns):
        """Hostname should trigger DNS lookup with correct family."""
        mock_dns.return_value = ['fe80::99']
        result = resolve_alt_ips(
            '192.168.1.1', ['aa:bb:cc:dd:ee:ff'], 'myhost.local'
        )
        mock_dns.assert_called_once_with('myhost.local', socket.AF_INET6)
        assert 'fe80::99' in result

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns')
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_ipv6_scan_dns_uses_af_inet(self, mock_cache, mock_dns):
        """IPv6 scan should query DNS with AF_INET for IPv4 addresses."""
        mock_dns.return_value = []
        resolve_alt_ips('fe80::1', ['aa:bb:cc:dd:ee:ff'], 'myhost.local')
        mock_dns.assert_called_once_with('myhost.local', socket.AF_INET)

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local',
           return_value='fe80::a8bb:ccff:fedd:eeff')
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache',
           return_value=['fe80::a8bb:ccff:fedd:eeff'])
    def test_deduplicates_eui64_and_cache(self, mock_cache, mock_eui, mock_dns):
        """EUI-64 result matching cache result should be deduplicated."""
        result = resolve_alt_ips(
            '192.168.1.1', ['aa:bb:cc:dd:ee:ff'], None
        )
        assert result.count('fe80::a8bb:ccff:fedd:eeff') == 1

    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_dns', return_value=[])
    @patch('lanscape.core.alt_ip_resolver._eui64_link_local')
    @patch('lanscape.core.alt_ip_resolver._alt_ips_from_neighbor_cache', return_value=[])
    def test_multiple_macs(self, mock_cache, mock_eui, mock_dns):
        """Multiple MACs should each be checked."""
        mock_eui.side_effect = ['fe80::1', 'fe80::2']
        result = resolve_alt_ips(
            '192.168.1.1', ['aa:bb:cc:00:00:00', 'aa:bb:cc:00:00:02'], None
        )
        assert 'fe80::1' in result
        assert 'fe80::2' in result
        assert mock_cache.call_count == 2


# ===========================================================================
# Device integration
# ===========================================================================


class TestDeviceResolveAltIps:
    """Tests for Device._resolve_alt_ips integration."""

    @patch('lanscape.core.net_tools.device.resolve_alt_ips',
           return_value=['fe80::1', '2001:db8::100'])
    def test_populates_alt_ips(self, mock_resolve):
        """Device._resolve_alt_ips should populate alt_ips and classify IPs."""
        from lanscape.core.net_tools import Device
        device = Device(
            ip='192.168.1.1',
            alive=True,
            macs=['aa:bb:cc:dd:ee:ff'],
            hostname='myhost.local',
        )
        device._resolve_alt_ips()
        assert device.alt_ips == ['fe80::1', '2001:db8::100']
        assert device.ipv4_addresses == ['192.168.1.1']
        assert device.ipv6_addresses == ['fe80::1', '2001:db8::100']
        mock_resolve.assert_called_once_with(
            '192.168.1.1', ['aa:bb:cc:dd:ee:ff'], 'myhost.local'
        )

    @patch('lanscape.core.net_tools.device.resolve_alt_ips',
           side_effect=RuntimeError('unexpected error'))
    def test_error_sets_empty_list(self, mock_resolve):
        """Errors in resolve_alt_ips should be caught, setting alt_ips=[]."""
        from lanscape.core.net_tools import Device
        device = Device(ip='192.168.1.1', alive=True)
        device._resolve_alt_ips()
        assert not device.alt_ips
        # Primary IP still classified even on error
        assert device.ipv4_addresses == ['192.168.1.1']
        assert device.ipv6_addresses == []

    @patch('lanscape.core.net_tools.device.resolve_alt_ips', return_value=['fe80::1'])
    def test_to_result_includes_alt_ips(self, mock_resolve):
        """DeviceResult should include ipv4/ipv6 addresses from Device."""
        from lanscape.core.net_tools import Device
        device = Device(ip='192.168.1.1', alive=True)
        device._resolve_alt_ips()
        result = device.to_result()
        assert result.ipv4_addresses == ['192.168.1.1']
        assert result.ipv6_addresses == ['fe80::1']

    def test_to_result_empty_alt_ips_default(self):
        """DeviceResult should default to empty ipv4/ipv6 address lists."""
        from lanscape.core.net_tools import Device
        device = Device(ip='192.168.1.1')
        result = device.to_result()
        assert not result.ipv4_addresses
        assert not result.ipv6_addresses

    @patch('lanscape.core.net_tools.device.resolve_alt_ips',
           return_value=['10.0.0.5', 'fe80::abc'])
    def test_classifies_mixed_alt_ips(self, mock_resolve):
        """Mixed IPv4+IPv6 alt_ips should be classified correctly."""
        from lanscape.core.net_tools import Device
        device = Device(ip='fe80::1', alive=True, macs=['aa:bb:cc:dd:ee:ff'])
        device._resolve_alt_ips()
        assert device.ipv4_addresses == ['10.0.0.5']
        assert device.ipv6_addresses == ['fe80::1', 'fe80::abc']
