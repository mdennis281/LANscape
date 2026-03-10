"""
Unit tests for IPv6 support across the scanning pipeline.

Covers:
- system_compat: is_ipv6, get_socket_family, send_arp_request (IPv6 skip),
  get_ping_command (IPv6), get_arp_lookup_command (IPv6 NDP),
  get_candidate_interfaces (AF_INET6)
- device_alive: ArpCacheLookup/ArpLookup skip for IPv6, Poker IPv6 socket family
- mac_lookup: Scapy skip for IPv6, neighbor cache fallback
- device: test_port AF_INET6, mDNS IPv6 dispatch, NetBIOS IPv6 skip
- subnet_scan: to_results sorts mixed IPv4/IPv6
"""
# pylint: disable=protected-access,unused-argument

import ipaddress
import socket
from unittest.mock import patch, MagicMock

from lanscape.core.system_compat import (
    is_ipv6,
    get_socket_family,
    send_arp_request,
    get_ping_command,
    get_arp_lookup_command,
    get_candidate_interfaces,
)
from lanscape.core.device_alive import (
    ArpCacheLookup,
    ArpLookup,
    Poker,
)
from lanscape.core.mac_lookup import MacResolver
from lanscape.core.net_tools import Device
from lanscape.core.net_tools.subnet_utils import (
    _get_ipv6_prefix,
    _is_scannable_ipv6,
    network_from_snicaddr,
)
from lanscape.core.scan_config import (
    ArpCacheConfig,
    ArpConfig,
    PokeConfig,
    PortScanConfig,
)


# ===========================================================================
# system_compat helpers
# ===========================================================================


class TestIsIpv6:
    """Tests for is_ipv6() helper."""

    def test_ipv4_address(self):
        """Standard dotted-decimal IPv4 returns False."""
        assert is_ipv6('192.168.1.1') is False

    def test_ipv6_full(self):
        """Full IPv6 address returns True."""
        assert is_ipv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334') is True

    def test_ipv6_compressed(self):
        """Compressed IPv6 address returns True."""
        assert is_ipv6('::1') is True

    def test_ipv6_link_local(self):
        """Link-local IPv6 address returns True."""
        assert is_ipv6('fe80::1') is True

    def test_empty_string(self):
        """Empty string returns False (no colon)."""
        assert is_ipv6('') is False


class TestGetSocketFamily:
    """Tests for get_socket_family() helper."""

    def test_ipv4_returns_af_inet(self):
        """IPv4 addresses produce AF_INET."""
        assert get_socket_family('10.0.0.1') == socket.AF_INET

    def test_ipv6_returns_af_inet6(self):
        """IPv6 addresses produce AF_INET6."""
        assert get_socket_family('::1') == socket.AF_INET6

    def test_ipv6_full_returns_af_inet6(self):
        """Full IPv6 address produces AF_INET6."""
        assert get_socket_family('2001:db8::1') == socket.AF_INET6


class TestSendArpRequestIpv6:
    """send_arp_request should return empty for IPv6."""

    def test_ipv6_returns_empty(self):
        """IPv6 address should skip Scapy and return ([], [])."""
        answered, unanswered = send_arp_request('::1')
        assert answered == []
        assert unanswered == []

    def test_ipv6_full_returns_empty(self):
        """Full IPv6 address should also return ([], [])."""
        answered, unanswered = send_arp_request('2001:db8::1')
        assert answered == []
        assert unanswered == []


class TestGetPingCommandIpv6:
    """get_ping_command produces correct IPv6 commands."""

    @patch('lanscape.core.system_compat.psutil')
    def test_windows_ipv6_uses_dash_6(self, mock_psutil):
        """Windows IPv6 ping should use 'ping -6'."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False

        cmd = get_ping_command(3, 1000, '::1')
        assert cmd[0] == 'ping'
        assert '-6' in cmd
        assert '::1' in cmd
        assert '3' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_windows_ipv4_uses_dash_4(self, mock_psutil):
        """Windows IPv4 ping should use 'ping -4'."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False

        cmd = get_ping_command(1, 2000, '192.168.1.1')
        assert cmd[0] == 'ping'
        assert '-4' in cmd
        assert '192.168.1.1' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_linux_ipv6_uses_ping_dash_6(self, mock_psutil):
        """Linux IPv6 ping should use 'ping -6' (works in minimal containers)."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False

        cmd = get_ping_command(2, 3000, 'fe80::1')
        assert cmd[0] == 'ping'
        assert '-6' in cmd
        assert 'fe80::1' in cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_linux_ipv4_uses_ping(self, mock_psutil):
        """Linux IPv4 ping should use plain 'ping'."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False

        cmd = get_ping_command(2, 3000, '10.0.0.1')
        assert cmd[0] == 'ping'
        assert '10.0.0.1' in cmd


class TestGetArpLookupCommandIpv6:
    """get_arp_lookup_command dispatches to NDP for IPv6."""

    @patch('lanscape.core.system_compat.psutil')
    def test_ipv6_windows_uses_netsh(self, mock_psutil):
        """Windows IPv6 should use netsh to query full neighbor table."""
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False

        cmd = get_arp_lookup_command('fe80::1')
        assert 'netsh' in cmd
        assert 'ipv6' in cmd
        # Note: Windows returns full table for Python-side exact IP matching
        assert cmd == 'netsh interface ipv6 show neighbors'

    @patch('lanscape.core.system_compat.psutil')
    def test_ipv6_linux_uses_ip_dash_6(self, mock_psutil):
        """Linux IPv6 should use 'ip -6 neigh show'."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False

        cmd = get_arp_lookup_command('2001:db8::1')
        assert 'ip -6 neigh show 2001:db8::1' == cmd

    @patch('lanscape.core.system_compat.psutil')
    def test_ipv6_macos_uses_ndp(self, mock_psutil):
        """macOS IPv6 should use 'ndp -an' for full neighbor table."""
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True

        cmd = get_arp_lookup_command('::1')
        assert 'ndp' in cmd
        # Note: macOS returns full table for Python-side exact IP matching
        assert cmd == 'ndp -an'


class TestGetCandidateInterfacesIpv6:
    """get_candidate_interfaces should include IPv6-capable interfaces."""

    @patch('lanscape.core.system_compat.psutil')
    def test_ipv6_only_interface_included(self, mock_psutil):
        """An up interface with only an IPv6 address should be a candidate."""
        v6_addr = MagicMock(family=socket.AF_INET6, address='2001:db8::1')
        mock_psutil.net_if_addrs.return_value = {'eth0': [v6_addr]}
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False

        result = get_candidate_interfaces()
        assert 'eth0' in result

    @patch('lanscape.core.system_compat.psutil')
    def test_loopback_v6_excluded(self, mock_psutil):
        """Interface with only ::1 (loopback) should be excluded."""
        v6_addr = MagicMock(family=socket.AF_INET6, address='::1')
        mock_psutil.net_if_addrs.return_value = {'lo': [v6_addr]}
        mock_psutil.net_if_stats.return_value = {
            'lo': MagicMock(isup=True),
        }

        result = get_candidate_interfaces()
        assert 'lo' not in result


# ===========================================================================
# device_alive — IPv6 behaviour
# ===========================================================================


class TestArpCacheLookupIpv6:
    """ArpCacheLookup should skip for IPv6 targets."""

    def test_ipv6_target_skipped(self):
        """IPv6 device should not trigger ARP cache lookup."""
        device = Device(ip='2001:db8::1')
        cfg = ArpCacheConfig()

        result = ArpCacheLookup.execute(device, cfg)

        # Should return without changing alive status
        assert result is False
        assert device.alive is None

    def test_ipv4_target_not_skipped(self):
        """IPv4 device should proceed with ARP cache lookup (mocked)."""
        device = Device(ip='192.168.1.1')
        cfg = ArpCacheConfig()

        with patch.object(ArpCacheLookup, '_get_platform_arp_command',
                          return_value=['arp', '-a']):
            with patch('lanscape.core.device_alive.subprocess.check_output',
                       return_value=b'192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic'):
                ArpCacheLookup.execute(device, cfg)

        assert device.alive is True


class TestArpLookupIpv6:
    """ArpLookup should skip for IPv6 targets."""

    def test_ipv6_target_skipped(self):
        """IPv6 device should not trigger ARP lookup."""
        device = Device(ip='fe80::1')
        cfg = ArpConfig()

        result = ArpLookup.execute(device, cfg)

        assert result is False
        assert device.alive is None


class TestPokerIpv6:
    """Poker should use the correct socket family for IPv6."""

    @patch('lanscape.core.device_alive.socket.socket')
    def test_ipv6_uses_af_inet6(self, mock_socket_cls):
        """Poker with IPv6 target should create AF_INET6 socket."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        device = Device(ip='2001:db8::1')
        cfg = PokeConfig(attempts=1, timeout=0.1)

        Poker.execute(device, cfg)

        # Verify at least one socket was created with AF_INET6
        calls = mock_socket_cls.call_args_list
        assert any(
            call[0][0] == socket.AF_INET6 for call in calls
        ), f"Expected AF_INET6 in socket calls: {calls}"

    @patch('lanscape.core.device_alive.socket.socket')
    def test_ipv4_uses_af_inet(self, mock_socket_cls):
        """Poker with IPv4 target should create AF_INET socket."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        device = Device(ip='192.168.1.1')
        cfg = PokeConfig(attempts=1, timeout=0.1)

        Poker.execute(device, cfg)

        calls = mock_socket_cls.call_args_list
        assert any(
            call[0][0] == socket.AF_INET for call in calls
        ), f"Expected AF_INET in socket calls: {calls}"


# ===========================================================================
# mac_lookup — IPv6 behaviour
# ===========================================================================


class TestMacResolverIpv6:
    """MacResolver should skip Scapy for IPv6 and use neighbor cache."""

    @patch.object(MacResolver, '_get_mac_by_neighbor_cache', return_value=['aa:bb:cc:dd:ee:ff'])
    @patch.object(MacResolver, '_get_mac_by_scapy')
    def test_ipv6_skips_scapy(self, mock_scapy, mock_cache):
        """IPv6 target should bypass Scapy and go straight to neighbor cache."""
        resolver = MacResolver()
        result = resolver.get_macs('2001:db8::1')

        mock_scapy.assert_not_called()
        mock_cache.assert_called_once_with('2001:db8::1')
        assert result == ['aa:bb:cc:dd:ee:ff']

    @patch.object(MacResolver, '_get_mac_by_neighbor_cache', return_value=['11:22:33:44:55:66'])
    @patch.object(MacResolver, '_get_mac_by_scapy', return_value=[])
    def test_ipv4_tries_scapy_first(self, mock_scapy, mock_cache):
        """IPv4 target should try Scapy first, then fall back to neighbor cache."""
        resolver = MacResolver()
        result = resolver.get_macs('192.168.1.1')

        mock_scapy.assert_called_once_with('192.168.1.1')
        mock_cache.assert_called_once_with('192.168.1.1')
        assert result == ['11:22:33:44:55:66']

    @patch('lanscape.core.mac_lookup.subprocess.check_output')
    @patch('lanscape.core.mac_lookup.get_arp_lookup_command',
           return_value='ip -6 neigh show 2001:db8::1')
    def test_ipv6_neighbor_cache_command(self, _mock_cmd, mock_check_output):
        """IPv6 neighbor cache lookup should use IPv6 NDP command."""
        mock_check_output.return_value = (
            b"2001:db8::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        )
        resolver = MacResolver()
        result = resolver._get_mac_by_neighbor_cache('2001:db8::1')

        mock_check_output.assert_called_once()
        assert 'aa:bb:cc:dd:ee:ff' in result


# ===========================================================================
# device — port scanning and hostname resolution
# ===========================================================================


class TestDeviceTestPortIpv6:
    """Device.test_port should use the correct socket family."""

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_ipv6_port_scan_uses_af_inet6(self, mock_socket_cls):
        """IPv6 device port scan should create AF_INET6 socket."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        device = Device(ip='2001:db8::1', alive=True)
        config = PortScanConfig(timeout=0.5, retries=0)

        result = device.test_port(80, config)

        assert result is True
        assert 80 in device.ports
        # Check socket was created with AF_INET6
        calls = mock_socket_cls.call_args_list
        assert any(
            call[0][0] == socket.AF_INET6 for call in calls
        ), f"Expected AF_INET6 in socket calls: {calls}"

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_ipv4_port_scan_uses_af_inet(self, mock_socket_cls):
        """IPv4 device port scan should create AF_INET socket."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        device = Device(ip='192.168.1.1', alive=True)
        config = PortScanConfig(timeout=0.5, retries=0)

        result = device.test_port(443, config)

        assert result is True
        calls = mock_socket_cls.call_args_list
        assert any(
            call[0][0] == socket.AF_INET for call in calls
        ), f"Expected AF_INET in socket calls: {calls}"


class TestDeviceMdnsIpv6:
    """Device._resolve_mdns dispatches to v4 or v6."""

    @patch.object(Device, '_resolve_mdns_v4', return_value='host-v4.local')
    @patch.object(Device, '_resolve_mdns_v6')
    def test_ipv4_device_uses_v4_mdns(self, mock_v6, mock_v4):
        """IPv4 device should use the v4 mDNS path."""
        device = Device(ip='192.168.1.10', alive=True)
        result = device._resolve_mdns()

        mock_v4.assert_called_once()
        mock_v6.assert_not_called()
        assert result == 'host-v4.local'

    @patch.object(Device, '_resolve_mdns_v6', return_value='host-v6.local')
    @patch.object(Device, '_resolve_mdns_v4')
    def test_ipv6_device_uses_v6_mdns(self, mock_v4, mock_v6):
        """IPv6 device should use the v6 mDNS path."""
        device = Device(ip='2001:db8::10', alive=True)
        result = device._resolve_mdns()

        mock_v6.assert_called_once()
        mock_v4.assert_not_called()
        assert result == 'host-v6.local'


class TestDeviceMdnsV6:
    """Tests for Device._resolve_mdns_v6 directly."""

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_sends_to_ipv6_multicast(self, mock_socket_cls):
        """IPv6 mDNS should send to ff02::fb on port 5353."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # Return a minimal non-response to trigger None
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')

        device = Device(ip='2001:0db8:0000:0000:0000:0000:0000:0001', alive=True)
        device._resolve_mdns_v6()

        # Verify sendto was called with IPv6 multicast address
        args, _ = mock_sock.sendto.call_args
        assert args[1] == ('ff02::fb', 5353)

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_uses_af_inet6_socket(self, mock_socket_cls):
        """IPv6 mDNS should create an AF_INET6 UDP socket."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')

        device = Device(ip='::1', alive=True)
        device._resolve_mdns_v6()

        mock_socket_cls.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_timeout_returns_none(self, mock_socket_cls):
        """Socket timeout returns None gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')

        device = Device(ip='fe80::1', alive=True)
        assert device._resolve_mdns_v6() is None
        mock_sock.close.assert_called_once()


class TestDeviceNetbiosIpv6:
    """Device._resolve_netbios should skip IPv6."""

    def test_ipv6_returns_none(self):
        """NetBIOS is IPv4-only, so IPv6 should return None immediately."""
        device = Device(ip='2001:db8::1', alive=True)
        assert device._resolve_netbios() is None

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_ipv6_does_not_create_socket(self, mock_socket_cls):
        """IPv6 should not even attempt socket creation for NetBIOS."""
        device = Device(ip='fe80::1', alive=True)
        device._resolve_netbios()
        mock_socket_cls.assert_not_called()


# ===========================================================================
# subnet_scan — mixed sorting
# ===========================================================================


class TestMixedIpSorting:
    """to_results should sort mixed IPv4/IPv6 addresses correctly."""

    def test_ipv4_before_ipv6(self):
        """IPv4 addresses should sort before IPv6 when using (version, packed) key."""
        addrs = ['2001:db8::1', '10.0.0.1', '192.168.1.1', '::1']
        sorted_addrs = sorted(
            addrs,
            key=lambda x: (
                ipaddress.ip_address(x).version,
                ipaddress.ip_address(x).packed,
            ),
        )
        # IPv4 (version 4) sorts before IPv6 (version 6)
        assert sorted_addrs == ['10.0.0.1', '192.168.1.1', '::1', '2001:db8::1']


# ===========================================================================
# IPv6 subnet discovery
# ===========================================================================


class TestIpv6SubnetDiscovery:
    """Tests for IPv6 prefix detection and filtering in subnet_utils."""

    def test_get_ipv6_prefix_with_netmask(self):
        """When netmask is provided (Linux), use it."""
        assert _get_ipv6_prefix('2001:db8::1', '64') == 64
        assert _get_ipv6_prefix('2001:db8::1', '128') == 128

    def test_get_ipv6_prefix_link_local_default(self):
        """Link-local addresses default to /10."""
        assert _get_ipv6_prefix('fe80::1', None) == 10
        assert _get_ipv6_prefix('FE80::abcd', None) == 10

    def test_get_ipv6_prefix_loopback(self):
        """Loopback ::1 should be /128."""
        assert _get_ipv6_prefix('::1', None) == 128

    def test_get_ipv6_prefix_global_default(self):
        """Global addresses default to /64 when netmask is None."""
        assert _get_ipv6_prefix('2001:db8::1', None) == 64
        assert _get_ipv6_prefix('2601:2c5:4000:20e9::18c2', None) == 64

    def test_is_scannable_ipv6_global(self):
        """Global IPv6 addresses are scannable."""
        assert _is_scannable_ipv6('2001:db8::1') is True
        assert _is_scannable_ipv6('2601:2c5:4000:20e9::18c2') is True

    def test_is_scannable_ipv6_link_local(self):
        """Link-local addresses are not scannable."""
        assert _is_scannable_ipv6('fe80::1') is False
        assert _is_scannable_ipv6('FE80::abcd') is False
        assert _is_scannable_ipv6('fe80::1%eth0') is False  # With zone ID

    def test_is_scannable_ipv6_loopback(self):
        """Loopback is not scannable."""
        assert _is_scannable_ipv6('::1') is False

    def test_network_from_snicaddr_ipv6_global(self):
        """Global IPv6 snicaddr should return network/prefix."""
        mock_snic = MagicMock()
        mock_snic.family = socket.AF_INET6
        mock_snic.address = '2001:db8::1'
        mock_snic.netmask = None  # Windows case
        result = network_from_snicaddr(mock_snic)
        assert result == '2001:db8::/64'

    def test_network_from_snicaddr_ipv6_link_local_filtered(self):
        """Link-local IPv6 snicaddr should return None."""
        mock_snic = MagicMock()
        mock_snic.family = socket.AF_INET6
        mock_snic.address = 'fe80::1'
        mock_snic.netmask = None
        result = network_from_snicaddr(mock_snic)
        assert result is None

    def test_network_from_snicaddr_ipv6_with_zone_id(self):
        """Zone IDs should be stripped from IPv6 addresses."""
        mock_snic = MagicMock()
        mock_snic.family = socket.AF_INET6
        mock_snic.address = '2001:db8::1%eth0'
        mock_snic.netmask = '64'
        result = network_from_snicaddr(mock_snic)
        assert result == '2001:db8::/64'
