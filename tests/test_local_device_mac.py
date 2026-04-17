"""Tests for local device MAC address detection.

Verifies that the scanning host's own IP is correctly identified and
its MAC is populated from OS interface info (since a device never
appears in its own ARP/neighbor table).
"""

import socket
from collections import namedtuple
from unittest.mock import patch, MagicMock

import pytest

from lanscape.core.system_compat import (
    get_local_mac_for_ip,
    refresh_local_ip_mac_cache,
    _build_local_ip_mac_map,
)


# Fake psutil address entries
FakeAddr = namedtuple('FakeAddr', ['family', 'address', 'netmask', 'broadcast', 'ptp'])

# Constants matching psutil's platform-specific L2 family values
AF_LINK = -1     # placeholder (macOS/BSD uses psutil.AF_LINK)


def _make_fake_addrs(mac: str, ipv4: str, ipv6: str | None = None):
    """Build a list of fake psutil snicaddr entries for one interface."""
    addrs = [
        FakeAddr(family=AF_LINK, address=mac, netmask=None, broadcast=None, ptp=None),
        FakeAddr(family=socket.AF_INET, address=ipv4, netmask='255.255.255.0',
                 broadcast=None, ptp=None),
    ]
    if ipv6:
        addrs.append(FakeAddr(family=socket.AF_INET6, address=ipv6,
                              netmask=None, broadcast=None, ptp=None))
    return addrs


class TestBuildLocalIpMacMap:
    """Unit tests for _build_local_ip_mac_map."""

    @patch('lanscape.core.system_compat.psutil')
    def test_maps_ipv4_to_mac(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'eth0': _make_fake_addrs('aa:bb:cc:dd:ee:ff', '192.168.1.100'),
        }
        result = _build_local_ip_mac_map()
        assert result.get('192.168.1.100') == 'aa:bb:cc:dd:ee:ff'

    @patch('lanscape.core.system_compat.psutil')
    def test_maps_ipv6_to_mac(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'eth0': _make_fake_addrs('aa:bb:cc:dd:ee:ff', '192.168.1.100',
                                     'fe80::1%eth0'),
        }
        result = _build_local_ip_mac_map()
        assert result.get('fe80::1') == 'aa:bb:cc:dd:ee:ff'

    @patch('lanscape.core.system_compat.psutil')
    def test_multiple_interfaces(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'eth0': _make_fake_addrs('aa:bb:cc:dd:ee:ff', '192.168.1.100'),
            'wlan0': _make_fake_addrs('11:22:33:44:55:66', '10.0.0.5'),
        }
        result = _build_local_ip_mac_map()
        assert result.get('192.168.1.100') == 'aa:bb:cc:dd:ee:ff'
        assert result.get('10.0.0.5') == '11:22:33:44:55:66'

    @patch('lanscape.core.system_compat.psutil')
    def test_skips_zero_mac(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'lo': _make_fake_addrs('00:00:00:00:00:00', '127.0.0.1'),
        }
        result = _build_local_ip_mac_map()
        assert '127.0.0.1' not in result

    @patch('lanscape.core.system_compat.psutil')
    def test_normalizes_windows_dashes_to_colons(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'Ethernet': _make_fake_addrs('AA-BB-CC-DD-EE-FF', '192.168.1.50'),
        }
        result = _build_local_ip_mac_map()
        assert result.get('192.168.1.50') == 'aa:bb:cc:dd:ee:ff'

    @patch('lanscape.core.system_compat.psutil')
    def test_interface_without_l2_addr_skipped(self, mock_psutil):
        """Interfaces with no MAC address should not map any IPs."""
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'tun0': [
                FakeAddr(family=socket.AF_INET, address='10.8.0.2',
                         netmask='255.255.255.0', broadcast=None, ptp=None),
            ],
        }
        result = _build_local_ip_mac_map()
        assert '10.8.0.2' not in result


class TestGetLocalMacForIp:
    """Tests for the cached get_local_mac_for_ip function."""

    @patch('lanscape.core.system_compat.psutil')
    def test_returns_mac_for_local_ip(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'eth0': _make_fake_addrs('de:ad:be:ef:00:01', '192.168.1.42'),
        }
        refresh_local_ip_mac_cache()
        assert get_local_mac_for_ip('192.168.1.42') == 'de:ad:be:ef:00:01'

    @patch('lanscape.core.system_compat.psutil')
    def test_returns_none_for_remote_ip(self, mock_psutil):
        mock_psutil.AF_LINK = AF_LINK
        mock_psutil.net_if_addrs.return_value = {
            'eth0': _make_fake_addrs('de:ad:be:ef:00:01', '192.168.1.42'),
        }
        refresh_local_ip_mac_cache()
        assert get_local_mac_for_ip('192.168.1.99') is None


class TestDeviceSelfDetection:
    """Integration-style tests: Device._get_mac_addresses uses local MAC for self."""

    @patch('lanscape.core.net_tools.device.get_local_mac_for_ip')
    @patch('lanscape.core.net_tools.device.NeighborTableService')
    def test_local_ip_gets_interface_mac(self, mock_nts, mock_get_local):
        """When the device IP matches a local interface, use interface MAC."""
        from lanscape.core.net_tools.device import Device

        mock_get_local.return_value = 'aa:bb:cc:dd:ee:ff'
        device = Device(ip='192.168.1.100', alive=True)
        device._get_mac_addresses()

        assert device.macs == ['aa:bb:cc:dd:ee:ff']
        mock_nts.instance.assert_not_called()  # Should NOT fall back to ARP

    @patch('lanscape.core.net_tools.device.get_local_mac_for_ip')
    @patch('lanscape.core.net_tools.device.NeighborTableService')
    def test_remote_ip_uses_neighbor_table(self, mock_nts, mock_get_local):
        """When the device IP is not local, fall back to NeighborTableService."""
        from lanscape.core.net_tools.device import Device

        mock_get_local.return_value = None
        mock_svc = MagicMock()
        mock_svc.get_macs_wait.return_value = ['11:22:33:44:55:66']
        mock_nts.instance.return_value = mock_svc

        device = Device(ip='192.168.1.50', alive=True)
        device._get_mac_addresses()

        assert device.macs == ['11:22:33:44:55:66']
        mock_svc.get_macs_wait.assert_called_once_with('192.168.1.50')

    @patch('lanscape.core.net_tools.device.get_local_mac_for_ip')
    @patch('lanscape.core.net_tools.device.NeighborTableService')
    def test_skips_lookup_if_macs_already_set(self, mock_nts, mock_get_local):
        """If macs are already populated, no lookups should happen."""
        from lanscape.core.net_tools.device import Device

        device = Device(ip='192.168.1.100', alive=True, macs=['ff:ff:ff:ff:ff:ff'])
        device._get_mac_addresses()

        mock_get_local.assert_not_called()
        mock_nts.instance.assert_not_called()
