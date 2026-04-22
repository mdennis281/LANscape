"""
Unit and integration tests for the centralized NeighborTableService.

Covers:
- Platform-specific output parsers (canned output for all OS/protocol combos)
- NeighborTable model (lookup, reverse lookup, deduplication)
- NeighborTableService lifecycle (start/stop, singleton, wait_for_refresh)
- Command fallback logic
- Live integration tests (Windows local)
"""
# pylint: disable=protected-access,missing-function-docstring,import-outside-toplevel
import shutil as _shutil
import subprocess
from unittest.mock import patch

import psutil
import pytest

from lanscape.core.neighbor_table import (
    NeighborEntry,
    NeighborTableService,
    build_table,
    parse_linux_neigh,
    parse_windows_arp,
    parse_powershell_neighbor,
    parse_netsh_neighbors,
    parse_macos_arp,
    parse_macos_ndp,
    parse_command_output,
    get_table_commands,
    _normalize_ip,
    _normalize_mac,
)
from lanscape.core.system_compat import query_single_arp_entry, _SINGLE_ARP_MAC_RE


# ═══════════════════════════════════════════════════════════════════
#  Canned output samples
# ═══════════════════════════════════════════════════════════════════

LINUX_IPV4_NEIGH = """\
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE
10.0.0.1 dev wlan0 lladdr de:ad:be:ef:00:01 DELAY
192.168.1.50 dev eth0  FAILED
"""

LINUX_IPV6_NEIGH = """\
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
2001:db8::100 dev eth0 lladdr 11:22:33:44:55:66 STALE
fe80::dead:beef dev wlan0 lladdr de:ad:be:ef:00:01 DELAY
fe80::bad dev eth0  FAILED
"""

WINDOWS_ARP_OUTPUT = """\

Interface: 10.0.4.1 --- 0x8
  Internet Address      Physical Address      Type
  10.0.0.1              00-1b-21-38-a9-64     dynamic
  10.0.0.11             ca-a2-81-86-ab-c1     dynamic
  10.0.0.20             e0-4f-43-e6-af-1f     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.56.1 --- 0x3
  Internet Address      Physical Address      Type
  192.168.56.255        ff-ff-ff-ff-ff-ff     static
"""

WINDOWS_PS_CSV_OUTPUT = """\
"ifIndex","IPAddress","LinkLayerAddress","State","PolicyStore","AddressFamily"
"8","fe80::ee71:dbff:fea0:dd01","EC-71-DB-A0-DD-01","Stale","ActiveStore","IPv6"
"8","fe80::ead8:7eff:fe73:bea1","E8-D8-7E-73-BE-A1","Stale","ActiveStore","IPv6"
"8","fe80::e24f:43ff:fee6:af1f","E0-4F-43-E6-AF-1F","Reachable","ActiveStore","IPv6"
"8","fe80::1","00-1B-21-38-A9-64","Stale","ActiveStore","IPv6"
"8","::1","00-00-00-00-00-00","Permanent","ActiveStore","IPv6"
"""

WINDOWS_PS_TABLE_OUTPUT = """\
ifIndex IPAddress                 LinkLayerAddress  State       PolicyStore
------- ---------                 ----------------  -----       -----------
8       fe80::ee71:dbff:fea0:dd01 EC-71-DB-A0-DD-01 Stale       ActiveStore
8       fe80::1                   00-1B-21-38-A9-64 Reachable   ActiveStore
"""

NETSH_OUTPUT = """\
Interface 8: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::ee71:dbff:fea0:dd01                     ec-71-db-a0-dd-01  Stale
fe80::ead8:7eff:fe73:bea1                     e8-d8-7e-73-be-a1  Stale
2601:2c5:4000:20e9::1115                      00-00-00-00-00-00  Unreachable
2601:2c5:4000:20e9:403c:3d7:7da1:79d2        26-27-b6-e3-91-e1  Stale

Interface 1: Loopback Pseudo-Interface 1

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
::1                                           00-00-00-00-00-00  Permanent
"""

MACOS_ARP_OUTPUT = """\
? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.2) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]
? (10.0.0.1) at de:ad:be:ef:0:1 on en1 [ethernet]
"""

MACOS_NDP_OUTPUT = """\
Neighbor                        Linklayer Address  Netif Expire    S Flags
fe80::1%en0                     aa:bb:cc:dd:ee:ff  en0   23h59m57s S R
fe80::aede:48ff:fe00:1122%en0   ac:de:48:00:11:22  en0   permanent R
2001:db8::100%en0               11:22:33:44:55:66  en0   23h50m00s S
"""


# ═══════════════════════════════════════════════════════════════════
#  Parser tests
# ═══════════════════════════════════════════════════════════════════

class TestParseLinuxNeigh:
    """Tests for parse_linux_neigh()."""

    def test_ipv4_basic(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        assert len(entries) == 3
        ips = {e.ip for e in entries}
        assert '192.168.1.1' in ips
        assert '192.168.1.2' in ips
        assert '10.0.0.1' in ips

    def test_ipv4_mac_normalized(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        entry = next(e for e in entries if e.ip == '192.168.1.1')
        assert entry.mac == 'aa:bb:cc:dd:ee:ff'

    def test_ipv4_state_captured(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        entry = next(e for e in entries if e.ip == '192.168.1.1')
        assert entry.state == 'REACHABLE'

    def test_ipv4_failed_excluded(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        ips = {e.ip for e in entries}
        assert '192.168.1.50' not in ips

    def test_ipv4_interface_captured(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        entry = next(e for e in entries if e.ip == '10.0.0.1')
        assert entry.interface == 'wlan0'

    def test_ipv6_basic(self):
        entries = parse_linux_neigh(LINUX_IPV6_NEIGH, ip_version=6)
        assert len(entries) == 3
        ips = {e.ip for e in entries}
        assert 'fe80::1' in ips
        assert '2001:db8::100' in ips

    def test_ipv6_failed_excluded(self):
        entries = parse_linux_neigh(LINUX_IPV6_NEIGH, ip_version=6)
        ips = {e.ip for e in entries}
        assert 'fe80::bad' not in ips

    def test_empty_output(self):
        assert not parse_linux_neigh('', ip_version=4)

    def test_ip_version_set(self):
        entries = parse_linux_neigh(LINUX_IPV4_NEIGH, ip_version=4)
        assert all(e.ip_version == 4 for e in entries)
        entries6 = parse_linux_neigh(LINUX_IPV6_NEIGH, ip_version=6)
        assert all(e.ip_version == 6 for e in entries6)


class TestParseWindowsArp:
    """Tests for parse_windows_arp()."""

    def test_basic_entries(self):
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        # Should get 10.0.0.1, 10.0.0.11, 10.0.0.20 (broadcast/multicast filtered by build_table)
        ips = {e.ip for e in entries}
        assert '10.0.0.1' in ips
        assert '10.0.0.11' in ips
        assert '10.0.0.20' in ips

    def test_mac_normalized(self):
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        entry = next(e for e in entries if e.ip == '10.0.0.1')
        assert entry.mac == '00:1b:21:38:a9:64'

    def test_broadcast_included_in_parse(self):
        """Parser includes broadcast MACs; build_table filters them."""
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        macs = {e.mac for e in entries}
        assert 'ff:ff:ff:ff:ff:ff' in macs

    def test_interface_from_header(self):
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        entry = next(e for e in entries if e.ip == '10.0.0.1')
        assert entry.interface == '0x8'

    def test_second_interface(self):
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        bcast = [e for e in entries if e.ip == '192.168.56.255']
        assert len(bcast) == 1
        assert bcast[0].interface == '0x3'

    def test_all_ipv4(self):
        entries = parse_windows_arp(WINDOWS_ARP_OUTPUT)
        assert all(e.ip_version == 4 for e in entries)

    def test_empty_output(self):
        assert not parse_windows_arp('')


class TestParsePowershellNeighbor:
    """Tests for parse_powershell_neighbor() — CSV and table formats."""

    def test_csv_basic(self):
        entries = parse_powershell_neighbor(WINDOWS_PS_CSV_OUTPUT, ip_version=6)
        # Loopback ::1 filtered, null MAC filtered by build_table
        real_entries = [e for e in entries if e.ip != '::1']
        assert len(real_entries) == 4

    def test_csv_mac_normalized(self):
        entries = parse_powershell_neighbor(WINDOWS_PS_CSV_OUTPUT, ip_version=6)
        entry = next(e for e in entries if e.ip == 'fe80::ee71:dbff:fea0:dd01')
        assert entry.mac == 'ec:71:db:a0:dd:01'

    def test_csv_state(self):
        entries = parse_powershell_neighbor(WINDOWS_PS_CSV_OUTPUT, ip_version=6)
        entry = next(e for e in entries if e.ip == 'fe80::e24f:43ff:fee6:af1f')
        assert entry.state == 'Reachable'

    def test_csv_loopback_filtered(self):
        entries = parse_powershell_neighbor(WINDOWS_PS_CSV_OUTPUT, ip_version=6)
        ips = {e.ip for e in entries}
        assert '::1' not in ips

    def test_table_fallback(self):
        entries = parse_powershell_neighbor(WINDOWS_PS_TABLE_OUTPUT, ip_version=6)
        assert len(entries) == 2
        ips = {e.ip for e in entries}
        assert 'fe80::ee71:dbff:fea0:dd01' in ips

    def test_empty_output(self):
        assert not parse_powershell_neighbor('', ip_version=6)


class TestParseNetshNeighbors:
    """Tests for parse_netsh_neighbors()."""

    def test_basic_entries(self):
        entries = parse_netsh_neighbors(NETSH_OUTPUT)
        # Null MACs included by parser, filtered by build_table
        all_ips = {e.ip for e in entries}
        assert 'fe80::ee71:dbff:fea0:dd01' in all_ips
        assert 'fe80::ead8:7eff:fe73:bea1' in all_ips

    def test_mac_normalized(self):
        entries = parse_netsh_neighbors(NETSH_OUTPUT)
        entry = next(e for e in entries
                     if e.ip == 'fe80::ee71:dbff:fea0:dd01')
        assert entry.mac == 'ec:71:db:a0:dd:01'

    def test_interface_from_header(self):
        entries = parse_netsh_neighbors(NETSH_OUTPUT)
        entry = next(e for e in entries
                     if e.ip == 'fe80::ee71:dbff:fea0:dd01')
        assert entry.interface == '8'

    def test_loopback_filtered(self):
        entries = parse_netsh_neighbors(NETSH_OUTPUT)
        ips = {e.ip for e in entries}
        assert '::1' not in ips

    def test_all_ipv6(self):
        entries = parse_netsh_neighbors(NETSH_OUTPUT)
        assert all(e.ip_version == 6 for e in entries)

    def test_empty_output(self):
        assert not parse_netsh_neighbors('')


class TestParseMacosArp:
    """Tests for parse_macos_arp()."""

    def test_basic_entries(self):
        entries = parse_macos_arp(MACOS_ARP_OUTPUT)
        assert len(entries) == 3  # incomplete entry excluded
        ips = {e.ip for e in entries}
        assert '192.168.1.1' in ips
        assert '192.168.1.2' in ips

    def test_single_digit_hex_normalized(self):
        """macOS arp may produce single-digit hex (e.g. 'de:ad:be:ef:0:1')."""
        entries = parse_macos_arp(MACOS_ARP_OUTPUT)
        entry = next(e for e in entries if e.ip == '10.0.0.1')
        assert entry.mac == 'de:ad:be:ef:00:01'

    def test_interface_captured(self):
        entries = parse_macos_arp(MACOS_ARP_OUTPUT)
        entry = next(e for e in entries if e.ip == '192.168.1.1')
        assert entry.interface == 'en0'

    def test_incomplete_excluded(self):
        entries = parse_macos_arp(MACOS_ARP_OUTPUT)
        ips = {e.ip for e in entries}
        assert '192.168.1.3' not in ips

    def test_empty_output(self):
        assert not parse_macos_arp('')


class TestParseMacosNdp:
    """Tests for parse_macos_ndp()."""

    def test_basic_entries(self):
        entries = parse_macos_ndp(MACOS_NDP_OUTPUT)
        assert len(entries) == 3
        ips = {e.ip for e in entries}
        assert 'fe80::1' in ips
        assert '2001:db8::100' in ips

    def test_scope_stripped(self):
        entries = parse_macos_ndp(MACOS_NDP_OUTPUT)
        entry = next(e for e in entries
                     if e.mac == 'ac:de:48:00:11:22')
        # IP should not contain %en0
        assert '%' not in entry.ip

    def test_interface_captured(self):
        entries = parse_macos_ndp(MACOS_NDP_OUTPUT)
        assert all(e.interface == 'en0' for e in entries)

    def test_all_ipv6(self):
        entries = parse_macos_ndp(MACOS_NDP_OUTPUT)
        assert all(e.ip_version == 6 for e in entries)

    def test_empty_output(self):
        assert not parse_macos_ndp('')


# ═══════════════════════════════════════════════════════════════════
#  NeighborTable model tests
# ═══════════════════════════════════════════════════════════════════

class TestBuildTable:
    """Tests for build_table() and NeighborTable lookups."""

    def _sample_entries(self) -> list[NeighborEntry]:
        return [
            NeighborEntry(ip='192.168.1.1', mac='aa:bb:cc:dd:ee:ff',
                          state='REACHABLE', ip_version=4),
            NeighborEntry(ip='192.168.1.2', mac='11:22:33:44:55:66',
                          state='STALE', ip_version=4),
            NeighborEntry(ip='fe80::1', mac='aa:bb:cc:dd:ee:ff',
                          state='REACHABLE', ip_version=6),
            NeighborEntry(ip='fe80::2', mac='de:ad:be:ef:00:01',
                          state='STALE', ip_version=6),
        ]

    def test_get_mac(self):
        table = build_table(self._sample_entries())
        assert table.get_mac('192.168.1.1') == 'aa:bb:cc:dd:ee:ff'
        assert table.get_mac('fe80::1') == 'aa:bb:cc:dd:ee:ff'

    def test_get_mac_missing(self):
        table = build_table(self._sample_entries())
        assert table.get_mac('10.0.0.99') is None

    def test_get_macs(self):
        table = build_table(self._sample_entries())
        assert table.get_macs('192.168.1.1') == ['aa:bb:cc:dd:ee:ff']
        assert not table.get_macs('10.0.0.99')

    def test_get_ips_for_mac(self):
        table = build_table(self._sample_entries())
        v4_ips = table.get_ips_for_mac('aa:bb:cc:dd:ee:ff', want_v6=False)
        assert '192.168.1.1' in v4_ips
        v6_ips = table.get_ips_for_mac('aa:bb:cc:dd:ee:ff', want_v6=True)
        assert 'fe80::1' in v6_ips

    def test_has_entry(self):
        table = build_table(self._sample_entries())
        assert table.has_entry('192.168.1.1')
        assert not table.has_entry('8.8.8.8')

    def test_null_mac_filtered(self):
        entries = [
            NeighborEntry(ip='10.0.0.1', mac='00:00:00:00:00:00',
                          state='Unreachable', ip_version=4),
            NeighborEntry(ip='10.0.0.2', mac='aa:bb:cc:dd:ee:ff',
                          state='REACHABLE', ip_version=4),
        ]
        table = build_table(entries)
        assert not table.has_entry('10.0.0.1')
        assert table.has_entry('10.0.0.2')

    def test_broadcast_mac_filtered(self):
        entries = [
            NeighborEntry(ip='10.0.0.255', mac='ff:ff:ff:ff:ff:ff',
                          state='static', ip_version=4),
        ]
        table = build_table(entries)
        assert not table.has_entry('10.0.0.255')

    def test_reachable_preferred(self):
        """When same IP appears twice, REACHABLE state should be preferred."""
        entries = [
            NeighborEntry(ip='10.0.0.1', mac='aa:bb:cc:dd:ee:ff',
                          state='REACHABLE', ip_version=4),
            NeighborEntry(ip='10.0.0.1', mac='11:22:33:44:55:66',
                          state='STALE', ip_version=4),
        ]
        table = build_table(entries)
        assert table.get_mac('10.0.0.1') == 'aa:bb:cc:dd:ee:ff'

    def test_timestamp_set(self):
        table = build_table([])
        assert table.timestamp > 0

    def test_mac_case_insensitive(self):
        entries = [
            NeighborEntry(ip='10.0.0.1', mac='AA:BB:CC:DD:EE:FF',
                          state='REACHABLE', ip_version=4),
        ]
        table = build_table(entries)
        assert table.get_mac('10.0.0.1') == 'aa:bb:cc:dd:ee:ff'
        assert table.get_ips_for_mac('AA:BB:CC:DD:EE:FF', want_v6=False) == ['10.0.0.1']


class TestNormalization:
    """Tests for _normalize_ip and _normalize_mac."""

    def test_normalize_ipv4(self):
        assert _normalize_ip('192.168.1.1') == '192.168.1.1'

    def test_normalize_ipv6_full(self):
        assert _normalize_ip('fe80:0000:0000:0000:0000:0000:0000:0001') == 'fe80::1'

    def test_normalize_ipv6_scoped(self):
        assert _normalize_ip('fe80::1%eth0') == 'fe80::1'

    def test_normalize_mac_dashes(self):
        assert _normalize_mac('AA-BB-CC-DD-EE-FF') == 'aa:bb:cc:dd:ee:ff'

    def test_normalize_mac_colons(self):
        assert _normalize_mac('aa:bb:cc:dd:ee:ff') == 'aa:bb:cc:dd:ee:ff'


# ═══════════════════════════════════════════════════════════════════
#  Command routing tests
# ═══════════════════════════════════════════════════════════════════

class TestGetTableCommands:
    """Tests for get_table_commands() platform dispatch."""

    @patch('lanscape.core.neighbor_table.psutil')
    def test_windows_ipv4(self, mock_psutil):
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmds = get_table_commands(want_v6=False)
        assert len(cmds) == 1
        assert cmds[0] == ['arp', '-a']

    @patch('lanscape.core.neighbor_table.psutil')
    def test_windows_ipv6_powershell_primary(self, mock_psutil):
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmds = get_table_commands(want_v6=True)
        assert len(cmds) == 2
        assert 'powershell' in cmds[0][0]
        assert 'netsh' in cmds[1][0]

    @patch('lanscape.core.neighbor_table.psutil')
    @patch('lanscape.core.neighbor_table.shutil')
    def test_linux_ipv4(self, mock_shutil, mock_psutil):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        mock_shutil.which.return_value = '/usr/bin/ip'
        cmds = get_table_commands(want_v6=False)
        assert any('ip' in cmd[0] for cmd in cmds)

    @patch('lanscape.core.neighbor_table.psutil')
    def test_macos_ipv6(self, mock_psutil):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True
        cmds = get_table_commands(want_v6=True)
        assert cmds == [['ndp', '-an']]


class TestParseCommandOutput:
    """Tests for parse_command_output() router."""

    def test_routes_arp_windows(self):
        with patch('lanscape.core.neighbor_table._get_platform', return_value='windows'):
            entries = parse_command_output(['arp', '-a'], WINDOWS_ARP_OUTPUT, want_v6=False)
        assert len(entries) > 0

    def test_routes_powershell(self):
        entries = parse_command_output(
            ['powershell', '-NoProfile', '-Command', 'Get-NetNeighbor'],
            WINDOWS_PS_CSV_OUTPUT, want_v6=True)
        assert len(entries) > 0

    def test_routes_netsh(self):
        entries = parse_command_output(
            ['netsh', 'interface', 'ipv6', 'show', 'neighbors'],
            NETSH_OUTPUT, want_v6=True)
        assert len(entries) > 0

    def test_routes_ip(self):
        entries = parse_command_output(
            ['ip', '-4', 'neigh', 'show'],
            LINUX_IPV4_NEIGH, want_v6=False)
        assert len(entries) > 0

    def test_routes_ndp(self):
        entries = parse_command_output(['ndp', '-an'], MACOS_NDP_OUTPUT, want_v6=True)
        assert len(entries) > 0

    def test_routes_macos_arp(self):
        with patch('lanscape.core.neighbor_table._get_platform', return_value='macos'):
            entries = parse_command_output(['arp', '-an'], MACOS_ARP_OUTPUT, want_v6=False)
        assert len(entries) > 0

    def test_unknown_command(self):
        entries = parse_command_output(['unknown_cmd'], 'some output', want_v6=False)
        assert not entries


# ═══════════════════════════════════════════════════════════════════
#  Service lifecycle tests
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def reset_service():
    """Reset the singleton between tests."""
    NeighborTableService._reset_instance()
    yield
    NeighborTableService._reset_instance()


class TestNeighborTableServiceLifecycle:
    """Tests for NeighborTableService start/stop/singleton."""

    def test_singleton(self):
        svc1 = NeighborTableService.instance()
        svc2 = NeighborTableService.instance()
        assert svc1 is svc2

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_start_stop(self, mock_check):
        mock_check.return_value = b''
        svc = NeighborTableService.instance()
        svc.start(refresh_interval=0.5)
        assert svc.is_running
        svc.stop()
        assert not svc.is_running

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_double_start_no_error(self, mock_check):
        mock_check.return_value = b''
        svc = NeighborTableService.instance()
        svc.start(refresh_interval=0.5)
        svc.start(refresh_interval=0.5)  # should not raise
        assert svc.is_running
        svc.stop()

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_start_updates_config_when_running(self, mock_check):
        """Calling start() with new config while running should update the config."""
        mock_check.return_value = b''
        svc = NeighborTableService.instance()
        svc.start(refresh_interval=2.0, command_timeout=5.0)
        assert svc._refresh_interval == 2.0
        assert svc._command_timeout == 5.0
        # Update config while running
        svc.start(refresh_interval=10.0, command_timeout=8.0)
        assert svc.is_running
        assert svc._refresh_interval == 10.0
        assert svc._command_timeout == 8.0
        svc.stop()

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_wait_for_refresh(self, mock_check):
        mock_check.return_value = LINUX_IPV4_NEIGH.encode()
        svc = NeighborTableService.instance()
        svc.start(refresh_interval=0.3)
        try:
            result = svc.wait_for_refresh(timeout=3.0)
            assert result is True
        finally:
            svc.stop()

    def test_wait_for_refresh_not_running(self):
        svc = NeighborTableService.instance()
        assert svc.wait_for_refresh(timeout=0.1) is False

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_get_macs_wait_instant_hit(self, mock_check):
        """get_macs_wait returns immediately when IP is already cached."""
        mock_check.return_value = LINUX_IPV4_NEIGH.encode()
        with patch('lanscape.core.neighbor_table.get_table_commands') as mock_cmds:
            mock_cmds.return_value = [['ip', '-4', 'neigh', 'show']]
            svc = NeighborTableService.instance()
            svc.start(refresh_interval=10.0)
            try:
                import time
                t0 = time.monotonic()
                macs = svc.get_macs_wait('192.168.1.1')
                elapsed = time.monotonic() - t0
                assert macs == ['aa:bb:cc:dd:ee:ff']
                assert elapsed < 1.0, f"Should be instant, took {elapsed:.2f}s"
            finally:
                svc.stop()

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_get_macs_wait_waits_one_cycle(self, mock_check):
        """get_macs_wait waits for a new refresh start+finish when IP is not cached."""
        mock_check.return_value = LINUX_IPV4_NEIGH.encode()
        with patch('lanscape.core.neighbor_table.get_table_commands') as mock_cmds:
            mock_cmds.return_value = [['ip', '-4', 'neigh', 'show']]
            svc = NeighborTableService.instance()
            svc.start(refresh_interval=0.5)
            try:
                # IP not in the test data — will wait one cycle then return empty
                macs = svc.get_macs_wait('10.99.99.99')
                assert macs == []
            finally:
                svc.stop()

    def test_get_macs_wait_not_running(self):
        """get_macs_wait returns empty list when service is not running."""
        svc = NeighborTableService.instance()
        macs = svc.get_macs_wait('192.168.1.1')
        assert macs == []

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_get_mac_after_start(self, mock_check):
        mock_check.return_value = LINUX_IPV4_NEIGH.encode()
        with patch('lanscape.core.neighbor_table.get_table_commands') as mock_cmds:
            mock_cmds.return_value = [['ip', '-4', 'neigh', 'show']]
            svc = NeighborTableService.instance()
            svc.start(refresh_interval=10.0)
            try:
                mac = svc.get_mac('192.168.1.1')
                assert mac == 'aa:bb:cc:dd:ee:ff'
            finally:
                svc.stop()

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_get_ips_for_mac(self, mock_check):
        mock_check.return_value = LINUX_IPV6_NEIGH.encode()
        with patch('lanscape.core.neighbor_table.get_table_commands') as mock_cmds:
            mock_cmds.return_value = [['ip', '-6', 'neigh', 'show']]
            svc = NeighborTableService.instance()
            svc.start(refresh_interval=10.0)
            try:
                ips = svc.get_ips_for_mac('aa:bb:cc:dd:ee:ff', want_v6=True)
                assert 'fe80::1' in ips
            finally:
                svc.stop()

    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_command_fallback(self, mock_check):
        """If first command fails, second should be tried."""
        call_count = 0
        def side_effect(cmd, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise subprocess.CalledProcessError(1, cmd)
            return NETSH_OUTPUT.encode()

        mock_check.side_effect = side_effect
        with patch('lanscape.core.neighbor_table.get_table_commands') as mock_cmds:
            mock_cmds.return_value = [
                ['powershell', '-NoProfile', '-Command', 'Get-NetNeighbor'],
                ['netsh', 'interface', 'ipv6', 'show', 'neighbors'],
            ]
            svc = NeighborTableService.instance()
            svc.start(refresh_interval=10.0)
            try:
                table = svc.get_table(want_v6=True)
                assert table.has_entry('fe80::ee71:dbff:fea0:dd01')
            finally:
                svc.stop()


# ═══════════════════════════════════════════════════════════════════
#  Live integration tests
# ═══════════════════════════════════════════════════════════════════

class TestSingleArpMacRegex:
    """Unit tests for _SINGLE_ARP_MAC_RE — the regex used by query_single_arp_entry.

    macOS arp(8) omits leading zeros per octet (e.g. ``6:94:e6:c8:e4:22``),
    so the regex must accept 1–2 hex digits per octet.
    """

    def test_standard_full_octets(self):
        """Matches a standard two-digit-per-octet MAC."""
        m = _SINGLE_ARP_MAC_RE.search("? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0")
        assert m is not None
        assert m.group(1) == 'aa:bb:cc:dd:ee:ff'

    def test_macos_single_digit_leading_octet(self):
        """Matches macOS output where the first octet has no leading zero."""
        line = "? (192.168.64.1) at 6:94:e6:c8:e4:22 on feth2275 ifscope [ethernet]"
        m = _SINGLE_ARP_MAC_RE.search(line)
        assert m is not None
        assert m.group(1) == '6:94:e6:c8:e4:22'

    def test_macos_multiple_short_octets(self):
        """Matches when several octets have only one hex digit."""
        line = "? (10.1.1.1) at 0:c:29:ab:cd:ef on en0 [ethernet]"
        m = _SINGLE_ARP_MAC_RE.search(line)
        assert m is not None
        assert m.group(1) == '0:c:29:ab:cd:ef'

    def test_windows_dash_separated(self):
        """Matches Windows-style dash-separated MAC."""
        line = "  10.0.0.1              00-1b-21-38-a9-64     dynamic"
        m = _SINGLE_ARP_MAC_RE.search(line)
        assert m is not None

    def test_no_match_for_incomplete(self):
        """Does not match '(incomplete)' entries."""
        line = "? (10.0.0.2) at (incomplete) on en0"
        assert _SINGLE_ARP_MAC_RE.search(line) is None


class TestLiveWindowsArpTable:
    """Live tests against the actual Windows ARP table."""

    @pytest.mark.skipif(not psutil.WINDOWS, reason="Windows only")
    def test_live_arp_a_parses(self):
        """arp -a on this Windows machine should return parseable entries."""
        output = subprocess.check_output(
            ['arp', '-a'], shell=False, timeout=5
        ).decode(errors='replace')
        entries = parse_windows_arp(output)
        assert len(entries) > 0, "Expected at least one ARP entry on local machine"

    @pytest.mark.skipif(not psutil.WINDOWS, reason="Windows only")
    def test_live_powershell_ipv6_parses(self):
        """Get-NetNeighbor on this Windows machine should return parseable entries."""
        try:
            output = subprocess.check_output(
                ['powershell', '-NoProfile', '-Command',
                 'Get-NetNeighbor -AddressFamily IPv6 | ConvertTo-Csv -NoTypeInformation'],
                shell=False, timeout=10,
            ).decode(errors='replace')
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("PowerShell not available or command failed")
        entries = parse_powershell_neighbor(output, ip_version=6)
        assert len(entries) > 0, "Expected at least one IPv6 neighbor on local machine"

    @pytest.mark.skipif(not psutil.WINDOWS, reason="Windows only")
    def test_live_service_resolves_something(self):
        """Start the service and verify it finds at least one entry."""
        svc = NeighborTableService.instance()
        svc.start(refresh_interval=10.0, command_timeout=10.0)
        try:
            v4_table = svc.get_table(want_v6=False)
            assert len(v4_table.entries) > 0, \
                "Service should find at least one IPv4 neighbor"
        finally:
            svc.stop()


# ═══════════════════════════════════════════════════════════════════
#  End-to-end: full pipeline with mocked subprocess
# ═══════════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    """Test the full service pipeline with mocked OS commands."""

    @patch('lanscape.core.neighbor_table.get_table_commands')
    @patch('lanscape.core.neighbor_table.subprocess.check_output')
    def test_full_ipv4_ipv6_pipeline(self, mock_check, mock_cmds):
        """Service fetches both tables and lookups work end-to-end."""
        def commands_side_effect(want_v6):
            if want_v6:
                return [['ip', '-6', 'neigh', 'show']]
            return [['ip', '-4', 'neigh', 'show']]

        def check_side_effect(cmd, **_kwargs):
            if '-6' in cmd:
                return LINUX_IPV6_NEIGH.encode()
            return LINUX_IPV4_NEIGH.encode()

        mock_cmds.side_effect = commands_side_effect
        mock_check.side_effect = check_side_effect

        svc = NeighborTableService.instance()
        svc.start(refresh_interval=10.0)
        try:
            # IPv4 lookups
            assert svc.get_mac('192.168.1.1') == 'aa:bb:cc:dd:ee:ff'
            assert svc.get_mac('192.168.1.2') == '11:22:33:44:55:66'

            # IPv6 lookups
            assert svc.get_mac('fe80::1') == 'aa:bb:cc:dd:ee:ff'
            assert svc.get_mac('2001:db8::100') == '11:22:33:44:55:66'

            # Reverse: MAC → IPs
            v4_ips = svc.get_ips_for_mac('aa:bb:cc:dd:ee:ff', want_v6=False)
            assert '192.168.1.1' in v4_ips
            v6_ips = svc.get_ips_for_mac('aa:bb:cc:dd:ee:ff', want_v6=True)
            assert 'fe80::1' in v6_ips

            # Missing entry
            assert svc.get_mac('8.8.8.8') is None
        finally:
            svc.stop()


# ═══════════════════════════════════════════════════════════════════
#  Live ARP query — default gateway MAC resolution
# ═══════════════════════════════════════════════════════════════════

def _get_default_gateway_ip() -> str | None:
    """Return the default gateway IPv4 address using the OS routing table.

    Works on Windows (``route print``), Linux (``ip route``), and macOS
    (``netstat -rn``).  Returns ``None`` if the gateway cannot be determined.
    """
    try:
        if psutil.WINDOWS:
            out = subprocess.check_output(
                ['route', 'print', '0.0.0.0'], text=True, timeout=5,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    return parts[2]
        elif psutil.LINUX:
            out = subprocess.check_output(
                ['ip', 'route', 'show', 'default'], text=True, timeout=5,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if 'default via' in line:
                    return line.split('via')[1].split()[0]
        else:
            # macOS / BSD
            out = subprocess.check_output(
                ['netstat', '-rn'], text=True, timeout=5,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0] in ('default', '0.0.0.0/0'):
                    return parts[1]
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
        pass
    return None


class TestLiveArpQuerySingleEntry:
    """Live integration tests for query_single_arp_entry().

    Mirrors the ARP-cache lookup that ``ping_then_arp`` (ICMP_ARP_DISCOVERY)
    and ``poke_then_arp`` (POKE_ARP_DISCOVERY) stages perform: after a ping or
    TCP poke warms the OS ARP cache, the stage calls ``query_single_arp_entry``
    to retrieve the device's MAC address.

    The default gateway is used as a known-reachable IPv4 target — it is
    virtually guaranteed to be present in the ARP cache on any connected host.
    """

    def test_default_gateway_mac_resolves(self):
        """query_single_arp_entry returns a valid MAC for the default gateway."""
        gateway_ip = _get_default_gateway_ip()
        if not gateway_ip:
            pytest.skip("Could not determine default gateway — skipping live ARP test")

        # Warm the ARP cache the same way ping_then_arp / poke_then_arp do:
        # send an ICMP echo so the OS records the gateway's MAC.
        ping_cmd = (
            ['ping', '-n', '1', '-w', '1000', gateway_ip]
            if psutil.WINDOWS
            else ['ping', '-c', '1', '-W', '1', gateway_ip]
        )
        subprocess.run(ping_cmd, timeout=5, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)

        mac = query_single_arp_entry(gateway_ip)

        assert mac is not None, (
            f"Expected a MAC for default gateway {gateway_ip!r} but got None. "
            "ARP cache may be empty or the gateway did not respond."
        )
        # Must look like a colon-separated MAC
        parts = mac.split(':')
        assert len(parts) == 6, f"MAC {mac!r} does not have 6 octets"
        assert all(len(p) == 2 for p in parts), f"MAC {mac!r} has malformed octets"
        # Must not be a null or broadcast address
        assert mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'), (
            f"MAC {mac!r} is invalid (null or broadcast)"
        )
