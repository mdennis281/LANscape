"""Tests for IPv6 stage implementations (NDP and mDNS discovery).

Covers IPv6NDPDiscoveryStage neighbor entry filtering/harvest
and IPv6MDNSDiscoveryStage subnet filtering.
"""
# pylint: disable=protected-access

from unittest.mock import patch, MagicMock

from lanscape.core.scan_context import ScanContext
from lanscape.core.stages.ipv6_discovery import IPv6NDPDiscoveryStage, IPv6MDNSDiscoveryStage
from lanscape.core.scan_config import IPv6NDPDiscoveryStageConfig, IPv6MDNSDiscoveryStageConfig
from lanscape.core.neighbor_table import NeighborEntry, NeighborTable


# ---------------------------------------------------------------------------
# IPv6 NDP Discovery Stage – filtering & harvest
# ---------------------------------------------------------------------------

class TestIPv6NDPFiltering:
    """Tests for IPv6NDPDiscoveryStage neighbor entry filtering."""

    @staticmethod
    def _make_entry(ip: str, mac: str = "aa:bb:cc:dd:ee:ff") -> NeighborEntry:
        return NeighborEntry(ip=ip, mac=mac, ip_version=6)

    @staticmethod
    def _make_table(entries: dict) -> NeighborTable:
        return NeighborTable(entries=entries)

    @staticmethod
    def _make_stage(subnet_hint: str | None = None):
        cfg = IPv6NDPDiscoveryStageConfig(t_cnt=2)
        stage = IPv6NDPDiscoveryStage(cfg, subnet_hint=subnet_hint)
        # Ensure neighbor service is mocked
        mock_svc = MagicMock()
        stage._neighbor_svc = mock_svc
        return stage, mock_svc

    def test_filters_multicast_addresses(self):
        """Multicast addresses (ff00::/8) are excluded."""
        stage, mock_svc = self._make_stage("2601:2c5:4000:20e9::/64")
        table = self._make_table({
            "ff02::1": self._make_entry("ff02::1"),
            "ff05::1:3": self._make_entry("ff05::1:3"),
            "ff0e::1": self._make_entry("ff0e::1"),
            "2601:2c5:4000:20e9::1000": self._make_entry("2601:2c5:4000:20e9::1000"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("2601:2c5:4000:20e9::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert "2601:2c5:4000:20e9::1000" in ips
        assert not any(ip.startswith("ff") for ip, _ in result)

    def test_filters_link_local_addresses(self):
        """Link-local addresses (fe80::/10) are excluded."""
        stage, mock_svc = self._make_stage("2601:2c5:4000:20e9::/64")
        table = self._make_table({
            "fe80::1%5": self._make_entry("fe80::1%5"),
            "fe80::abcd:1234": self._make_entry("fe80::abcd:1234"),
            "2601:2c5:4000:20e9::2000": self._make_entry("2601:2c5:4000:20e9::2000"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("2601:2c5:4000:20e9::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert "2601:2c5:4000:20e9::2000" in ips
        assert not any(ip.startswith("fe80") for ip, _ in result)

    def test_filters_loopback(self):
        """Loopback (::1) is excluded."""
        stage, mock_svc = self._make_stage("2601:2c5:4000:20e9::/64")
        table = self._make_table({
            "::1": self._make_entry("::1"),
            "2601:2c5:4000:20e9::1": self._make_entry("2601:2c5:4000:20e9::1"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("2601:2c5:4000:20e9::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert "2601:2c5:4000:20e9::1" in ips
        assert "::1" not in ips

    def test_filters_off_subnet(self):
        """Addresses outside the target subnet are excluded."""
        stage, mock_svc = self._make_stage("2601:2c5:4000:20e9::/64")
        table = self._make_table({
            "2601:2c5:4000:20e9::100": self._make_entry("2601:2c5:4000:20e9::100"),
            "2601:2c5:4000:aaaa::100": self._make_entry("2601:2c5:4000:aaaa::100"),
            "2001:db8::1": self._make_entry("2001:db8::1"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("2601:2c5:4000:20e9::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert ips == ["2601:2c5:4000:20e9::100"]

    def test_keeps_all_on_subnet_unicast(self):
        """All unicast on-subnet addresses are kept."""
        stage, mock_svc = self._make_stage("fd00::/64")
        on_subnet = {
            f"fd00::{i:x}": self._make_entry(f"fd00::{i:x}")
            for i in range(1, 6)
        }
        table = self._make_table(on_subnet)
        mock_svc.get_table.return_value = table
        ctx = ScanContext("fd00::/64")

        result = stage._filter_neighbor_entries(ctx)

        assert len(result) == 5

    def test_falls_back_to_context_subnet(self):
        """When no subnet_hint, uses context.subnet for filtering."""
        stage, mock_svc = self._make_stage(subnet_hint=None)
        table = self._make_table({
            "fd00::1": self._make_entry("fd00::1"),
            "fd00::2": self._make_entry("fd00::2"),
            "2001:db8::1": self._make_entry("2001:db8::1"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("fd00::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert len(ips) == 2
        assert "2001:db8::1" not in ips

    def test_skips_ipv4_entries(self):
        """IPv4 entries in the table are ignored."""
        stage, mock_svc = self._make_stage("fd00::/64")
        table = self._make_table({
            "192.168.1.1": self._make_entry("192.168.1.1"),
            "fd00::1": self._make_entry("fd00::1"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("fd00::/64")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert ips == ["fd00::1"]

    def test_no_subnet_no_hint_keeps_all_unicast(self):
        """Without subnet or hint, all unicast addresses pass."""
        stage, mock_svc = self._make_stage(subnet_hint=None)
        table = self._make_table({
            "2001:db8::1": self._make_entry("2001:db8::1"),
            "fd00::1": self._make_entry("fd00::1"),
            "ff02::1": self._make_entry("ff02::1"),
        })
        mock_svc.get_table.return_value = table
        # context with IPv4 subnet — no v6 filter possible
        ctx = ScanContext("10.0.0.0/24")

        result = stage._filter_neighbor_entries(ctx)

        ips = [ip for ip, _ in result]
        assert "2001:db8::1" in ips

    def test_harvest_adds_devices_to_context(self):
        """_harvest_ndp_devices resolves entries and adds to context."""
        stage, mock_svc = self._make_stage("fd00::/64")
        table = self._make_table({
            "fd00::1": self._make_entry("fd00::1", mac="aa:bb:cc:00:00:01"),
            "fd00::2": self._make_entry("fd00::2", mac="aa:bb:cc:00:00:02"),
        })
        mock_svc.get_table.return_value = table
        ctx = ScanContext("fd00::/64")
        stage.running = True

        with patch(
            'lanscape.core.stages.ipv6_discovery.Device'
        ) as mock_device_cls:
            mock_devs = []

            def _make_dev(ip):
                d = MagicMock()
                d.ip = ip
                d.alive = True
                mock_devs.append(d)
                return d

            mock_device_cls.side_effect = _make_dev

            stage._harvest_ndp_devices(ctx)

        assert len(ctx.devices) == 2
        assert stage.completed == 2

    def test_execute_sets_total_to_subnet_size(self):
        """execute() sets total to the subnet address count."""
        stage, mock_svc = self._make_stage("fd00::/120")
        table = self._make_table({
            "fd00::1": self._make_entry("fd00::1"),
        })
        mock_svc.get_table.return_value = table

        with patch.object(stage, '_detect_scopes', return_value=[]), \
             patch.object(stage, '_ping_multicast'), \
             patch('lanscape.core.stages.ipv6_discovery.Device') as mock_dev:
            mock_dev.side_effect = lambda ip: MagicMock(ip=ip, alive=True)
            ctx = ScanContext("fd00::/120")
            stage.run(ctx)

        # /120 = 256 addresses, minus 1 (network) for IPv6 = 255
        assert stage.total == 255

    def test_harvest_empty_table_no_error(self):
        """Harvest with no matching entries completes without error."""
        stage, mock_svc = self._make_stage("fd00::/64")
        table = self._make_table({})
        mock_svc.get_table.return_value = table
        ctx = ScanContext("fd00::/64")
        stage.running = True

        stage._harvest_ndp_devices(ctx)

        assert len(ctx.devices) == 0


# ---------------------------------------------------------------------------
# IPv6 mDNS Discovery Stage – subnet filtering
# ---------------------------------------------------------------------------

class TestIPv6MDNSSubnetFilter:
    """mDNS listener must only accept IPs within the target subnet."""

    @staticmethod
    def _run_listener_add(addr: str, subnet: str):
        """
        Directly invoke the inner _Listener.add_service logic via a minimal
        execute() run using a patched Zeroconf + ServiceBrowser.
        Returns the set of ip strings added to the context.
        """
        cfg = IPv6MDNSDiscoveryStageConfig(timeout=0.1)
        stage = IPv6MDNSDiscoveryStage(cfg)
        stage.running = True

        ctx = ScanContext(subnet)

        fake_info = MagicMock()
        fake_info.parsed_addresses.return_value = [addr]
        fake_info.server = None

        class FakeZeroconf:
            """Minimal Zeroconf stub for testing."""

            def get_service_info(self, *_):
                """Return the fake service info."""
                return fake_info

            def close(self):
                """No-op close."""

        class FakeServiceBrowser:
            """Minimal ServiceBrowser stub that fires add_service immediately."""

            def __init__(self, zc, svc_type, listener):
                """Trigger add_service for non-meta service types."""
                if svc_type == "_services._dns-sd._udp.local.":
                    return
                # Immediately fire add_service for the first registered type
                listener.add_service(zc, svc_type, "test._http._tcp.local.")

        with patch('lanscape.core.stages.ipv6_discovery.Zeroconf', FakeZeroconf), \
             patch('lanscape.core.stages.ipv6_discovery.ServiceBrowser', FakeServiceBrowser), \
             patch('lanscape.core.stages.ipv6_discovery.NeighborTableService') as mock_nts:
            mock_nts.instance.return_value = MagicMock(is_running=True)
            stage.execute(ctx)

        return {d.ip for d in ctx.devices}

    def test_on_subnet_address_accepted(self):
        """An address within the target subnet is accepted."""
        found = self._run_listener_add("fd00::1", "fd00::/64")
        assert "fd00::1" in found

    def test_off_subnet_address_rejected(self):
        """An address outside the target subnet is rejected."""
        found = self._run_listener_add("2001:db8::1", "fd00::/64")
        assert "2001:db8::1" not in found

    def test_link_local_rejected(self):
        """Link-local addresses are always rejected regardless of subnet."""
        found = self._run_listener_add("fe80::1", "fe80::/10")
        assert "fe80::1" not in found

    def test_multicast_rejected(self):
        """Multicast addresses are always rejected."""
        found = self._run_listener_add("ff02::1", "fd00::/64")
        assert "ff02::1" not in found
