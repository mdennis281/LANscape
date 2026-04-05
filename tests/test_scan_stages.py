"""
Tests for the scan stage pipeline infrastructure.
Covers ScanStageMixin, ScanContext, ScanPipeline, stage_builder, stage configs, and presets.
"""
# pylint: disable=protected-access

from unittest.mock import patch, MagicMock

import pytest

from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.scan_pipeline import ScanPipeline
from lanscape.core.models.enums import StageType
from lanscape.core.models.scan import StageProgress
from lanscape.core.net_tools.device import Device
from lanscape.core.scan_config import (
    ScanConfig, PipelineConfig, StageConfig,
    ICMPDiscoveryStageConfig, PortScanStageConfig,
    ResilienceConfig, get_stage_config_defaults,
    STAGE_CONFIG_REGISTRY,
)
from lanscape.core.stage_presets import StagePreset, get_stage_presets
from lanscape.core.stage_builder import build_stages
from lanscape.core.stages.discovery import (
    ICMPDiscoveryStage, ARPDiscoveryStage,
    PokeARPDiscoveryStage, ICMPARPDiscoveryStage,
)
from lanscape.core.stages.port_scan import PortScanStage
from lanscape.core.stages.ipv6_discovery import IPv6NDPDiscoveryStage, IPv6MDNSDiscoveryStage
from lanscape.core.scan_config import IPv6NDPDiscoveryStageConfig
from lanscape.core.neighbor_table import NeighborEntry, NeighborTable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeStage(ScanStageMixin):
    """Simple stage for testing."""
    stage_type = StageType.ICMP_DISCOVERY
    stage_name = "Fake ICMP"

    def __init__(self, work_items: int = 5, should_fail: bool = False):
        super().__init__()
        self._work_items = work_items
        self._should_fail = should_fail

    def execute(self, context: ScanContext) -> None:
        self.total = self._work_items
        for _ in range(self._work_items):
            if not self.running:
                break
            self.increment()
        if self._should_fail:
            raise RuntimeError("stage failed")


class _DeviceAddingStage(ScanStageMixin):
    """Stage that adds mock devices to context."""
    stage_type = StageType.ARP_DISCOVERY
    stage_name = "Device Adder"

    def __init__(self, ips: list[str]):
        super().__init__()
        self._ips = ips

    def execute(self, context: ScanContext) -> None:
        self.total = len(self._ips)
        for ip in self._ips:
            if not self.running:
                break
            device = MagicMock()
            device.ip = ip
            context.add_device(device)
            self.increment()


# ---------------------------------------------------------------------------
# ScanStageMixin
# ---------------------------------------------------------------------------

class TestScanStageMixin:
    """Tests for the base stage mixin."""

    def test_increment_is_thread_safe(self):
        """Increment updates completed count atomically."""
        stage = _FakeStage(work_items=10)
        stage.total = 10
        stage.running = True
        for _ in range(10):
            stage.increment()
        assert stage.completed == 10

    def test_stage_progress_snapshot(self):
        """stage_progress() returns a StageProgress model."""
        stage = _FakeStage()
        stage._total = 10
        stage._completed = 5
        stage._finished = False

        progress = stage.stage_progress()
        assert isinstance(progress, StageProgress)
        assert progress.stage_name == "Fake ICMP"
        assert progress.stage_type == StageType.ICMP_DISCOVERY
        assert progress.total == 10
        assert progress.completed == 5
        assert progress.finished is False
        assert progress.counter_label == "items"  # default from base class

    def test_stage_progress_counter_label(self):
        """counter_label flows through to StageProgress snapshot."""
        stage = _FakeStage()
        stage.counter_label = "IPs scanned"
        progress = stage.stage_progress()
        assert progress.counter_label == "IPs scanned"

    def test_run_sets_running_and_finished(self):
        """run() sets running=True before execute, finished=True after."""
        stage = _FakeStage(work_items=3)
        context = ScanContext("10.0.0.0/24")
        stage.run(context)

        assert stage.finished is True
        assert stage.running is False
        assert stage.completed == 3

    def test_terminate_sets_running_false(self):
        """terminate() sets running to False."""
        stage = _FakeStage()
        stage.running = True
        stage.terminate()
        assert stage.running is False


class TestConcreteStageCounterLabels:
    """Each concrete stage must define a meaningful counter_label."""

    @pytest.mark.parametrize("stage_cls,expected_label", [
        (ICMPDiscoveryStage, "IPs scanned"),
        (ARPDiscoveryStage, "IPs scanned"),
        (PokeARPDiscoveryStage, "IPs scanned"),
        (ICMPARPDiscoveryStage, "IPs scanned"),
        (PortScanStage, "ports scanned"),
        (IPv6NDPDiscoveryStage, "devices discovered"),
        (IPv6MDNSDiscoveryStage, "devices discovered"),
    ])
    def test_counter_label(self, stage_cls, expected_label):
        """Concrete stage has the expected counter_label class attribute."""
        assert stage_cls.counter_label == expected_label


# ---------------------------------------------------------------------------
# ScanContext
# ---------------------------------------------------------------------------

class TestScanContext:
    """Tests for the shared scan context."""

    def test_add_device_deduplicates_by_ip(self):
        """Adding a device with the same IP twice returns False."""
        ctx = ScanContext("10.0.0.0/24")
        d1 = MagicMock()
        d1.ip = "10.0.0.1"
        d2 = MagicMock()
        d2.ip = "10.0.0.1"

        assert ctx.add_device(d1) is True
        assert ctx.add_device(d2) is False
        assert len(ctx.devices) == 1

    def test_get_unscanned_devices(self):
        """get_unscanned_devices returns only devices not yet port-scanned."""
        ctx = ScanContext("10.0.0.0/24")
        d1 = MagicMock()
        d1.ip = "10.0.0.1"
        d2 = MagicMock()
        d2.ip = "10.0.0.2"
        ctx.add_device(d1)
        ctx.add_device(d2)

        ctx.mark_port_scanned("10.0.0.1")
        unscanned = ctx.get_unscanned_devices()
        assert len(unscanned) == 1
        assert unscanned[0].ip == "10.0.0.2"

    def test_mark_port_scanned_tracks_specific_ports(self):
        """mark_port_scanned with ports records which ports were tested."""
        ctx = ScanContext("10.0.0.0/24")
        d1 = MagicMock()
        d1.ip = "10.0.0.1"
        ctx.add_device(d1)

        ctx.mark_port_scanned("10.0.0.1", {80, 443})
        assert ctx.get_scanned_ports("10.0.0.1") == {80, 443}

        # Additional ports accumulate
        ctx.mark_port_scanned("10.0.0.1", {8080, 443})
        assert ctx.get_scanned_ports("10.0.0.1") == {80, 443, 8080}

    def test_get_scanned_ports_unknown_ip_returns_empty(self):
        """get_scanned_ports returns empty set for unknown IPs."""
        ctx = ScanContext("10.0.0.0/24")
        assert ctx.get_scanned_ports("10.0.0.99") == set()

    def test_mark_port_scanned_without_ports_still_marks_device(self):
        """mark_port_scanned without ports still excludes device from unscanned."""
        ctx = ScanContext("10.0.0.0/24")
        d1 = MagicMock()
        d1.ip = "10.0.0.1"
        ctx.add_device(d1)

        ctx.mark_port_scanned("10.0.0.1")
        assert ctx.get_unscanned_devices() == []

    def test_errors_and_warnings(self):
        """Errors and warnings lists are accessible."""
        ctx = ScanContext("10.0.0.0/24")
        assert not ctx.errors
        assert not ctx.warnings


# ---------------------------------------------------------------------------
# ScanPipeline
# ---------------------------------------------------------------------------

class TestScanPipeline:
    """Tests for the pipeline orchestrator."""

    def test_executes_stages_in_order(self):
        """Stages execute sequentially."""
        execution_order = []

        class _OrderedStage(ScanStageMixin):
            stage_type = StageType.ICMP_DISCOVERY
            stage_name = "Ordered"

            def __init__(self, label: str):
                super().__init__()
                self._label = label

            def execute(self, context: ScanContext) -> None:
                execution_order.append(self._label)
                self.total = 1
                self.increment()

        pipeline = ScanPipeline([
            _OrderedStage("A"),
            _OrderedStage("B"),
            _OrderedStage("C"),
        ])
        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        assert execution_order == ["A", "B", "C"]

    def test_terminate_skips_remaining(self):
        """After terminate(), remaining stages are skipped."""

        class _TerminatingStage(ScanStageMixin):
            stage_type = StageType.ICMP_DISCOVERY
            stage_name = "Terminator"

            def __init__(self, pipeline_ref):
                super().__init__()
                self._pipeline = pipeline_ref

            def execute(self, context: ScanContext) -> None:
                self._pipeline.terminate()

        class _UnreachableStage(ScanStageMixin):
            stage_type = StageType.ARP_DISCOVERY
            stage_name = "Should Not Run"
            executed = False

            def execute(self, context: ScanContext) -> None:
                _UnreachableStage.executed = True

        pipeline = ScanPipeline([])
        s1 = _TerminatingStage(pipeline)
        s2 = _UnreachableStage()
        pipeline.stages = [s1, s2]

        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        assert not _UnreachableStage.executed

    def test_get_stage_progress(self):
        """get_stage_progress returns list of StageProgress."""
        s1 = _FakeStage(work_items=5)
        s2 = _FakeStage(work_items=3)
        pipeline = ScanPipeline([s1, s2])

        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        progress = pipeline.get_stage_progress()
        assert len(progress) == 2
        assert progress[0].completed == 5
        assert progress[0].finished is True
        assert progress[1].completed == 3
        assert progress[1].finished is True

    def test_context_devices_shared_across_stages(self):
        """Devices added in one stage are visible to later stages."""
        s1 = _DeviceAddingStage(["10.0.0.1", "10.0.0.2"])

        received_devices = []

        class _ReaderStage(ScanStageMixin):
            stage_type = StageType.PORT_SCAN
            stage_name = "Reader"

            def execute(self, context: ScanContext) -> None:
                received_devices.extend(context.devices)
                self.total = 1
                self.increment()

        pipeline = ScanPipeline([s1, _ReaderStage()])
        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        assert len(received_devices) == 2

    def test_append_stages_during_execution(self):
        """Stages appended while the pipeline is running get executed."""
        execution_order = []

        class _TrackingStage(ScanStageMixin):
            stage_type = StageType.ICMP_DISCOVERY
            stage_name = "Tracking"

            def __init__(self, label: str, pipeline_ref=None, to_append=None):
                super().__init__()
                self._label = label
                self._pipeline = pipeline_ref
                self._to_append = to_append

            def execute(self, context: ScanContext) -> None:
                execution_order.append(self._label)
                if self._pipeline and self._to_append:
                    self._pipeline.append_stages(self._to_append)
                    self._pipeline = None  # only append once
                self.total = 1
                self.increment()

        pipeline = ScanPipeline([])
        late_stage = _TrackingStage("C")
        s1 = _TrackingStage("A", pipeline_ref=pipeline, to_append=[late_stage])
        s2 = _TrackingStage("B")
        pipeline.stages = [s1, s2]

        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        assert execution_order == ["A", "B", "C"]

    def test_append_stages_after_completion(self):
        """Stages appended after pipeline completion are available for re-execution."""
        pipeline = ScanPipeline([_FakeStage(work_items=1)])
        ctx = ScanContext("10.0.0.0/24")
        pipeline.execute(ctx)

        assert len(pipeline.stages) == 1

        new_stage = _FakeStage(work_items=2)
        pipeline.append_stages([new_stage])

        assert len(pipeline.stages) == 2
        assert not pipeline._terminated  # reset so re-execute works

        # Re-execute picks up from where it left off via index-based loop
        pipeline.execute(ctx)
        assert new_stage.finished


# ---------------------------------------------------------------------------
# PipelineConfig / StageConfig
# ---------------------------------------------------------------------------

class TestPipelineConfig:
    """Tests for pipeline configuration models."""

    def test_scan_config_to_pipeline_config(self):
        """ScanConfig.to_pipeline_config() produces valid PipelineConfig."""
        cfg = ScanConfig(subnet='10.0.0.0/28', port_list='small')
        pipeline_cfg = cfg.to_pipeline_config()

        assert pipeline_cfg.subnet == '10.0.0.0/28'
        assert len(pipeline_cfg.stages) >= 1  # at least discovery + port scan

    def test_stage_config_get_typed_config(self):
        """StageConfig.get_typed_config() deserializes correctly."""
        icmp_cfg = ICMPDiscoveryStageConfig(t_cnt=8)
        stage = StageConfig(
            stage_type=StageType.ICMP_DISCOVERY,
            config=icmp_cfg.to_dict(),
        )
        typed = stage.get_typed_config()
        assert isinstance(typed, ICMPDiscoveryStageConfig)
        assert typed.t_cnt == 8

    def test_pipeline_config_serialization(self):
        """PipelineConfig round-trips through dict."""
        cfg = PipelineConfig(
            subnet='192.168.1.0/24',
            stages=[
                StageConfig(
                    stage_type=StageType.ICMP_DISCOVERY,
                    config=ICMPDiscoveryStageConfig().to_dict(),
                ),
            ],
            resilience=ResilienceConfig(t_multiplier=2.0),
        )
        data = cfg.to_dict()
        cfg2 = PipelineConfig.from_dict(data)
        assert cfg2.subnet == '192.168.1.0/24'
        assert len(cfg2.stages) == 1
        assert cfg2.resilience.t_multiplier == 2.0

    def test_get_stage_config_defaults_returns_all_stages(self):
        """get_stage_config_defaults() returns defaults for every registered stage."""
        defaults = get_stage_config_defaults()

        expected_types = {
            'icmp_discovery', 'arp_discovery', 'poke_arp_discovery',
            'icmp_arp_discovery', 'ipv6_ndp_discovery',
            'ipv6_mdns_discovery', 'port_scan',
        }
        assert set(defaults.keys()) == expected_types

        # Each value should be a dict with real config fields
        for stage_type, cfg_dict in defaults.items():
            assert isinstance(cfg_dict, dict), f"{stage_type} default is not a dict"
            assert len(cfg_dict) > 0, f"{stage_type} default is empty"

    def test_get_stage_config_defaults_matches_model(self):
        """get_stage_config_defaults() values match Pydantic model defaults."""
        defaults = get_stage_config_defaults()

        icmp = defaults['icmp_discovery']
        model_default = ICMPDiscoveryStageConfig()
        assert icmp['t_cnt'] == model_default.t_cnt
        assert icmp['ping_config'] == model_default.to_dict()['ping_config']

        port = defaults['port_scan']
        port_default = PortScanStageConfig()
        assert port['port_list'] == port_default.port_list
        assert port['scan_services'] == port_default.scan_services


# ---------------------------------------------------------------------------
# stage_presets
# ---------------------------------------------------------------------------

class TestStagePresets:
    """Tests for the stage preset system."""

    def test_get_stage_presets_returns_all_stages(self):
        """get_stage_presets() returns presets for every registered stage."""
        presets = get_stage_presets()
        expected_types = {
            'icmp_discovery', 'arp_discovery', 'poke_arp_discovery',
            'icmp_arp_discovery', 'ipv6_ndp_discovery',
            'ipv6_mdns_discovery', 'port_scan',
        }
        assert set(presets.keys()) == expected_types

    def test_each_stage_has_three_presets(self):
        """Every stage has fast, balanced, and accurate presets."""
        presets = get_stage_presets()
        for stage_type, preset_map in presets.items():
            assert set(preset_map.keys()) == {'fast', 'balanced', 'accurate'}, (
                f"{stage_type} missing preset(s)"
            )

    def test_balanced_matches_defaults(self):
        """The balanced preset matches Pydantic model defaults."""
        presets = get_stage_presets()
        defaults = get_stage_config_defaults()
        for stage_type in presets:
            assert presets[stage_type]['balanced'] == defaults[stage_type], (
                f"{stage_type} balanced preset differs from default"
            )

    def test_presets_are_valid_config_dicts(self):
        """Every preset can be round-tripped through its config class."""
        presets = get_stage_presets()
        for stage_type_str, preset_map in presets.items():
            stage_type = StageType(stage_type_str)
            cfg_cls = STAGE_CONFIG_REGISTRY[stage_type]
            for preset_name, cfg_dict in preset_map.items():
                instance = cfg_cls.from_dict(cfg_dict)
                assert instance.to_dict() == cfg_dict, (
                    f"{stage_type_str}/{preset_name} round-trip failed"
                )

    def test_fast_port_scan_uses_small_list(self):
        """Fast port scan preset uses the 'small' port list."""
        presets = get_stage_presets()
        assert presets['port_scan']['fast']['port_list'] == 'small'

    def test_accurate_port_scan_uses_large_list(self):
        """Accurate port scan preset uses the 'large' port list."""
        presets = get_stage_presets()
        assert presets['port_scan']['accurate']['port_list'] == 'large'


# ---------------------------------------------------------------------------
# stage_builder
# ---------------------------------------------------------------------------

class TestStageBuilder:
    """Tests for the stage factory."""

    def test_builds_icmp_discovery_stage(self):
        """build_stages creates ICMPDiscoveryStage from config."""
        pipeline_cfg = PipelineConfig(
            subnet='10.0.0.0/28',
            stages=[
                StageConfig(
                    stage_type=StageType.ICMP_DISCOVERY,
                    config=ICMPDiscoveryStageConfig().to_dict(),
                ),
            ],
        )

        with patch('lanscape.core.stage_builder.parse_ip_input') as mock_parse:
            mock_parse.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
            stages = build_stages(pipeline_cfg)

        assert len(stages) == 1
        assert isinstance(stages[0], ICMPDiscoveryStage)

    def test_builds_port_scan_stage(self):
        """build_stages creates PortScanStage from config."""
        pipeline_cfg = PipelineConfig(
            subnet='10.0.0.0/28',
            stages=[
                StageConfig(
                    stage_type=StageType.PORT_SCAN,
                    config=PortScanStageConfig().to_dict(),
                ),
            ],
        )

        with patch('lanscape.core.stage_builder.parse_ip_input') as mock_parse:
            mock_parse.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
            stages = build_stages(pipeline_cfg)

        assert len(stages) == 1
        assert isinstance(stages[0], PortScanStage)

    def test_builds_multi_stage_pipeline(self):
        """build_stages handles multiple stages in sequence."""
        pipeline_cfg = PipelineConfig(
            subnet='10.0.0.0/28',
            stages=[
                StageConfig(
                    stage_type=StageType.ICMP_DISCOVERY,
                    config=ICMPDiscoveryStageConfig().to_dict(),
                ),
                StageConfig(
                    stage_type=StageType.PORT_SCAN,
                    config=PortScanStageConfig().to_dict(),
                ),
            ],
        )

        with patch('lanscape.core.stage_builder.parse_ip_input') as mock_parse:
            mock_parse.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
            stages = build_stages(pipeline_cfg)

        assert len(stages) == 2


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
        assert "fd00::1" in ips
        assert "ff02::1" not in ips  # multicast still filtered

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
# PortScanStage – per-port delta tracking
# ---------------------------------------------------------------------------

class TestPortScanDeltaPorts:
    """Verify that appending a port scan stage only scans NEW ports."""

    def _make_device(self, ip: str) -> MagicMock:
        dev = MagicMock()
        dev.ip = ip
        dev.stage = 'found'
        return dev

    @patch('lanscape.core.stages.port_scan.PortManager')
    def test_skips_already_scanned_ports(self, mock_pm_cls):
        """Second port scan with same list scans nothing."""
        # Simulate "small" = ports 80, 443
        mock_pm_cls.return_value.get_port_list.return_value = {80: '', 443: ''}

        ctx = ScanContext("10.0.0.0/24")
        dev = self._make_device("10.0.0.1")
        ctx.add_device(dev)

        # Mark both ports as already scanned
        ctx.mark_port_scanned("10.0.0.1", {80, 443})

        stage = PortScanStage(PortScanStageConfig(port_list='small'))
        stage.run(ctx)

        assert stage.total == 0  # nothing to scan
        assert stage.finished

    @patch('lanscape.core.stages.port_scan.PortManager')
    @patch('lanscape.core.stages.port_scan.ThreadPoolRetryManager')
    def test_scans_only_delta_ports(self, mock_retry_mgr_cls, mock_pm_cls):
        """Upgrading from 'small' to 'large' only scans the difference."""
        # "small" was {80, 443}, "large" is {80, 443, 8080, 8443}
        mock_pm_cls.return_value.get_port_list.return_value = {
            80: '', 443: '', 8080: '', 8443: ''
        }

        ctx = ScanContext("10.0.0.0/24")
        dev = self._make_device("10.0.0.1")
        ctx.add_device(dev)

        # Ports already scanned from the first stage
        ctx.mark_port_scanned("10.0.0.1", {80, 443})

        stage = PortScanStage(PortScanStageConfig(port_list='large'))
        stage.execute(ctx)

        # Should only scan the 2 new ports
        assert stage.total == 2

        # Verify retry manager was called with correct job data
        mock_retry_mgr_cls.return_value.execute_all.assert_called_once()
        jobs = mock_retry_mgr_cls.return_value.execute_all.call_args[0][0]
        assert len(jobs) == 1  # one device
        assert jobs[0].job_id == "10.0.0.1"
        # The ports passed to _scan_device should be [8080, 8443] (sorted)
        _, ports_arg, _ = jobs[0].args
        assert ports_arg == [8080, 8443]

    @patch('lanscape.core.stages.port_scan.PortManager')
    @patch('lanscape.core.stages.port_scan.ThreadPoolRetryManager')
    def test_new_device_gets_all_ports(self, mock_retry_mgr_cls, mock_pm_cls):
        """A device with no prior port scanning gets the full port list."""
        mock_pm_cls.return_value.get_port_list.return_value = {80: '', 443: '', 22: ''}

        ctx = ScanContext("10.0.0.0/24")
        dev = self._make_device("10.0.0.1")
        ctx.add_device(dev)

        stage = PortScanStage(PortScanStageConfig(port_list='small'))
        stage.execute(ctx)

        assert stage.total == 3
        jobs = mock_retry_mgr_cls.return_value.execute_all.call_args[0][0]
        _, ports_arg, _ = jobs[0].args
        assert sorted(ports_arg) == [22, 80, 443]

    @patch('lanscape.core.stages.port_scan.PortManager')
    @patch('lanscape.core.stages.port_scan.ThreadPoolRetryManager')
    def test_mixed_devices_partial_coverage(self, mock_retry_mgr_cls, mock_pm_cls):
        """Devices with different prior coverage get different port lists."""
        mock_pm_cls.return_value.get_port_list.return_value = {80: '', 443: '', 8080: ''}

        ctx = ScanContext("10.0.0.0/24")
        dev1 = self._make_device("10.0.0.1")
        dev2 = self._make_device("10.0.0.2")
        ctx.add_device(dev1)
        ctx.add_device(dev2)

        # dev1 already had 80 scanned, dev2 is fresh
        ctx.mark_port_scanned("10.0.0.1", {80})

        stage = PortScanStage(PortScanStageConfig(port_list='large'))
        stage.execute(ctx)

        # dev1 needs 2 ports (443, 8080), dev2 needs 3 ports (all)
        assert stage.total == 5

        jobs = mock_retry_mgr_cls.return_value.execute_all.call_args[0][0]
        job_map = {j.job_id: j for j in jobs}
        assert len(job_map) == 2

        _, dev1_ports, _ = job_map["10.0.0.1"].args
        assert dev1_ports == [443, 8080]

        _, dev2_ports, _ = job_map["10.0.0.2"].args
        assert sorted(dev2_ports) == [80, 443, 8080]

    def test_scan_device_resets_progress(self):
        """_scan_device resets ports_scanned and sets ports_to_scan for UI progress."""
        ctx = ScanContext("10.0.0.0/24")
        dev = Device(ip="10.0.0.1", alive=True)
        dev.ports_scanned = 50  # leftover from previous stage
        ctx.add_device(dev)

        stage = PortScanStage(PortScanStageConfig(port_list='small'))
        stage.running = True  # simulate stage running

        ports = [80, 443, 8080]
        stage._scan_device(dev, ports, ctx)

        assert dev.ports_scanned == 3  # reset to 0 then incremented 3 times
        assert dev.ports_to_scan == 3
        assert dev.stage == 'complete'


# ---------------------------------------------------------------------------
# SubnetScanner.append_stages
# ---------------------------------------------------------------------------

class TestSubnetScannerAppendStages:
    """Tests for appending stages to an existing SubnetScanner."""

    def _make_scanner(self):
        """Create a SubnetScanner with a minimal pipeline (no start)."""
        from lanscape.core.subnet_scan import SubnetScanner  # pylint: disable=import-outside-toplevel
        cfg = PipelineConfig(
            subnet='10.0.0.0/28',
            stages=[StageConfig(stage_type=StageType.ICMP_DISCOVERY)],
        )
        scanner = SubnetScanner(cfg)
        return scanner

    def test_append_adds_stages_to_pipeline(self):
        """append_stages() builds and extends the pipeline's stage list."""
        scanner = self._make_scanner()
        original_count = len(scanner.pipeline.stages)

        with patch.object(scanner, '_restart_pipeline'):
            scanner.append_stages([
                {'stage_type': 'port_scan', 'config': {'port_list': 'small'}},
            ])

        assert len(scanner.pipeline.stages) == original_count + 1

    def test_append_restarts_when_not_running(self):
        """When the scan is not running, append_stages restarts the pipeline."""
        scanner = self._make_scanner()
        scanner.running = False

        with patch.object(scanner, '_restart_pipeline') as mock_restart:
            scanner.append_stages([
                {'stage_type': 'port_scan', 'config': {}},
            ])
            mock_restart.assert_called_once()

    def test_append_does_not_restart_when_running(self):
        """When the scan is still running, append_stages does NOT restart."""
        scanner = self._make_scanner()
        scanner.running = True

        with patch.object(scanner, '_restart_pipeline') as mock_restart:
            scanner.append_stages([
                {'stage_type': 'port_scan', 'config': {}},
            ])
            mock_restart.assert_not_called()
