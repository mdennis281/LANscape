"""
Tests for the scan stage skip-guard system.

Covers StageEvalContext construction, per-stage can_execute guards,
pipeline skip flow, and StageProgress serialization of skipped state.
"""
# pylint: disable=protected-access

from unittest.mock import patch

from lanscape.core.models.enums import StageType
from lanscape.core.models.scan import StageEvalContext, StageProgress
from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.scan_pipeline import ScanPipeline
from lanscape.core.stages.discovery import (
    ICMPDiscoveryStage,
    ARPDiscoveryStage,
    PokeARPDiscoveryStage,
    ICMPARPDiscoveryStage,
)
from lanscape.core.stages.ipv6_discovery import (
    IPv6NDPDiscoveryStage,
    IPv6MDNSDiscoveryStage,
)
from lanscape.core.stages.port_scan import PortScanStage
from lanscape.core.scan_config import (
    ICMPDiscoveryStageConfig,
    ARPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
    ICMPARPDiscoveryStageConfig,
    IPv6NDPDiscoveryStageConfig,
    IPv6MDNSDiscoveryStageConfig,
    PortScanStageConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ipv4_local_ctx(arp: bool = True) -> StageEvalContext:
    """Context for a local IPv4 subnet."""
    return StageEvalContext(
        subnet="192.168.1.0/24",
        is_ipv6=False,
        is_local=True,
        matching_interface="eth0",
        arp_supported=arp,
        os_platform="windows",
    )


def _ipv4_remote_ctx(arp: bool = True) -> StageEvalContext:
    """Context for a remote (non-local) IPv4 subnet."""
    return StageEvalContext(
        subnet="10.99.0.0/16",
        is_ipv6=False,
        is_local=False,
        matching_interface=None,
        arp_supported=arp,
        os_platform="linux",
    )


def _ipv6_ctx() -> StageEvalContext:
    """Context for an IPv6 subnet."""
    return StageEvalContext(
        subnet="2001:db8::/64",
        is_ipv6=True,
        is_local=True,
        matching_interface="eth0",
        arp_supported=False,
        os_platform="linux",
    )


class _DummyStage(ScanStageMixin):
    """Minimal concrete stage for pipeline tests."""
    stage_type = StageType.ICMP_DISCOVERY
    stage_name = "Dummy"

    def __init__(self, skip_reason: str | None = None):
        super().__init__()
        self._skip_reason_value = skip_reason

    def can_execute(self, _eval_ctx: StageEvalContext) -> str | None:
        return self._skip_reason_value

    def execute(self, context: ScanContext) -> None:
        self.total = 1
        self.increment()


# ---------------------------------------------------------------------------
# StageEvalContext
# ---------------------------------------------------------------------------

class TestStageEvalContext:
    """Tests for StageEvalContext model and build factory."""

    def test_manual_construction(self):
        """Direct construction sets all fields."""
        ctx = _ipv4_local_ctx()
        assert ctx.subnet == "192.168.1.0/24"
        assert ctx.is_ipv6 is False
        assert ctx.is_local is True
        assert ctx.arp_supported is True
        assert ctx.os_platform == "windows"

    @patch("lanscape.core.net_tools.subnet_utils.is_ipv6_subnet", return_value=False)
    @patch("lanscape.core.net_tools.subnet_utils.is_local_subnet", return_value=True)
    @patch("lanscape.core.net_tools.subnet_utils.matching_interface", return_value="Wi-Fi")
    @patch("lanscape.core.net_tools.subnet_utils.get_os_platform", return_value="windows")
    def test_build_ipv4_local(self, _mock_os, _mock_match, _mock_local, _mock_v6):
        """build() wires subnet helpers into the model."""
        ctx = StageEvalContext.build("192.168.1.0/24", arp_supported=True)
        assert ctx.is_ipv6 is False
        assert ctx.is_local is True
        assert ctx.matching_interface == "Wi-Fi"
        assert ctx.arp_supported is True
        assert ctx.os_platform == "windows"

    @patch("lanscape.core.net_tools.subnet_utils.is_ipv6_subnet", return_value=True)
    @patch("lanscape.core.net_tools.subnet_utils.is_local_subnet", return_value=False)
    @patch("lanscape.core.net_tools.subnet_utils.matching_interface", return_value=None)
    @patch("lanscape.core.net_tools.subnet_utils.get_os_platform", return_value="linux")
    def test_build_ipv6(self, _mock_os, _mock_match, _mock_local, _mock_v6):
        """build() correctly detects IPv6."""
        ctx = StageEvalContext.build("2001:db8::/64")
        assert ctx.is_ipv6 is True
        assert ctx.is_local is False


# ---------------------------------------------------------------------------
# Stage guards — IPv4 discovery
# ---------------------------------------------------------------------------

class TestICMPDiscoveryGuard:
    """ICMP discovery skips on IPv6."""

    def _make(self) -> ICMPDiscoveryStage:
        return ICMPDiscoveryStage(ICMPDiscoveryStageConfig(), [])

    def test_allows_ipv4_local(self):
        """IPv4 local is allowed."""
        assert self._make().can_execute(_ipv4_local_ctx()) is None

    def test_allows_ipv4_remote(self):
        """IPv4 remote is allowed."""
        assert self._make().can_execute(_ipv4_remote_ctx()) is None

    def test_skips_ipv6(self):
        """IPv6 subnet is skipped."""
        reason = self._make().can_execute(_ipv6_ctx())
        assert reason is not None
        assert "IPv4-only" in reason


class TestARPDiscoveryGuard:
    """ARP discovery skips on IPv6, remote, or no-ARP."""

    def _make(self) -> ARPDiscoveryStage:
        return ARPDiscoveryStage(ARPDiscoveryStageConfig(), [])

    def test_allows_ipv4_local_arp(self):
        """Local IPv4 with ARP is allowed."""
        assert self._make().can_execute(_ipv4_local_ctx(arp=True)) is None

    def test_skips_ipv6(self):
        """IPv6 subnet is skipped."""
        assert self._make().can_execute(_ipv6_ctx()) is not None

    def test_skips_remote(self):
        """Remote subnet is skipped."""
        reason = self._make().can_execute(_ipv4_remote_ctx())
        assert reason is not None
        assert "local" in reason

    def test_skips_no_arp(self):
        """No ARP support is skipped."""
        reason = self._make().can_execute(_ipv4_local_ctx(arp=False))
        assert reason is not None
        assert "not supported" in reason


class TestPokeARPDiscoveryGuard:
    """Poke+ARP discovery skips on IPv6 or remote."""

    def _make(self) -> PokeARPDiscoveryStage:
        return PokeARPDiscoveryStage(PokeARPDiscoveryStageConfig(), [])

    def test_allows_ipv4_local(self):
        """IPv4 local is allowed."""
        assert self._make().can_execute(_ipv4_local_ctx()) is None

    def test_skips_ipv6(self):
        """IPv6 subnet is skipped."""
        assert self._make().can_execute(_ipv6_ctx()) is not None

    def test_skips_remote(self):
        """Remote subnet is skipped."""
        reason = self._make().can_execute(_ipv4_remote_ctx())
        assert reason is not None
        assert "local" in reason


class TestICMPARPDiscoveryGuard:
    """ICMP+ARP discovery skips on IPv6 or remote."""

    def _make(self) -> ICMPARPDiscoveryStage:
        return ICMPARPDiscoveryStage(ICMPARPDiscoveryStageConfig(), [])

    def test_allows_ipv4_local(self):
        """IPv4 local is allowed."""
        assert self._make().can_execute(_ipv4_local_ctx()) is None

    def test_skips_ipv6(self):
        """IPv6 subnet is skipped."""
        assert self._make().can_execute(_ipv6_ctx()) is not None

    def test_skips_remote(self):
        """Remote subnet is skipped."""
        reason = self._make().can_execute(_ipv4_remote_ctx())
        assert reason is not None
        assert "local" in reason


# ---------------------------------------------------------------------------
# Stage guards — IPv6 discovery
# ---------------------------------------------------------------------------

class TestIPv6NDPDiscoveryGuard:
    """NDP discovery skips on IPv4."""

    def _make(self) -> IPv6NDPDiscoveryStage:
        return IPv6NDPDiscoveryStage(IPv6NDPDiscoveryStageConfig())

    def test_allows_ipv6(self):
        """IPv6 subnet is allowed."""
        assert self._make().can_execute(_ipv6_ctx()) is None

    def test_skips_ipv4(self):
        """IPv4 subnet is skipped."""
        reason = self._make().can_execute(_ipv4_local_ctx())
        assert reason is not None
        assert "IPv6-only" in reason


class TestIPv6MDNSDiscoveryGuard:
    """mDNS discovery skips on IPv4."""

    def _make(self) -> IPv6MDNSDiscoveryStage:
        return IPv6MDNSDiscoveryStage(IPv6MDNSDiscoveryStageConfig())

    def test_allows_ipv6(self):
        """IPv6 subnet is allowed."""
        assert self._make().can_execute(_ipv6_ctx()) is None

    def test_skips_ipv4(self):
        """IPv4 subnet is skipped."""
        reason = self._make().can_execute(_ipv4_local_ctx())
        assert reason is not None
        assert "IPv6-only" in reason


# ---------------------------------------------------------------------------
# Stage guards — Port scan (never skipped)
# ---------------------------------------------------------------------------

class TestPortScanGuard:
    """Port scan never skips."""

    def test_never_skips(self):
        """Port scan runs on any context."""
        stage = PortScanStage(PortScanStageConfig())
        assert stage.can_execute(_ipv4_local_ctx()) is None
        assert stage.can_execute(_ipv4_remote_ctx()) is None
        assert stage.can_execute(_ipv6_ctx()) is None


# ---------------------------------------------------------------------------
# mark_skipped & StageProgress serialization
# ---------------------------------------------------------------------------

class TestMarkSkipped:
    """mark_skipped and StageProgress serialization."""

    def test_mark_skipped_sets_fields(self):
        """mark_skipped sets internal flags."""
        stage = _DummyStage()
        stage.mark_skipped("test reason")
        assert stage._finished is True
        assert stage._skipped is True
        assert stage._skip_reason == "test reason"

    def test_stage_progress_includes_skipped(self):
        """StageProgress reflects skipped state."""
        stage = _DummyStage()
        stage.mark_skipped("some guard failed")
        progress = stage.stage_progress()
        assert progress.skipped is True
        assert progress.skip_reason == "some guard failed"
        assert progress.finished is True

    def test_stage_progress_not_skipped_by_default(self):
        """Stages are not skipped by default."""
        stage = _DummyStage()
        progress = stage.stage_progress()
        assert progress.skipped is False
        assert progress.skip_reason is None

    def test_stage_progress_serialization(self):
        """skipped/skip_reason appear in dict output."""
        progress = StageProgress(
            stage_name="Test",
            stage_type=StageType.ICMP_DISCOVERY,
            skipped=True,
            skip_reason="IPv6-only",
        )
        d = progress.model_dump()
        assert d["skipped"] is True
        assert d["skip_reason"] == "IPv6-only"


# ---------------------------------------------------------------------------
# Pipeline skip flow
# ---------------------------------------------------------------------------

class TestPipelineSkipFlow:
    """Pipeline integration tests for skip guards."""

    def test_skipped_stage_not_executed(self):
        """A stage whose can_execute returns a reason is not executed."""
        skipped = _DummyStage(skip_reason="not compatible")
        normal = _DummyStage()

        ctx = ScanContext("10.0.0.0/24")
        eval_ctx = _ipv4_local_ctx()
        pipeline = ScanPipeline([skipped, normal], eval_ctx=eval_ctx)
        pipeline.execute(ctx)

        assert skipped._skipped is True
        assert skipped.finished is True
        assert skipped.completed == 0  # execute never ran

        assert normal._skipped is False
        assert normal.finished is True
        assert normal.completed == 1

    def test_skipped_stage_emits_warning(self):

        """A skipped stage appends a ScanWarningInfo to context."""
        skipped = _DummyStage(skip_reason="bad subnet")
        ctx = ScanContext("10.0.0.0/24")
        eval_ctx = _ipv4_local_ctx()
        pipeline = ScanPipeline([skipped], eval_ctx=eval_ctx)
        pipeline.execute(ctx)

        assert len(ctx.warnings) == 1
        w = ctx.warnings[0]
        assert w.category.value == "stage_skip"
        assert "Dummy" in w.title
        assert "bad subnet" in w.body

    def test_on_stage_change_fires_for_skipped(self):
        """The on_stage_change callback fires even for skipped stages."""
        skipped = _DummyStage(skip_reason="nope")
        changes = []
        pipeline = ScanPipeline(
            [skipped],
            on_stage_change=changes.append,
            eval_ctx=_ipv4_local_ctx(),
        )
        pipeline.execute(ScanContext("10.0.0.0/24"))
        assert skipped in changes

    def test_all_stages_skipped(self):

        """Pipeline completes normally even if every stage is skipped."""
        s1 = _DummyStage(skip_reason="r1")
        s2 = _DummyStage(skip_reason="r2")
        ctx = ScanContext("10.0.0.0/24")
        pipeline = ScanPipeline([s1, s2], eval_ctx=_ipv4_local_ctx())
        pipeline.execute(ctx)

        assert s1._skipped and s2._skipped
        assert len(ctx.warnings) == 2

    def test_stage_progress_list_includes_skipped(self):

        """get_stage_progress reflects skipped states."""
        s1 = _DummyStage(skip_reason="skip me")
        s2 = _DummyStage()
        ctx = ScanContext("10.0.0.0/24")
        pipeline = ScanPipeline([s1, s2], eval_ctx=_ipv4_local_ctx())
        pipeline.execute(ctx)

        progress = pipeline.get_stage_progress()
        assert progress[0].skipped is True
        assert progress[0].skip_reason == "skip me"
        assert progress[1].skipped is False
