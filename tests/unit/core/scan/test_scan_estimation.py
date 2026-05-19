"""
Tests for scan progress estimation logic in SubnetScanner.
Covers the pipeline-based calc_percent_complete and stage progress tracking.
"""
# pylint: disable=protected-access

from unittest.mock import patch


from lanscape.core.scan_config import ScanConfig
from lanscape.core.subnet_scan import SubnetScanner
from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.scan_pipeline import ScanPipeline
from lanscape.core.models.enums import StageType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeStage(ScanStageMixin):
    """Manually controllable stage for testing progress."""

    stage_type = StageType.ICMP_DISCOVERY
    stage_name = "Fake Stage"

    def execute(self, context: ScanContext) -> None:
        pass  # controlled externally in tests


def _make_scanner(**kwargs) -> SubnetScanner:
    """
    Build a SubnetScanner with mocked network parsing to avoid DNS lookups.
    """
    cfg_kwargs = {
        'subnet': '10.0.0.0/28',   # 14 hosts
        'port_list': 'small',
        **kwargs,
    }

    with patch('lanscape.core.scan_config.parse_ip_input') as mock_parse, \
            patch('lanscape.core.scan_config.PortManager') as mock_pm, \
            patch('lanscape.core.stage_builder.parse_ip_input') as mock_parse2:
        mock_parse.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
        mock_parse2.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
        mock_pm.return_value.get_port_list.return_value = {
            p: None for p in range(1, 51)  # 50 ports
        }
        scanner = SubnetScanner(ScanConfig(**cfg_kwargs))

    scanner.job_stats.clear_stats()
    return scanner


# ---------------------------------------------------------------------------
# calc_percent_complete — pipeline-based
# ---------------------------------------------------------------------------

class TestCalcPercentComplete:
    """Tests for pipeline-based percent complete calculation."""

    def test_returns_100_when_not_running(self):
        """Stopped scans report 100%."""
        scanner = _make_scanner()
        scanner.running = False
        assert scanner.calc_percent_complete() == 100

    def test_returns_0_with_no_stages(self):
        """Running scan with empty pipeline returns 0."""
        scanner = _make_scanner()
        scanner.running = True
        scanner.pipeline = ScanPipeline([])
        assert scanner.calc_percent_complete() == 0

    def test_returns_0_when_just_started(self):
        """Fresh scan with no progress returns 0."""
        scanner = _make_scanner()
        scanner.running = True
        # All stages have total=0 and completed=0 initially
        for stage in scanner.pipeline.stages:
            stage._total = 10
            stage._completed = 0
        assert scanner.calc_percent_complete() == 0

    def test_single_stage_partial_progress(self):
        """Single stage at 50% → overall 50%."""
        scanner = _make_scanner()
        scanner.running = True

        fake = _FakeStage()
        fake._total = 100
        fake._completed = 50
        fake.running = True
        scanner.pipeline = ScanPipeline([fake])

        assert scanner.calc_percent_complete() == 50

    def test_two_stages_first_complete(self):
        """Two stages, first finished, second not started → 50%."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1._finished = True
        s2 = _FakeStage()
        s2._total = 10
        s2._completed = 0
        scanner.pipeline = ScanPipeline([s1, s2])

        assert scanner.calc_percent_complete() == 50

    def test_two_stages_first_complete_second_half(self):
        """Two stages: first done, second at 50% → 75%."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1._finished = True
        s2 = _FakeStage()
        s2._total = 100
        s2._completed = 50
        s2.running = True
        scanner.pipeline = ScanPipeline([s1, s2])

        assert scanner.calc_percent_complete() == 75

    def test_caps_at_99(self):
        """Should never exceed 99% while running."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1._finished = True
        scanner.pipeline = ScanPipeline([s1])

        result = scanner.calc_percent_complete()
        assert result <= 99

    def test_progress_increases(self):
        """Percent complete should increase as stages progress."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1._total = 100
        s1._completed = 0
        s1.running = True
        scanner.pipeline = ScanPipeline([s1])

        pct_0 = scanner.calc_percent_complete()

        s1._completed = 50
        pct_50 = scanner.calc_percent_complete()

        assert pct_50 > pct_0


# ---------------------------------------------------------------------------
# Pipeline stage progress in metadata
# ---------------------------------------------------------------------------

class TestStageProgress:
    """Tests for pipeline stage progress reported in metadata."""

    def test_metadata_includes_stage_progress(self):
        """ScannerResults.get_metadata() includes stage progress."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1.stage_name = "Discovery"
        s1._total = 14
        s1._completed = 7
        s1.running = True
        scanner.pipeline = ScanPipeline([s1])

        meta = scanner.results.get_metadata()
        assert len(meta.stages) == 1
        assert meta.stages[0].stage_name == "Discovery"
        assert meta.stages[0].total == 14
        assert meta.stages[0].completed == 7
        assert meta.stages[0].finished is False

    def test_metadata_current_stage_index(self):
        """Metadata reports the current stage index during execution."""
        scanner = _make_scanner()
        scanner.running = True

        s1 = _FakeStage()
        s1._finished = True
        s2 = _FakeStage()
        s2.stage_name = "Port Scan"
        s2._total = 100
        s2._completed = 10
        s2.running = True
        scanner.pipeline = ScanPipeline([s1, s2])
        scanner.pipeline._current_index = 1

        meta = scanner.results.get_metadata()
        assert meta.current_stage_index == 1
