"""Tests for PortScanStage delta-port logic and SubnetScanner.append_stages."""
# pylint: disable=protected-access

from unittest.mock import patch, MagicMock

from lanscape.core.scan_context import ScanContext
from lanscape.core.stages.port_scan import PortScanStage
from lanscape.core.scan_config import PipelineConfig, StageConfig, PortScanStageConfig
from lanscape.core.models.enums import StageType
from lanscape.core.net_tools.device import Device
from lanscape.core.subnet_scan import SubnetScanner


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
