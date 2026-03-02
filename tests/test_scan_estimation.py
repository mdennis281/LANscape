"""
Tests for scan progress estimation logic in SubnetScanner.
Covers _estimate_port_test_time, _calc_port_scan_time, _calc_host_discovery_time,
_estimate_alive_devices, and calc_percent_complete.
"""
# pylint: disable=protected-access

from unittest.mock import patch, MagicMock

import pytest

from lanscape.core.scan_config import ScanConfig, PortScanConfig
from lanscape.core.subnet_scan import SubnetScanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_scanner(port_scan_config: PortScanConfig | None = None, **kwargs) -> SubnetScanner:
    """
    Build a SubnetScanner with mocked network parsing to avoid DNS lookups.
    Accepts optional PortScanConfig override and extra ScanConfig kwargs.
    """
    cfg_kwargs = {
        'subnet': '10.0.0.0/28',   # 14 hosts
        'port_list': 'small',
        **kwargs,
    }
    if port_scan_config is not None:
        cfg_kwargs['port_scan_config'] = port_scan_config

    with patch('lanscape.core.scan_config.parse_ip_input') as mock_parse, \
         patch('lanscape.core.scan_config.PortManager') as mock_pm:
        mock_parse.return_value = [f'10.0.0.{i}' for i in range(1, 15)]
        mock_pm.return_value.get_port_list.return_value = {
            p: None for p in range(1, 51)  # 50 ports
        }
        scanner = SubnetScanner(ScanConfig(**cfg_kwargs))

    # Reset JobStats so tests don't leak into each other
    scanner.job_stats.clear_stats()
    return scanner


# ---------------------------------------------------------------------------
# _estimate_port_test_time
# ---------------------------------------------------------------------------

class TestEstimatePortTestTime:
    """Tests for the config-aware port test time estimator."""

    def test_no_samples_returns_config_estimate(self):
        """With zero ports scanned, should return the config-derived estimate."""
        pcfg = PortScanConfig(timeout=2.5, retries=1, retry_delay=0.2)
        scanner = _make_scanner(port_scan_config=pcfg)
        # Config estimate: 2.5 * 2 + 0.2 * 1 = 5.2
        assert scanner._estimate_port_test_time() == pytest.approx(5.2)

    def test_default_config_estimate(self):
        """Default PortScanConfig (timeout=1, retries=0) → estimate = 1.0."""
        scanner = _make_scanner()
        assert scanner._estimate_port_test_time() == pytest.approx(1.0)

    def test_blends_measured_gradually(self):
        """With some samples, should blend between config estimate and measured avg."""
        pcfg = PortScanConfig(timeout=2.5, retries=1, retry_delay=0.2)
        scanner = _make_scanner(port_scan_config=pcfg)
        config_est = 5.2
        measured = 0.5

        # Simulate 10 scanned ports (half of blend threshold)
        scanner.job_stats.finished['SubnetScanner._test_port'] = 10
        scanner.job_stats.timing['SubnetScanner._test_port'] = measured

        result = scanner._estimate_port_test_time()
        # weight = 10/20 = 0.5 → 0.5 * 0.5 + 5.2 * 0.5 = 2.85
        expected = measured * 0.5 + config_est * 0.5
        assert result == pytest.approx(expected)

    def test_full_measured_at_threshold(self):
        """At 20+ samples, should fully trust measured average."""
        pcfg = PortScanConfig(timeout=2.5, retries=1, retry_delay=0.2)
        scanner = _make_scanner(port_scan_config=pcfg)
        measured = 0.3

        scanner.job_stats.finished['SubnetScanner._test_port'] = 20
        scanner.job_stats.timing['SubnetScanner._test_port'] = measured

        result = scanner._estimate_port_test_time()
        assert result == pytest.approx(measured)

    def test_above_threshold_stays_measured(self):
        """Beyond 20 samples, weight stays clamped at 1.0 → pure measured."""
        scanner = _make_scanner()
        measured = 0.42

        scanner.job_stats.finished['SubnetScanner._test_port'] = 100
        scanner.job_stats.timing['SubnetScanner._test_port'] = measured

        result = scanner._estimate_port_test_time()
        assert result == pytest.approx(measured)

    def test_high_retry_config_gives_higher_estimate(self):
        """Configs with more retries produce larger initial estimates."""
        pcfg_high = PortScanConfig(timeout=3.0, retries=3, retry_delay=0.5)
        scanner = _make_scanner(port_scan_config=pcfg_high)
        # 3.0 * 4 + 0.5 * 3 = 13.5
        assert scanner._estimate_port_test_time() == pytest.approx(13.5)

    def test_zero_measured_avg_uses_config(self):
        """If measured avg is 0 (shouldn't happen but edge case), use config."""
        pcfg = PortScanConfig(timeout=1.0, retries=0, retry_delay=0.1)
        scanner = _make_scanner(port_scan_config=pcfg)

        scanner.job_stats.finished['SubnetScanner._test_port'] = 5
        scanner.job_stats.timing['SubnetScanner._test_port'] = 0.0

        result = scanner._estimate_port_test_time()
        assert result == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# _calc_port_scan_time
# ---------------------------------------------------------------------------

class TestCalcPortScanTime:
    """Tests for the port scan time calculation."""

    def test_uses_estimated_time_and_thread_multiplier(self):
        """Verify total/remaining reflect config estimate and thread counts."""
        pcfg = PortScanConfig(timeout=2.0, retries=0, retry_delay=0.0)
        scanner = _make_scanner(
            port_scan_config=pcfg,
            t_cnt_port_scan=2,
            t_cnt_port_test=5,
        )

        est_alive = 10.0
        total, remaining = scanner._calc_port_scan_time(est_alive)

        # 10 devices × 50 ports = 500 total ports
        # Config estimate: 2.0 * 1 + 0 = 2.0s per port
        # Raw total: 500 * 2.0 = 1000s
        # Multiplier: 2 * 5 = 10
        # Adjusted: 1000 / 10 = 100s
        assert total == pytest.approx(100.0)
        assert remaining == pytest.approx(100.0)

    def test_remaining_decreases_as_ports_scanned(self):
        """As ports are scanned, remaining time should decrease."""
        scanner = _make_scanner(t_cnt_port_scan=1, t_cnt_port_test=1)
        est_alive = 5.0  # 5 devices × 50 ports = 250 total

        # Simulate 50 ports scanned with fast measured time
        scanner.job_stats.finished['SubnetScanner._test_port'] = 50
        scanner.job_stats.timing['SubnetScanner._test_port'] = 0.5

        total, remaining = scanner._calc_port_scan_time(est_alive)

        # At 50 scanned out of 250 total, remaining = 200
        # Measured weight: 50/20 = clamped to 1.0 → avg = 0.5
        assert remaining < total
        assert remaining == pytest.approx(200 * 0.5)


# ---------------------------------------------------------------------------
# _estimate_alive_devices
# ---------------------------------------------------------------------------

class TestEstimateAliveDevices:
    """Tests for alive device estimation."""

    def test_returns_actual_count_when_discovery_complete(self):
        """After all hosts scanned, returns actual alive count."""
        scanner = _make_scanner()
        scanner.results.devices_scanned = scanner.results.devices_total
        # Add some mock devices
        scanner.results.devices = [MagicMock() for _ in range(5)]

        result = scanner._estimate_alive_devices()
        assert result == 5.0

    def test_estimates_during_discovery(self):
        """During discovery, extrapolates from scanned proportion."""
        scanner = _make_scanner()
        scanner.results.devices_scanned = 7  # half of 14
        scanner.results.devices = [MagicMock() for _ in range(2)]

        result = scanner._estimate_alive_devices()
        # 2/7 alive rate × 14 total = 4.0
        assert result == pytest.approx(4.0)

    def test_assumes_10_percent_at_start(self):
        """Before any devices scanned, assumes 10% alive."""
        scanner = _make_scanner()
        assert scanner.results.devices_scanned == 0

        result = scanner._estimate_alive_devices()
        assert result == pytest.approx(0.1 * 14)


# ---------------------------------------------------------------------------
# calc_percent_complete
# ---------------------------------------------------------------------------

class TestCalcPercentComplete:
    """Tests for overall percent complete calculation."""

    def test_returns_100_when_not_running(self):
        """Stopped scans report 100%."""
        scanner = _make_scanner()
        scanner.running = False
        assert scanner.calc_percent_complete() == 100

    def test_returns_0_when_just_started(self):
        """Fresh scan with no progress returns 0."""
        scanner = _make_scanner()
        scanner.running = True
        # No devices scanned, no ports scanned, initial estimate
        assert scanner.calc_percent_complete() == 0

    def test_caps_at_99(self):
        """Should never exceed 99% while running."""
        scanner = _make_scanner()
        scanner.running = True
        # Simulate almost everything done
        scanner.results.devices_scanned = scanner.results.devices_total
        scanner.results.devices = [MagicMock() for _ in range(2)]

        # Mark all expected ports as scanned
        total_ports = 2 * len(scanner.ports)
        scanner.job_stats.finished['SubnetScanner._test_port'] = total_ports
        scanner.job_stats.timing['SubnetScanner._test_port'] = 0.1

        # Also finish host discovery timing
        scanner.job_stats.finished['SubnetScanner._get_host_details'] = 14
        scanner.job_stats.timing['SubnetScanner._get_host_details'] = 0.5

        result = scanner.calc_percent_complete()
        assert result <= 99

    def test_progress_increases_with_scanned_ports(self):
        """Percent complete should increase as ports are scanned."""
        scanner = _make_scanner(t_cnt_port_scan=1, t_cnt_port_test=1)
        scanner.running = True
        scanner.results.devices_scanned = scanner.results.devices_total
        scanner.results.devices = [MagicMock() for _ in range(3)]

        scanner.job_stats.finished['SubnetScanner._get_host_details'] = 14
        scanner.job_stats.timing['SubnetScanner._get_host_details'] = 0.5

        # Check at 0 ports
        pct_0 = scanner.calc_percent_complete()

        # Scan 50 ports (1 device's worth)
        scanner.job_stats.finished['SubnetScanner._test_port'] = 50
        scanner.job_stats.timing['SubnetScanner._test_port'] = 0.3
        pct_50 = scanner.calc_percent_complete()

        assert pct_50 > pct_0

    def test_accurate_config_produces_reasonable_estimate(self):
        """Accurate config should not wildly underestimate time."""
        pcfg = PortScanConfig(timeout=2.5, retries=1, retry_delay=0.2)
        scanner = _make_scanner(
            port_scan_config=pcfg,
            t_cnt_port_scan=5,
            t_cnt_port_test=64,
        )
        scanner.running = True
        scanner.results.devices_scanned = scanner.results.devices_total
        scanner.results.devices = [MagicMock() for _ in range(3)]

        scanner.job_stats.finished['SubnetScanner._get_host_details'] = 14
        scanner.job_stats.timing['SubnetScanner._get_host_details'] = 1.0

        # No ports scanned yet → should use config estimate (5.2s)
        # not hardcoded 1s, so percent should be low (lots of work ahead)
        pct = scanner.calc_percent_complete()
        # With accurate config the port phase dominates;
        # percent should be modest, not misleadingly high
        assert pct < 60
