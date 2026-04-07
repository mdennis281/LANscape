"""Subnet scanning: device discovery, port scanning, and result management."""

# Standard library imports
import uuid
import logging
import ipaddress
import threading
from time import time, sleep
from typing import List, Union

# Third-party imports
from tabulate import tabulate

# Local imports
from lanscape.core.scan_config import ScanConfig, PipelineConfig, StageConfig
from lanscape.core.decorators import JobStats
from lanscape.core.net_tools import (
    Device, is_internal_block, scan_config_uses_arp
)
from lanscape.core.errors import SubnetScanTerminationFailure
from lanscape.core.models import (
    ScanMetadata, ScanResults, ScanStage, ScanSummary, ScanListItem,
    ScanErrorInfo, ScanWarningInfo
)
from lanscape.core.models.enums import StageType
from lanscape.core.system_compat import clear_screen
from lanscape.core.scan_pipeline import ScanPipeline
from lanscape.core.scan_context import ScanContext
from lanscape.core.stage_builder import build_stages
from lanscape.core.neighbor_table import NeighborTableService


class SubnetScanner():
    """
    Scans a subnet for devices and open ports.

    Manages the scanning process including device discovery and port scanning.
    Tracks scan progress and provides mechanisms for controlled termination.

    Accepts either a :class:`ScanConfig` (legacy) or a :class:`PipelineConfig`.
    Legacy configs are automatically converted via
    :meth:`ScanConfig.to_pipeline_config`.
    """

    def __init__(
        self,
        config: Union[ScanConfig, PipelineConfig],
    ):
        # Normalise to PipelineConfig
        if isinstance(config, ScanConfig):
            self.cfg = config
            self.pipeline_cfg = config.to_pipeline_config()
        else:
            self.cfg = config  # keep reference for backward-compat fields
            self.pipeline_cfg = config

        self.subnet_str = self.pipeline_cfg.subnet
        self.job_stats = JobStats()

        # Status properties
        self.running = False
        self.uid = str(uuid.uuid4())
        self.log: logging.Logger = logging.getLogger('SubnetScanner')

        # Build pipeline stages
        stage_instances = build_stages(self.pipeline_cfg)
        self.pipeline = ScanPipeline(
            stage_instances,
            on_stage_change=self._on_stage_change,
        )
        self.context = ScanContext(self.subnet_str)

        # Results bridge — adapts pipeline data to the existing ScannerResults API
        self.results = ScannerResults(self)

        self.log.debug(f'Instantiated with uid: {self.uid}')

    def start(self):
        """
        Scan the subnet for devices and open ports using the stage pipeline.
        """
        self._set_stage('scanning devices')
        self.running = True

        # Start the neighbor table service so discovery stages can
        # resolve MAC addresses via the OS ARP / NDP cache.
        neighbor_svc = NeighborTableService.instance()
        neighbor_svc.start()

        try:
            self.job_stats.clear_stats()
            self.pipeline.execute(self.context)
        except Exception:
            self.log.exception("Pipeline execution failed")
            raise
        finally:
            neighbor_svc.stop()

        # Set stage BEFORE running=False so the broadcast loop never sees
        # running=False with a stale stage (e.g. 'testing ports').
        self._set_stage('complete')
        self.results.end_time = time()
        self.running = False

        devices_found = len(self.context.devices)
        open_ports = sum(len(d.ports) for d in self.context.devices)
        self.log.info(
            f'Scan complete for {self.subnet_str}: '
            f'{devices_found} device(s) found, {open_ports} open port(s)'
        )

        return self.results

    def terminate(self):
        """
        Terminate the scan operation.

        Attempts a graceful shutdown of all scan operations and waits for running
        tasks to complete. Raises an exception if termination takes too long.

        Returns:
            bool: True if terminated successfully

        Raises:
            SubnetScanTerminationFailure: If the scan cannot be terminated within the timeout
        """
        # Set stage BEFORE running=False so the broadcast loop always sees
        # 'terminating' when it detects the scan is no longer running.
        self._set_stage('terminating')
        self.running = False

        # Terminate the pipeline (stops current + skips remaining stages)
        self.pipeline.terminate()

        for _ in range(20):
            if not self.job_stats.running:
                self._set_stage('terminated')
                return True
            sleep(.5)
        raise SubnetScanTerminationFailure(self.job_stats.running)

    def append_stages(self, stage_configs: List[dict]) -> None:
        """Append new stages to an active or completed scan.

        Builds concrete stage instances from config dicts and appends
        them to the pipeline.  If the scan has already finished, it is
        restarted in a new thread so the new stages execute.
        """
        stage_entries = [StageConfig.from_dict(sc) for sc in stage_configs]
        temp_cfg = PipelineConfig(
            subnet=self.subnet_str,
            stages=stage_entries,
            resilience=self.pipeline_cfg.resilience,
            hostname_config=self.pipeline_cfg.hostname_config,
        )
        new_instances = build_stages(temp_cfg)
        self.pipeline.append_stages(new_instances)

        if not self.running:
            self._restart_pipeline()

    def _restart_pipeline(self) -> None:
        """Restart pipeline execution in a background thread for appended stages."""
        self.running = True
        self._set_stage('scanning devices')

        def _run() -> None:
            neighbor_svc = NeighborTableService.instance()
            neighbor_svc.start()
            try:
                self.pipeline.execute(self.context)
            except Exception:
                self.log.exception("Pipeline execution failed (restart)")
                raise
            finally:
                neighbor_svc.stop()

            self._set_stage('complete')
            self.results.end_time = time()
            self.running = False

        t = threading.Thread(target=_run)
        t.start()

    def _estimate_alive_devices(self) -> float:
        """
        Estimate the number of alive devices in the subnet.

        Once device discovery is complete, returns the actual count.
        During discovery, estimates based on current alive percentage.

        Returns:
            float: Estimated or actual number of alive devices
        """
        device_discovery_complete = (
            self.results.devices_scanned >= self.results.devices_total
        )

        if device_discovery_complete:
            return float(len(self.results.devices))

        if self.results.devices and self.results.devices_scanned:
            alive_percent = len(self.results.devices) / self.results.devices_scanned
            return alive_percent * self.results.devices_total

        # Assume 10% alive percentage if the scan just started
        return 0.1 * self.results.devices_total

    def _calc_host_discovery_time(self) -> tuple[float, float]:
        """
        Calculate total and remaining time for host discovery phase.

        Returns:
            tuple: (total_time_sec, remaining_time_sec) adjusted by thread multiplier
        """
        avg_host_detail_sec = self.job_stats.timing.get(
            'SubnetScanner._get_host_details', 4.5)

        remaining_devices = self.results.devices_total - self.results.devices_scanned
        remaining_sec = remaining_devices * avg_host_detail_sec
        total_sec = self.results.devices_total * avg_host_detail_sec

        multiplier = self.cfg.t_cnt('isalive')
        return total_sec / multiplier, remaining_sec / multiplier

    def _estimate_port_test_time(self) -> float:
        """
        Estimate the average time per port test based on config and measured data.

        Uses a weighted blend between config-derived estimate and measured average,
        transitioning smoothly as more samples accumulate.

        Returns:
            float: Estimated seconds per port test
        """
        pcfg = self.cfg.port_scan_config
        # Worst-case per-port: each attempt can take up to `timeout`,
        # plus `retry_delay` between retries (not after the last attempt).
        config_estimate = (
            pcfg.timeout * (pcfg.retries + 1)
            + pcfg.retry_delay * pcfg.retries
        )

        ports_scanned = self.job_stats.finished.get('SubnetScanner._test_port', 0)
        measured_avg = self.job_stats.timing.get('SubnetScanner._test_port', 0.0)

        if ports_scanned == 0 or measured_avg <= 0:
            return config_estimate

        # Blend: measured data gets more weight as samples grow (full trust at 20)
        blend_threshold = 20
        measured_weight = min(1.0, ports_scanned / blend_threshold)
        return measured_avg * measured_weight + config_estimate * (1 - measured_weight)

    def _calc_port_scan_time(self, est_alive_devices: float) -> tuple[float, float]:
        """
        Calculate total and remaining time for port scanning phase.

        Args:
            est_alive_devices: Estimated or actual number of alive devices

        Returns:
            tuple: (total_time_sec, remaining_time_sec) adjusted by thread multiplier
        """
        ports_scanned = self.job_stats.finished.get('SubnetScanner._test_port', 0)
        avg_port_test_sec = self._estimate_port_test_time()

        total_ports = est_alive_devices * len(self.cfg.get_ports())
        remaining_ports = max(0, total_ports - ports_scanned)

        remaining_sec = remaining_ports * avg_port_test_sec
        total_sec = total_ports * avg_port_test_sec

        multiplier = self.cfg.t_cnt('port_scan') * self.cfg.t_cnt('port_test')
        return total_sec / multiplier, remaining_sec / multiplier

    def calc_percent_complete(self) -> int:
        """
        Calculate the percentage completion of the scan based on pipeline stage progress.

        Returns:
            int: Completion percentage (0-100)
        """
        if not self.running:
            return 100

        stages = self.pipeline.stages
        if not stages:
            return 0

        # Weight each stage equally, progress within each stage is proportional
        total_stages = len(stages)
        completed_weight = 0.0

        for stage in stages:
            if stage.finished:
                completed_weight += 1.0
            elif stage.running and stage.total > 0:
                completed_weight += stage.completed / stage.total

        return min(99, int((completed_weight / total_stages) * 100))

    def debug_active_scan(self, sleep_sec=1):
        """
            Run this after running scan_subnet_threaded
            to see the progress of the scan
        """
        while self.running:
            percent = self.calc_percent_complete()
            t_elapsed = time() - self.results.start_time
            t_remain = int((100 - percent) * (t_elapsed / percent)
                           ) if percent else '∞'
            buffer = f'{self.uid} - {self.subnet_str}\n'
            buffer += f'Config: {self.cfg}\n'
            buffer += f'Elapsed: {int(t_elapsed)} sec - Remain: {t_remain} sec\n'
            buffer += f'Progress: {percent}%\n'
            buffer += str(self.job_stats)
            clear_screen()
            print(buffer)
            sleep(sleep_sec)

    def _set_stage(self, stage):
        self.log.debug(f'[{self.uid}] Moving to Stage: {stage}')
        self.results.stage = stage
        if not self.running:
            self.results.end_time = time()

    def _on_stage_change(self, stage) -> None:
        """Called by the pipeline when a new stage begins executing."""
        if stage.stage_type == StageType.PORT_SCAN:
            self._set_stage('testing ports')
        elif self.results.stage != 'scanning devices':
            # Revert to discovery stage if we're back to a discovery stage
            self._set_stage('scanning devices')


class ScannerResults:
    """
    Stores and manages the results of a subnet scan.

    Bridges the pipeline's :class:`ScanContext` to the existing result APIs.
    Tracks scan statistics and provides export functionality.
    """

    def __init__(self, scan: SubnetScanner):
        # Parent reference and identifiers
        self.scan = scan
        self.subnet: str = scan.subnet_str
        self.uid = scan.uid

        # Status tracking
        self.running: bool = False
        self.start_time: float = time()
        self.end_time: int = None
        self.stage = 'instantiated'
        self.run_time = 0

        # Logging
        self.log = logging.getLogger('ScannerResults')
        self.log.debug(f'Instantiated Logger For Scan: {self.scan.uid}')

    # ── Properties that delegate to the pipeline context ────────────

    @property
    def devices(self) -> List[Device]:
        """Devices discovered across all stages."""
        return self.scan.context.devices

    @property
    def devices_alive(self) -> int:
        """Number of alive devices found in the scan."""
        return len(self.devices)

    @property
    def errors(self) -> List[ScanErrorInfo]:
        """Scan-level errors from all stages."""
        return self.scan.context.errors

    @errors.setter
    def errors(self, value: List[ScanErrorInfo]) -> None:
        self.scan.context.errors = value

    @property
    def warnings(self) -> List[ScanWarningInfo]:
        """Scan-level warnings from all stages."""
        return self.scan.context.warnings

    @warnings.setter
    def warnings(self, value: List[ScanWarningInfo]) -> None:
        self.scan.context.warnings = value

    @property
    def port_list(self) -> str:
        """Port list name from config."""
        if isinstance(self.scan.cfg, ScanConfig):
            return self.scan.cfg.port_list
        return "custom"

    @property
    def devices_total(self) -> int:
        """Total IPs to scan (sum of discovery stage totals)."""
        total = 0
        for stage in self.scan.pipeline.stages:
            if stage.stage_type.name.endswith('_DISCOVERY'):
                total = max(total, stage.total)
        return total or 0

    @property
    def devices_scanned(self) -> int:
        """Number of IPs checked so far (sum of discovery stage completed)."""
        scanned = 0
        for stage in self.scan.pipeline.stages:
            if stage.stage_type.name.endswith('_DISCOVERY'):
                scanned = max(scanned, stage.completed)
        return scanned

    @property
    def port_list_length(self) -> int:
        """Number of ports being tested."""
        if isinstance(self.scan.cfg, ScanConfig):
            return len(self.scan.cfg.get_ports())
        return 0

    def get_runtime(self):
        """
        Calculate the runtime of the scan in seconds.

        Returns:
            float: Runtime in seconds
        """
        if self.scan.running or self.end_time is None:
            return time() - self.start_time
        return self.end_time - self.start_time

    def _get_stage_enum(self) -> ScanStage:
        """Convert stage string to ScanStage enum."""
        stage_map = {
            'instantiated': ScanStage.INSTANTIATED,
            'scanning devices': ScanStage.SCANNING_DEVICES,
            'testing ports': ScanStage.TESTING_PORTS,
            'complete': ScanStage.COMPLETE,
            'terminating': ScanStage.TERMINATING,
            'terminated': ScanStage.TERMINATED,
        }
        return stage_map.get(self.stage, ScanStage.INSTANTIATED)

    def get_metadata(self) -> ScanMetadata:
        """
        Get scan metadata as a Pydantic model.

        Returns:
            ScanMetadata: Current scan metadata for status updates
        """
        stage_progress = self.scan.pipeline.get_stage_progress()
        current_idx = self.scan.pipeline.current_stage_index

        # Approximate ports scanned from PortScan stages
        ports_scanned = 0
        ports_total = 0
        for sp in stage_progress:
            if sp.stage_type == StageType.PORT_SCAN:
                ports_scanned += sp.completed
                ports_total += sp.total

        return ScanMetadata(
            scan_id=self.uid,
            subnet=self.subnet,
            port_list=self.port_list,
            running=self.scan.running,
            stage=self._get_stage_enum(),
            percent_complete=self.scan.calc_percent_complete(),
            devices_total=self.devices_total,
            devices_scanned=self.devices_scanned,
            devices_alive=self.devices_alive,
            port_list_length=self.port_list_length,
            ports_scanned=ports_scanned,
            ports_total=ports_total,
            start_time=self.start_time,
            end_time=self.end_time,
            run_time=int(round(self.get_runtime(), 0)),
            errors=self.errors,
            warnings=self.warnings,
            stages=stage_progress,
            current_stage_index=current_idx,
        )

    def to_results(self) -> ScanResults:
        """
        Export scan results as a Pydantic model.

        Returns:
            ScanResults: Complete scan results with metadata, devices, and config
        """
        def _sort_key(obj):
            addr = ipaddress.ip_address(obj.ip)
            return (addr.version, addr.packed)

        sorted_devices = sorted(self.devices, key=_sort_key)
        device_results = [device.to_result() for device in sorted_devices]

        return ScanResults(
            metadata=self.get_metadata(),
            devices=device_results,
            config=self.scan.cfg.to_dict()
        )

    def to_summary(self) -> ScanSummary:
        """
        Get a summary of the scan results.

        Returns:
            ScanSummary: Summary with metadata and aggregate information
        """
        ports_found = set()
        services_found = set()
        for device in self.devices:
            ports_found.update(device.ports)
            services_found.update(device.services.keys())

        return ScanSummary(
            metadata=self.get_metadata(),
            ports_found=sorted(ports_found),
            services_found=sorted(services_found),
            warnings=self.warnings
        )

    def to_list_item(self) -> ScanListItem:
        """
        Get a lightweight representation for scan lists.

        Returns:
            ScanListItem: Minimal scan info for listing
        """
        return ScanListItem(
            scan_id=self.uid,
            subnet=self.subnet,
            running=self.scan.running,
            stage=self._get_stage_enum(),
            percent_complete=self.scan.calc_percent_complete(),
            devices_alive=self.devices_alive,
            devices_total=self.devices_total
        )

    def __str__(self):
        # Prepare data for tabulate
        data = [
            [device.ip, device.hostname, device.get_mac(
            ), ", ".join(map(str, device.ports))]
            for device in self.devices
        ]

        # Create headers for the table
        headers = ["IP", "Host", "MAC", "Ports"]

        # Generate the table using tabulate
        table = tabulate(data, headers=headers, tablefmt="grid")

        # Format and return the complete buffer with table output
        buffer = f"Scan Results - {self.scan.subnet_str} - {self.uid}\n"
        buffer += f'Found/Scanned: {self.devices_alive}/{self.devices_scanned}\n'
        buffer += "---------------------------------------------\n\n"
        buffer += table
        return buffer


class ScanManager:
    """
    Maintain active and completed scans in memory for
    future reference. Singleton implementation.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ScanManager, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'scans'):  # Prevent reinitialization
            self.scans: List[SubnetScanner] = []
            self.log = logging.getLogger('ScanManager')

    def new_scan(self, config: Union[ScanConfig, PipelineConfig]) -> SubnetScanner:
        """
        Create and start a new scan with the given configuration.

        Args:
            config: The scan configuration (ScanConfig or PipelineConfig)

        Returns:
            SubnetScanner: The newly created scan instance
        """
        if isinstance(config, ScanConfig):
            if not is_internal_block(config.subnet) and scan_config_uses_arp(config):
                self.log.warning(
                    f"ARP scanning detected for external subnet '{config.subnet}'. "
                    "ARP requests typically only work within the local network segment. "
                    "Consider using ICMP scanning for external IP ranges."
                )

        scan = SubnetScanner(config)
        self._start(scan)
        self.log.info(f'Scan started - {config}')
        self.scans.append(scan)
        return scan

    def get_scan(self, scan_id: str) -> SubnetScanner:
        """
        Get scan by scan.uid
        """
        for scan in self.scans:
            if scan.uid == scan_id:
                return scan
        return None  # Explicitly return None for consistency

    def terminate_scans(self):
        """
        Terminate all active scans
        """
        for scan in self.scans:
            if scan.running:
                scan.terminate()

    def wait_until_complete(self, scan_id: str) -> SubnetScanner:
        """Wait for a scan to complete."""
        scan = self.get_scan(scan_id)
        while scan.running:
            sleep(.5)
        return scan

    def _start(self, scan: SubnetScanner):
        """
        Start a scan in a separate thread.

        Args:
            scan: The scan to start

        Returns:
            Thread: The thread running the scan
        """
        t = threading.Thread(target=scan.start)
        t.start()
        return t
