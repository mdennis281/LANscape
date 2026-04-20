"""Port scanning stage."""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List

from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.models.enums import StageType
from lanscape.core.models.scan import ScanErrorInfo
from lanscape.core.scan_config import PortScanStageConfig, ResilienceConfig
from lanscape.core.models.scan import ScanWarningInfo
from lanscape.core.net_tools.device import Device
from lanscape.core.port_manager import PortManager
from lanscape.core.decorators import job_tracker
from lanscape.core.threadpool_retry import (
    ThreadPoolRetryManager, RetryJob, RetryConfig, MultiplierController,
)


log = logging.getLogger(__name__)


class PortScanStage(ScanStageMixin):
    """Scan open ports and identify services on discovered devices.

    Each device is scanned only for ports that have not been tested yet
    (tracked via :meth:`ScanContext.get_scanned_ports`).  When a second
    port-scan stage uses a larger port list, only the delta ports are
    scanned — already-tested ports are skipped.
    """

    stage_type = StageType.PORT_SCAN
    stage_name = "Port Scan"
    counter_label = "ports scanned"

    def __init__(
        self,
        cfg: PortScanStageConfig,
        *,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.resilience = resilience or ResilienceConfig()

    def execute(self, context: ScanContext) -> None:
        all_ports = set(int(p) for p in PortManager().get_port_list(self.cfg.port_list).keys())

        # Build per-device list of ports not yet tested
        device_port_map: list[tuple[Device, list[int]]] = []
        for device in context.devices:
            new_ports = sorted(all_ports - context.get_scanned_ports(device.ip))
            if new_ports:
                device_port_map.append((device, new_ports))

        if not device_port_map:
            self.log.info("No unscanned ports — skipping port scan")
            return

        self.total = sum(len(ports) for _, ports in device_port_map)

        def on_warning(warning: ScanWarningInfo) -> None:
            context.warnings.append(warning)

        mc = MultiplierController(
            initial_multiplier=self.resilience.t_multiplier,
            decrease_percent=self.resilience.failure_multiplier_decrease,
            debounce_sec=self.resilience.failure_debounce_sec,
            min_multiplier=0.1,
            on_warning=on_warning,
        )
        mc.stage_name = self.stage_name
        retry_config = RetryConfig(
            max_retries=self.resilience.failure_retry_cnt,
            multiplier_decrease=self.resilience.failure_multiplier_decrease,
            debounce_sec=self.resilience.failure_debounce_sec,
        )

        def on_error(job_id: str, error: Exception, tb_str: str) -> None:
            context.errors.append(ScanErrorInfo(
                basic=f"Error scanning ports on {job_id}: {error}",
                traceback=tb_str,
            ))

        max_workers = max(1, int(self.cfg.t_cnt_device * self.resilience.t_multiplier))
        retry_manager = ThreadPoolRetryManager(
            max_workers=max_workers,
            retry_config=retry_config,
            multiplier_controller=mc,
            thread_name_prefix="PortScan",
            on_job_error=on_error,
        )

        jobs = [
            RetryJob(
                job_id=device.ip,
                func=self._scan_device,
                args=(device, ports, context),
                max_retries=self.resilience.failure_retry_cnt,
            )
            for device, ports in device_port_map
        ]
        retry_manager.execute_all(jobs)

    @job_tracker
    def _scan_device(
        self,
        device: Device,
        ports: List[int],
        context: ScanContext,
    ) -> None:
        """Scan all ports on a single device, then mark it port-scanned."""
        device.stage = 'scanning'
        device.ports_scanned = 0
        device.ports_to_scan = len(ports)

        with ThreadPoolExecutor(
            max_workers=self.cfg.t_cnt_port,
            thread_name_prefix=f"{device.ip}-PortScan",
        ) as executor:
            futures = {
                executor.submit(self._test_port, device, port): port
                for port in ports
            }
            for future in futures:
                if not self.running:
                    break
                future.result()

        device.stage = 'complete'
        context.mark_port_scanned(device.ip, set(ports))

    @job_tracker
    def _test_port(self, device: Device, port: int) -> bool:
        """Test a single port and optionally scan its service."""
        is_open = device.test_port(port, self.cfg.port_scan_config)
        self.increment()
        if is_open and self.cfg.scan_services:
            device.scan_service(port, self.cfg.service_scan_config)
        return is_open
