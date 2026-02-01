"""
Network subnet scanning module for LANscape.
Provides classes for performing network discovery, device scanning, and port scanning.
Handles scan management, result tracking, and scan termination.
"""

# Standard library imports
import os
import uuid
import logging
import ipaddress
import threading
from time import time, sleep
from typing import List
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
from tabulate import tabulate

# Local imports
from lanscape.core.scan_config import ScanConfig
from lanscape.core.decorators import job_tracker, terminator, JobStats
from lanscape.core.net_tools import (
    Device, is_internal_block, scan_config_uses_arp
)
from lanscape.core.errors import SubnetScanTerminationFailure
from lanscape.core.device_alive import is_device_alive
from lanscape.core.models import (
    ScanMetadata, ScanResults, ScanStage, ScanSummary, ScanListItem,
    ScanErrorInfo, ScanWarningInfo
)
from lanscape.core.threadpool_retry import (
    ThreadPoolRetryManager, RetryJob, RetryConfig, MultiplierController
)


class SubnetScanner():
    """
    Scans a subnet for devices and open ports.

    Manages the scanning process including device discovery and port scanning.
    Tracks scan progress and provides mechanisms for controlled termination.
    """

    def __init__(
        self,
        config: ScanConfig
    ):
        # Config and network properties
        self.cfg = config
        self.subnet = config.parse_subnet()
        self.ports: List[int] = config.get_ports()
        self.subnet_str = config.subnet
        self.job_stats = JobStats()

        # Status properties
        self.running = False
        self.uid = str(uuid.uuid4())
        self.results = ScannerResults(self)
        self.log: logging.Logger = logging.getLogger('SubnetScanner')

        # Multiplier controller for resilient thread management
        self._multiplier_controller = MultiplierController(
            initial_multiplier=config.t_multiplier,
            decrease_percent=config.failure_multiplier_decrease,
            debounce_sec=config.failure_debounce_sec,
            min_multiplier=0.1,
            on_warning=self._handle_warning
        )

        self.log.debug(f'Instantiated with uid: {self.uid}')
        self.log.debug(
            f'Port Count: {len(self.ports)} | Device Count: {len(self.subnet)}')

    def start(self):
        """
        Scan the subnet for devices and open ports.
        """
        self._set_stage('scanning devices')
        self.running = True

        # Create retry manager for device scanning
        retry_config = RetryConfig(
            max_retries=self.cfg.failure_retry_cnt,
            multiplier_decrease=self.cfg.failure_multiplier_decrease,
            debounce_sec=self.cfg.failure_debounce_sec,
        )

        def on_device_error(job_id: str, error: Exception, tb_str: str):
            """Callback for permanent device scan failures."""
            self.results.errors.append({
                'basic': f"Error scanning IP {job_id}: {error}",
                'traceback': tb_str,
            })

        retry_manager = ThreadPoolRetryManager(
            max_workers=self.cfg.t_cnt('isalive'),
            retry_config=retry_config,
            multiplier_controller=self._multiplier_controller,
            thread_name_prefix="DeviceAlive",
            on_job_error=on_device_error,
        )

        # Create jobs for each IP in the subnet
        jobs = [
            RetryJob(
                job_id=str(ip),
                func=self._get_host_details,
                args=(str(ip),),
                max_retries=self.cfg.failure_retry_cnt,
            )
            for ip in self.subnet
        ]

        # Execute with retry support
        retry_manager.execute_all(jobs)

        self._set_stage('testing ports')
        if self.cfg.task_scan_ports:
            self._scan_network_ports()
        self.running = False
        self._set_stage('complete')

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
        self.running = False
        self._set_stage('terminating')
        for _ in range(20):
            if not self.job_stats.running:
                self._set_stage('terminated')
                return True
            sleep(.5)
        raise SubnetScanTerminationFailure(self.job_stats.running)

    def calc_percent_complete(self) -> int:  # 0 - 100
        """
        Calculate the percentage completion of the scan.

        Uses scan statistics and job timing information to estimate progress.

        Returns:
            int: Completion percentage (0-100)
        """
        if not self.running:
            return 100

        # --- Host discovery (isalive) calculations ---
        avg_host_detail_sec = self.job_stats.timing.get(
            '_get_host_details', 4.5)
        # assume 10% alive percentage if the scan just started
        if self.results.devices and self.results.devices_scanned:
            est_subnet_alive_percent = (
                # avoid div 0
                len(self.results.devices)) / (self.results.devices_scanned)
        else:
            est_subnet_alive_percent = .1
        est_subnet_devices = est_subnet_alive_percent * self.results.devices_total

        remaining_isalive_sec = (
            self.results.devices_total - self.results.devices_scanned) * avg_host_detail_sec
        total_isalive_sec = self.results.devices_total * avg_host_detail_sec

        isalive_multiplier = self.cfg.t_cnt('isalive')

        # --- Port scanning calculations ---
        device_ports_scanned = self.job_stats.finished.get('_test_port', 0)
        # remediate initial inaccurate results because open ports reurn quickly
        avg_port_test_sec = self.job_stats.timing.get(
            '_test_port', 1) if device_ports_scanned > 20 else 1

        device_ports_unscanned = max(
            0, (est_subnet_devices * len(self.ports)) - device_ports_scanned)

        remaining_port_test_sec = device_ports_unscanned * avg_port_test_sec
        total_port_test_sec = est_subnet_devices * \
            len(self.ports) * avg_port_test_sec

        port_test_multiplier = self.cfg.t_cnt(
            'port_scan') * self.cfg.t_cnt('port_test')

        # --- Overall progress ---
        est_total_time = (total_isalive_sec / isalive_multiplier) + \
            (total_port_test_sec / port_test_multiplier)
        est_remaining_time = (remaining_isalive_sec / isalive_multiplier) + \
            (remaining_port_test_sec / port_test_multiplier)

        return int(abs((1 - (est_remaining_time / est_total_time)) * 100))

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
            buffer += f'Scanned: {self.results.devices_scanned}/{self.results.devices_total}'
            buffer += f' - {percent}%\n'
            buffer += str(self.job_stats)
            os.system('cls' if os.name == 'nt' else 'clear')
            print(buffer)
            sleep(sleep_sec)

    @terminator
    @job_tracker
    def _get_host_details(self, host: str):
        """
        Get the MAC address and open ports of the given host.
        """
        device = Device(ip=host)
        device.alive = self._ping(device)
        self.results.scanned()
        if not device.alive:
            return None
        self.log.debug(f'[{host}] is alive, getting metadata')
        device.get_metadata()
        self.results.devices.append(device)
        return True

    @terminator
    def _scan_network_ports(self):
        """Scan ports on all discovered devices using retry manager."""
        retry_config = RetryConfig(
            max_retries=self.cfg.failure_retry_cnt,
            multiplier_decrease=self.cfg.failure_multiplier_decrease,
            debounce_sec=self.cfg.failure_debounce_sec,
        )

        def on_port_scan_error(job_id: str, error: Exception, tb_str: str):
            """Callback for permanent port scan failures."""
            self.results.errors.append({
                'basic': f"Error scanning ports on {job_id}: {error}",
                'traceback': tb_str,
            })

        retry_manager = ThreadPoolRetryManager(
            max_workers=self.cfg.t_cnt('port_scan'),
            retry_config=retry_config,
            multiplier_controller=self._multiplier_controller,
            thread_name_prefix="DevicePortScan",
            on_job_error=on_port_scan_error,
        )

        # Create jobs for each device
        jobs = [
            RetryJob(
                job_id=device.ip,
                func=self._scan_ports,
                args=(device,),
                max_retries=self.cfg.failure_retry_cnt,
            )
            for device in self.results.devices
        ]

        # Execute with retry support
        retry_manager.execute_all(jobs)

    @terminator
    @job_tracker
    def _scan_ports(self, device: Device):
        self.log.debug(f'[{device.ip}] Initiating port scan')
        device.stage = 'scanning'
        with ThreadPoolExecutor(
                max_workers=self.cfg.t_cnt('port_test'),
                thread_name_prefix=f"{device.ip}-PortScan") as executor:
            futures = {executor.submit(self._test_port, device, int(
                port)): port for port in self.ports}
            for future in futures:
                future.result()
        self.log.debug(f'[{device.ip}] Completed port scan')
        device.stage = 'complete'

    @terminator
    @job_tracker
    def _test_port(self, host: Device, port: int):
        """
        Test if a port is open on a given host.
        If port open, determine service.
        Device class handles tracking open ports.
        """
        is_alive = host.test_port(port, self.cfg.port_scan_config)
        if is_alive and self.cfg.task_scan_port_services:
            host.scan_service(port, self.cfg.service_scan_config)
        return is_alive

    @terminator
    @job_tracker
    def _ping(self, host: Device):
        """
        Ping the given host and return True if it's reachable, False otherwise.
        """
        return is_device_alive(host, self.cfg)

    def _set_stage(self, stage):
        self.log.debug(f'[{self.uid}] Moving to Stage: {stage}')
        self.results.stage = stage
        if not self.running:
            self.results.end_time = time()

    def _handle_warning(self, warning_type: str, warning_data: dict):
        """
        Handle a warning from the multiplier controller or other sources.

        Args:
            warning_type: Type of warning (e.g., 'multiplier_reduced')
            warning_data: Dict with warning details
        """
        self.results.warnings.append({
            'type': warning_type,
            **warning_data
        })
        self.log.warning(f'Scan warning [{warning_type}]: {warning_data.get("message", "")}')


class ScannerResults:
    """
    Stores and manages the results of a subnet scan.

    Tracks devices found, scan statistics, and provides export functionality
    for scan results. Also handles runtime calculation and progress tracking.
    """

    def __init__(self, scan: SubnetScanner):
        # Parent reference and identifiers
        self.scan = scan
        self.port_list: str = scan.cfg.port_list
        self.subnet: str = scan.subnet_str
        self.uid = scan.uid

        # Scan statistics
        self.devices_total: int = len(list(scan.subnet))
        self.devices_scanned: int = 0
        self.port_list_length: int = len(scan.ports)
        self.devices: List[Device] = []

        # Status tracking
        self.errors: List[str] = []
        self.warnings: List[dict] = []  # Warnings like multiplier reductions
        self.running: bool = False
        self.start_time: float = time()
        self.end_time: int = None
        self.stage = 'instantiated'
        self.run_time = 0

        # Logging
        self.log = logging.getLogger('ScannerResults')
        self.log.debug(f'Instantiated Logger For Scan: {self.scan.uid}')

    @property
    def devices_alive(self):
        """number of alive devices found in the scan"""
        return len(self.devices)

    def scanned(self):
        """
        Increment the count of scanned devices.
        """
        self.devices_scanned += 1

    def get_runtime(self):
        """
        Calculate the runtime of the scan in seconds.

        Returns:
            float: Runtime in seconds
        """
        if self.scan.running:
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
        # Convert error dicts to ScanErrorInfo models
        error_infos = [
            ScanErrorInfo(basic=err.get('basic', str(err)), traceback=err.get('traceback'))
            if isinstance(err, dict) else ScanErrorInfo(basic=str(err))
            for err in self.errors
        ]

        # Convert warning dicts to ScanWarningInfo models
        warning_infos = [
            ScanWarningInfo(
                type=warn.get('type', 'unknown'),
                message=warn.get('message', str(warn)),
                old_multiplier=warn.get('old_multiplier'),
                new_multiplier=warn.get('new_multiplier'),
                decrease_percent=warn.get('decrease_percent'),
                timestamp=warn.get('timestamp')
            )
            if isinstance(warn, dict) else ScanWarningInfo(type='unknown', message=str(warn))
            for warn in self.warnings
        ]

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
            start_time=self.start_time,
            end_time=self.end_time,
            run_time=int(round(self.get_runtime(), 0)),
            errors=error_infos,
            warnings=warning_infos
        )

    def to_results(self) -> ScanResults:
        """
        Export scan results as a Pydantic model.

        Returns:
            ScanResults: Complete scan results with metadata, devices, and config
        """
        sorted_devices = sorted(
            self.devices, key=lambda obj: ipaddress.IPv4Address(obj.ip))
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

    def new_scan(self, config: ScanConfig) -> SubnetScanner:
        """
        Create and start a new scan with the given configuration.

        Args:
            config: The scan configuration

        Returns:
            SubnetScanner: The newly created scan instance
        """
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
