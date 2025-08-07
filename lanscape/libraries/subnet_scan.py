"""
Network subnet scanning module for LANscape.
Provides classes for performing network discovery, device scanning, and port scanning.
Handles scan management, result tracking, and scan termination.
"""

# Standard library imports
import os
import json
import uuid
import logging
import ipaddress
import traceback
import threading
from time import time, sleep
from typing import List, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
from tabulate import tabulate

# Local imports
from lanscape.libraries.scan_config import ScanConfig
from lanscape.libraries.decorators import job_tracker, terminator, JobStatsMixin
from lanscape.libraries.net_tools import Device, is_arp_supported
from lanscape.libraries.errors import SubnetScanTerminationFailure


class SubnetScanner(JobStatsMixin):
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

        # Status properties
        self.running = False
        self.uid = str(uuid.uuid4())
        self.results = ScannerResults(self)
        self.log: logging.Logger = logging.getLogger('SubnetScanner')

        # Initial logging
        if not is_arp_supported():
            self.log.warning(
                'ARP is not supported with the active runtime context. '
                'Device discovery will be limited to ping responses.')
        self.log.debug(f'Instantiated with uid: {self.uid}')
        self.log.debug(
            f'Port Count: {len(self.ports)} | Device Count: {len(self.subnet)}')

    def start(self):
        """
        Scan the subnet for devices and open ports.
        """
        self._set_stage('scanning devices')
        self.running = True
        with ThreadPoolExecutor(max_workers=self.cfg.t_cnt('isalive')) as executor:
            futures = {executor.submit(self._get_host_details, str(
                ip)): str(ip) for ip in self.subnet}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log.error(
                        f'[{ip}] scan failed. details below:\n{traceback.format_exc()}')
                    self.results.errors.append({
                        'basic': f"Error scanning IP {ip}: {e}",
                        'traceback': traceback.format_exc(),
                    })

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
        device = Device(host)
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
        with ThreadPoolExecutor(max_workers=self.cfg.t_cnt('port_scan')) as executor:
            futures = {executor.submit(
                self._scan_ports, device): device for device in self.results.devices}
            for future in futures:
                future.result()

    @terminator
    @job_tracker
    def _scan_ports(self, device: Device):
        self.log.debug(f'[{device.ip}] Initiating port scan')
        device.stage = 'scanning'
        with ThreadPoolExecutor(max_workers=self.cfg.t_cnt('port_test')) as executor:
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
        is_alive = host.test_port(port)
        if is_alive and self.cfg.task_scan_port_services:
            host.scan_service(port)
        return is_alive

    @terminator
    @job_tracker
    def _ping(self, host: Device):
        """
        Ping the given host and return True if it's reachable, False otherwise.
        """
        return host.is_alive(
            host.ip,
            scan_type=self.cfg.lookup_type,
            ping_config=self.cfg.ping_config,
            arp_config=self.cfg.arp_config
        )

    def _set_stage(self, stage):
        self.log.debug(f'[{self.uid}] Moving to Stage: {stage}')
        self.results.stage = stage
        if not self.running:
            self.results.end_time = time()


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
        self.devices: List[Device] = []
        self.devices_alive = 0

        # Status tracking
        self.errors: List[str] = []
        self.running: bool = False
        self.start_time: float = time()
        self.end_time: int = None
        self.stage = 'instantiated'
        self.run_time = 0

        # Logging
        self.log = logging.getLogger('ScannerResults')
        self.log.debug(f'Instantiated Logger For Scan: {self.scan.uid}')

    def scanned(self):
        """
        Increment the count of scanned devices.
        """
        self.devices_scanned += 1

    def get_runtime(self):
        """
        Calculate the runtime of the scan in seconds.

        Returns:
            int: Runtime in seconds
        """
        if self.scan.running:
            return int(time() - self.start_time)
        return int(self.end_time - self.start_time)

    def export(self, out_type=dict) -> Union[str, dict]:
        """
        Export scan results in the specified format.

        Args:
            out_type: The output type (dict or str)

        Returns:
            Union[str, dict]: Scan results in the specified format
        """
        self.running = self.scan.running
        self.run_time = int(round(time() - self.start_time, 0))
        self.devices_alive = len(self.devices)

        out = vars(self).copy()
        out.pop('scan')
        out.pop('log')
        out['cfg'] = vars(self.scan.cfg)

        devices: List[Device] = out.pop('devices')
        sorted_devices = sorted(
            devices, key=lambda obj: ipaddress.IPv4Address(obj.ip))
        out['devices'] = [device.dict() for device in sorted_devices]

        if out_type == str:
            return json.dumps(out, default=str, indent=2)
        # otherwise return dict
        return out

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
