import os
import json
import uuid
import logging
import ipaddress
import traceback
import threading
from time import time
from time import sleep
from typing import List
from tabulate import tabulate
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from .net_tools import Device
from .ip_parser import parse_ip_input
from .port_manager import PortManager
from.errors import SubnetScanTerminationFailure
from .decorators import job_tracker, JobStats, terminator


TCNT_PORT_SCANS = 10
TCNT_PORT_TEST = 128
TCNT_DEVICE_ISALIVE = 256

@dataclass
class ScanConfig:
    subnet: str
    port_list: str
    parallelism: float = 1.0



class SubnetScanner:
    def __init__(
            self, 
            config: ScanConfig
        ):
        self.subnet = parse_ip_input(config.subnet)
        self.port_list = config.port_list
        self.ports: list = PortManager().get_port_list(config.port_list).keys()
        self.running = False
        self.parallelism: float = float(config.parallelism)
        self.subnet_str = config.subnet
        self.job_stats = JobStats()
        self.uid = str(uuid.uuid4())
        self.results = ScannerResults(self)
        self.log: logging.Logger = logging.getLogger('SubnetScanner')
        self.log.debug(f'Instantiated with uid: {self.uid}')
        self.log.debug(f'Port Count: {len(self.ports)} | Device Count: {len(self.subnet)}')


    
    
    def start(self):
        """
        Scan the subnet for devices and open ports.
        """
        self._set_stage('scanning devices')
        self.running = True
        with ThreadPoolExecutor(max_workers=self._t_cnt(TCNT_DEVICE_ISALIVE)) as executor:
            futures = {executor.submit(self._get_host_details, str(ip)): str(ip) for ip in self.subnet}
            for future in futures:
                ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.log.error(f'[{ip}] scan failed. details below:\n{traceback.format_exc()}')
                    self.results.errors.append({
                        'basic': f"Error scanning IP {ip}: {e}",
                        'traceback': traceback.format_exc(),
                    })
                
        
        self._set_stage('testing ports')
        self._scan_network_ports()
        self.running = False
        self._set_stage('complete')
        
        return self.results
    
    def terminate(self):
        self.running = False
        self._set_stage('terminating')
        for i in range(20):
            if not len(self.job_stats.running.keys()):
                self._set_stage('terminated')
                return True
            sleep(.5)
        raise SubnetScanTerminationFailure(self.job_stats.running)
            
    def calc_percent_complete(self) -> int: # 0 - 100
        if not self.running: return 100

        # --- Host discovery (isalive) calculations ---
        avg_host_detail_sec = self.job_stats.timing.get('_get_host_details', 4.5)
        # assume 10% alive percentage if the scan just started
        if len(self.results.devices) and (self.results.devices_scanned):
            est_subnet_alive_percent = (len(self.results.devices)) / (self.results.devices_scanned)  # avoid div 0
        else:
            est_subnet_alive_percent = .1
        est_subnet_devices = est_subnet_alive_percent * self.results.devices_total

        remaining_isalive_sec = (self.results.devices_total - self.results.devices_scanned) * avg_host_detail_sec
        total_isalive_sec = self.results.devices_total * avg_host_detail_sec

        isalive_multiplier = self._t_cnt(TCNT_DEVICE_ISALIVE)

        # --- Port scanning calculations ---
        device_ports_scanned = self.job_stats.finished.get('_test_port', 0)
        # remediate initial inaccurate results because open ports reurn quickly
        avg_port_test_sec = self.job_stats.timing.get('_test_port', 1) if device_ports_scanned > 20 else 1
            
        device_ports_unscanned = max(0, (est_subnet_devices*len(self.ports)) - device_ports_scanned)

        remaining_port_test_sec = device_ports_unscanned * avg_port_test_sec
        total_port_test_sec = est_subnet_devices * len(self.ports) * avg_port_test_sec

        port_test_multiplier = self._t_cnt(TCNT_PORT_SCANS) * self._t_cnt(TCNT_PORT_TEST)

        # --- Overall progress ---
        est_total_time = (total_isalive_sec / isalive_multiplier) + (total_port_test_sec / port_test_multiplier)
        est_remaining_time = (remaining_isalive_sec / isalive_multiplier) + (remaining_port_test_sec / port_test_multiplier)

        return int(abs((1 - (est_remaining_time / est_total_time)) * 100))

        

    def debug_active_scan(self):
        """
            Run this after running scan_subnet_threaded 
            to see the progress of the scan
        """
        while self.running:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f'{self.uid} - {self.subnet_str}')
            print(f"Scanned: {self.results.devices_scanned}/{self.results.devices_total} - {self.calc_percent_complete()}%")
            print(self.job_stats)
            sleep(1)

    @terminator
    @job_tracker
    def _get_host_details(self, host: str):
        """
        Get the MAC address and open ports of the given host.
        """
        device = Device(host)
        is_alive = self._ping(device)
        self.results.scanned()
        if not is_alive:
            return None
        self.log.debug(f'[{host}] is alive, getting metadata')
        
        device.get_metadata()
        self.results.devices.append(device)
        return True
        
    @terminator
    def _scan_network_ports(self):
        with ThreadPoolExecutor(max_workers=self._t_cnt(TCNT_PORT_SCANS)) as executor:
            futures = {executor.submit(self._scan_ports, device): device for device in self.results.devices}
            for future in futures:
                future.result()

    @terminator
    @job_tracker
    def _scan_ports(self, device: Device):
        self.log.debug(f'[{device.ip}] Initiating port scan')
        device.stage = 'scanning'
        with ThreadPoolExecutor(max_workers=self._t_cnt(TCNT_PORT_TEST)) as executor:
            futures = {executor.submit(self._test_port, device, int(port)): port for port in self.ports}
            for future in futures:
                future.result()
        self.log.debug(f'[{device.ip}] Completed port scan')
        device.stage = 'complete'
    
    @terminator
    @job_tracker
    def _test_port(self,host: Device, port: int):
        """
        Test if a port is open on a given host.
        Device class handles tracking open ports.
        """
        return host.test_port(port)
    
        
    @terminator
    @job_tracker
    def _ping(self, host: Device):
        """
        Ping the given host and return True if it's reachable, False otherwise.
        """
        return host.is_alive(host.ip)
    
    def _t_cnt(self, base_threads: int) -> int:
        """
        Calculate the number of threads to use based on the base number 
        of threads and the parallelism factor.
        """
        return int(base_threads * self.parallelism)
    
    def _set_stage(self,stage):
        self.log.debug(f'[{self.uid}] Moving to Stage: {stage}')
        self.results.stage = stage
        if not self.running:
            self.results.end_time = time()
    
class ScannerResults:
    def __init__(self,scan: SubnetScanner):
        self.scan = scan
        self.port_list: str = scan.port_list
        self.subnet: str = scan.subnet_str
        self.parallelism: float = scan.parallelism
        self.uid = scan.uid

        self.devices_total: int = len(list(scan.subnet))
        self.devices_scanned: int = 0
        self.devices: List[Device] = []

        self.errors: List[str] = []        
        self.running: bool = False
        self.start_time: float = time()
        self.end_time: int = None
        self.stage = 'instantiated'

        self.log = logging.getLogger('ScannerResults')
        self.log.debug(f'Instantiated Logger For Scan: {self.scan.uid}')


    def scanned(self):
        self.devices_scanned += 1

    def get_runtime(self):
        if self.scan.running:
            return int(time()-self.start_time)
        return int(self.end_time-self.start_time)
        

    
    def export(self,out_type=dict) -> str | dict:
        """
            Returns json representation of the scan
        """

        self.running = self.scan.running
        self.run_time = int(round(time() - self.start_time,0))
        self.devices_alive = len(self.devices)

        out = vars(self).copy()
        out.pop('scan')
        out.pop('log')
        
        devices: Device = out.pop('devices')
        sortedDevices = sorted(devices, key=lambda obj: ipaddress.IPv4Address(obj.ip))
        out['devices'] = [vars(device).copy() for device in sortedDevices]
        for device in out['devices']: device.pop('log') 

        if out_type == str:
            return json.dumps(out, indent=2)
        # otherwise return dict
        return out
    
    def __str__(self):
        # Prepare data for tabulate
        data = [
            [device.ip, device.hostname, device.mac_addr, ", ".join(map(str, device.ports))]
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
    future reference
    """
    def __init__(self):
        self.scans: List[SubnetScanner] = []

    def new_scan(self, config: ScanConfig) -> SubnetScanner:
        scan = SubnetScanner(config)
        self._start(scan)
        self.scans.append(scan)
        return scan

    def get_scan(self,scan_id:str) -> SubnetScanner:
        """
        Get scan by scan.uid
        """
        for scan in self.scans:
            if scan.uid == scan_id:
                return scan
            
    def terminate_scans(self):
        """
        terminate all active scans
        """
        for scan in self.scans:
            if scan.running:
                scan.terminate()

    def wait_until_complete(self,scan_id:str) -> SubnetScanner:
        scan = self.get_scan(scan_id)
        while scan.running:
            sleep(.5)
        return scan

    def _start(self,scan:SubnetScanner):
        t = threading.Thread(target=scan.start)
        t.start()
        return t
    


    