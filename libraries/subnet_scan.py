import os
import platform
import socket
import subprocess
import sys
from time import sleep
import re
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Network
from time import time
from libraries.decorators import job_tracker
import traceback
from libraries.mac_lookup import lookup_mac
from pathlib import Path

JOB_DIR = './jobs/'


class SubnetScanner:
    def __init__(self, subnet: str, ports: dict):
        self.subnet = IPv4Network(subnet)
        self.ports = ports
        self.running = False
        self.uid = str(uuid.uuid4())

        self.subnet_str = subnet
        self.results = []
        self.stats = {"open_ports": 0, "pingable": 0, "dead": 0, "scanned": 0}
        self.job_stats = {'running': {}, 'finished': {}, 'timing': {}}
        self.errors = []
        self.start_time = time()

    def scan_subnet_threaded(self):
        threading.Thread(target=self.scan_subnet).start()

    def scan_subnet(self):
        self.running = True
        print(f"Scanning subnet {self.subnet}...")
        with ThreadPoolExecutor(max_workers=256) as executor:
            futures = {executor.submit(self._get_host_details, str(ip)): str(ip) for ip in self.subnet}
            for future in futures:
                ip = futures[future]
                try:
                    ans = future.result()
                    if ans:
                        if ans['open_ports']:
                            self.stats['open_ports'] += 1

                        self.stats['pingable'] += 1
                        
                    else:
                        self.stats['dead'] += 1
                except Exception as e:
                    self.errors.append({
                        'basic': f"Error scanning IP {ip}: {e}",
                        'traceback': traceback.format_exc(),
                    })
                
                self.stats['scanned'] += 1
                self.save_job_state()

        self.running = False
        self.save_job_state()





    def save_job_state(self):
        Path(JOB_DIR).mkdir(parents=True, exist_ok=True)

        state = {
            'results': self.results,
            'stats': self.stats,
            'errors': self.errors,
            'job_stats': self.job_stats,
            'running': self.running,
            'uid': self.uid,
            'subnet': self.subnet_str,
            'run_time': time() - self.start_time,
            'ip_count': len(list(self.subnet.hosts())),
        }
        with open(f'{JOB_DIR}{self.uid}.json', 'w') as f:
            json.dump(state, f, indent=2)

    def debug_active_scan(self):
        """
            Run this after running scan_subnet_threaded to see the progress of the scan
        """
        while self.running:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"Running jobs:  {self.job_stats['running']}")
            print(f"Finished jobs: {self.job_stats['finished']}")
            print(f"Job timing:    {self.job_stats['timing']}")
            sleep(1)


    
    def _get_host_details(self, host):
        """
        Get the MAC address and open ports of the given host.
        """
        is_alive = self._ping(host)
        if not is_alive:
            return None
        # add host to results, modify as pass by ref moving forward
        host_info = {'ip': host}
        self.results.append(host_info)
        host_info['hostname'] = self._get_hostname(host)
        host_info['mac'] = self._get_mac_address(host)
        host_info['manufacturer'] = self._get_manufacturer(host_info['mac'])
        host_info['open_ports'] = self._scan_ports(host)

        return host_info
    
    def _get_mac_address(self, ip_address):
        """
        Get the MAC address of a network device given its IP address.
        """
        os = platform.system().lower()
        if os == "windows":
            arp_command = ['arp', '-a', ip_address]
        else:
            arp_command = ['arp', ip_address]
        try:
            output = subprocess.check_output(arp_command, stderr=subprocess.STDOUT, universal_newlines=True)
            output = output.replace('-', ':')
            mac = re.search(r'..:..:..:..:..:..', output)
            return mac.group() if mac else None
        except:
            return None
        
    @job_tracker
    def _get_manufacturer(self, mac_address: str):
        return lookup_mac(mac_address)

    @job_tracker
    def _get_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror:
            return None

    @job_tracker
    def _get_mac_address(self, ip_address):
        """
        Get the MAC address of a network device given its IP address.
        """
        os = platform.system().lower()
        if os == "windows":
            arp_command = ['arp', '-a', ip_address]
        else:
            arp_command = ['arp', ip_address]
        try:
            output = subprocess.check_output(arp_command, stderr=subprocess.STDOUT, universal_newlines=True)
            output = output.replace('-', ':')
            mac = re.search(r'..:..:..:..:..:..', output)
            return mac.group() if mac else None
        except:
            return None

    def _scan_ports(self, host):
        open_ports = []
        with ThreadPoolExecutor(max_workers=128) as executor:
            futures = {executor.submit(self._scan_port, host, int(port)): port for port in self.ports}
            for future in futures:
                port = futures[future]
                if future.result():
                    open_ports.append(port)
        return open_ports
    
    @job_tracker
    def _scan_port(self,host, port):
        """
        Scan a single port on the given host and return True if the port is open, False otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0

    @job_tracker
    def _ping(self, host, retries=1, retry_delay=1, ping_count=2, timeout=1000):
        """
        Ping the given host and return True if it's reachable, False otherwise.
        """
        os = platform.system().lower()
        if os == "windows":
            ping_command = ['ping', '-n', str(ping_count), '-w', str(timeout)]  
        else:
            ping_command = ['ping', '-c', str(ping_count), '-W', str(timeout)]
            
        for _ in range(retries):
            try:
                output = subprocess.check_output(ping_command + [host], stderr=subprocess.STDOUT, universal_newlines=True)
                # Check if 'TTL' or 'time' is in the output to determine success
                if 'TTL' in output.upper():
                    return True
            except subprocess.CalledProcessError:
                pass  # Ping failed
            sleep(retry_delay)
        return False
            
    


common_ports = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    115: 'SFTP',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    194: 'IRC',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP (mail submission)',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'Microsoft SQL Server',
}

if __name__ == "__main__":
    # Define your subnet and ports to scan
    subnet = '10.0.10.0/24'
    ports_to_scan = common_ports.keys()  # Example ports, add more as needed

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner(subnet, ports_to_scan)
    scanner.scan_subnet_threaded()

    while scanner.running:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Running jobs:  {scanner.job_stats['running']}")
        print(f"Finished jobs: {scanner.job_stats['finished']}")
        sleep(1)

# subnet = IPv4Network('10.0.0.0/20')
# ports_to_scan = common_ports.keys()  # Example ports, add more as needed
# scanner = SubnetScanner(subnet, ports_to_scan)
# print(scanner._ping('10.0.0.1'))
# print(scanner._ping('10.0.0.35'))


# def ping(host):
#     """
#     Ping the given host and return True if it's reachable, False otherwise.
#     """
#     ping_command = ['ping', '-n', '1'] if platform.system().lower() == "windows" else ['ping', '-c', '1']
#     with open(os.devnull, 'w') as DEVNULL:
#         try:
#             subprocess.check_call(ping_command + [host], stdout=DEVNULL, stderr=DEVNULL)
#             return True
#         except subprocess.CalledProcessError:
#             return False
        
    

# def scan_ports(host, ports):
#     """
#     Scan the specified ports on the given host and return a dictionary
#     indicating which ports are open.
#     """
#     open_ports = []
#     with ThreadPoolExecutor(max_workers=20) as executor:
#         futures = {executor.submit(scan_port, host, port): port for port in ports}
#         for future in futures:
#             port = futures[future]
#             if future.result():
#                 open_ports.append(port)
        
#     return open_ports

# def scan_port(host, port):
#     """
#     Scan a single port on the given host and return True if the port is open, False otherwise.
#     """
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock.settimeout(1)
#     result = sock.connect_ex((host, port))
#     sock.close()
#     return result == 0



# def scan_subnet(subnet, ports):
#     """
#     Scan all IPs in the specified subnet and store the findings in a JSON file.
#     """
#     start_time = time()
#     results = []
#     stats = {"alive": 0, "pingable": 0, "dead": 0}
#     print(f"Scanning subnet {subnet}...")
#     with ThreadPoolExecutor(max_workers=128) as executor:
#         futures = {executor.submit(ping, str(ip)): str(ip) for ip in subnet}
#         for future in futures:
#             ip = futures[future]
#             try:
#                 if future.result():
#                     open_ports = scan_ports(ip, ports)
#                     mac = get_mac_address(ip)
#                     if open_ports:
#                         stats["alive"] += 1
#                         results.append({"ip": ip, "status": "alive", "mac": mac, "open_ports": open_ports})
#                     else:
#                         stats["pingable"] += 1
#                         results.append({"ip": ip, "status": "pingable", "mac": mac,  "open_ports": []})
#                 else:
#                     stats['dead'] += 1
#             except Exception as e:
#                 print(f"Error scanning IP {ip}: {e}")
#     end_time = time()
#     print(f"Scanning completed in {end_time - start_time:.2f} seconds.")
#     print(f"Alive hosts: {stats['alive']}")
#     print(f"Pingable hosts: {stats['pingable']}")
#     print(f"Dead hosts: {stats['dead']}")

#     # Write results to a JSON file
#     with open('scan_results.json', 'w') as f:
#         json.dump(results, f, indent=4)
#     print("Results saved to scan_results.json")
