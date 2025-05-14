import re
import psutil
import socket
import struct
import logging
import platform
import ipaddress
import traceback
import subprocess
from time import sleep
from typing import List, Dict
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed

from .service_scan import scan_service
from .mac_lookup import lookup_mac, get_macs
from .ip_parser import get_address_count, MAX_IPS_ALLOWED

log = logging.getLogger('NetTools')


class IPAlive:
    def is_alive(self, ip: str) -> bool:
        """
        Run ARP and ping in parallel. As soon as one returns True, we shut
        down the executor (without waiting) and return True. Exceptions
        from either lookup are caught and treated as False.
        """
        executor = ThreadPoolExecutor(max_workers=2)
        futures = [
            executor.submit(self._arp_lookup,  ip),
            executor.submit(self._ping_lookup, ip),
        ]

        for future in as_completed(futures):
            try:
                if future.result():
                    # one check succeeded — don’t block on the other
                    executor.shutdown(wait=False)
                    return True
            except Exception:
                # treat any error as a False response
                pass

        # neither check found the host alive
        executor.shutdown(wait=False)
        return False

    def _arp_lookup(self, ip: str, timeout: int = 4) -> bool:
        arp_request = ARP(pdst=ip)
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request

        answered, _ = srp(packet, timeout=timeout, verbose=False)
        return any(resp.psrc == ip for _, resp in answered)

    def _ping_lookup(
        self, host: str,
        retries: int = 1,
        retry_delay: int = 1,
        ping_count: int = 2,
        timeout: int = 2
    ) -> bool:
        cmd = []
        os_name = platform.system().lower()
        if os_name == "windows":
            # -n count, -w timeout in ms
            cmd = ['ping', '-n', str(ping_count), '-w', str(timeout*1000)]
        else:
            # -c count, -W timeout in s
            cmd = ['ping', '-c', str(ping_count), '-W', str(timeout)]

        for _ in range(retries):
            try:
                output = subprocess.check_output(
                    cmd + [host],
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                # Windows/Linux both include “TTL” on a successful reply
                if 'TTL' in output.upper():
                    return True
            except subprocess.CalledProcessError:
                pass
            sleep(retry_delay)
        return False
    


class Device(IPAlive):
    def __init__(self,ip:str):
        self.ip: str = ip
        self.alive: bool = None
        self.hostname: str = None
        self.macs: List[str] = []
        self.manufacturer: str = None
        self.ports: List[int] = []
        self.stage: str = 'found'
        self.services: Dict[str,List[int]] = {}
        self.log = logging.getLogger('Device')

    def get_metadata(self):
        if self.alive:
            self.hostname = self._get_hostname()
            self.macs = self._get_mac_addresses()

    def dict(self) -> dict:
        obj = vars(self).copy()
        obj.pop('log')
        primary_mac = self.get_mac()
        obj['mac_addr'] = primary_mac
        obj['manufacturer'] = self._get_manufacturer(primary_mac)

        return obj
            
    
    def test_port(self,port:int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.ip, port))
        sock.close()
        if result == 0:
            self.ports.append(port)
            return True
        return False
    
    def scan_service(self,port:int):
        service = scan_service(self.ip,port)
        service_ports = self.services.get(service,[])
        service_ports.append(port)
        self.services[service] = service_ports
    
    def get_mac(self):
        if not self.macs:
            self.macs = self._get_mac_addresses()
        return mac_selector.choose_mac(self.macs)

    def _get_mac_addresses(self):
        """
        Get the MAC address of a network device given its IP address.
        """
        macs = get_macs(self.ip)
        mac_selector.import_macs(macs)
        return macs
        
    def _get_hostname(self):
        """
        Get the hostname of a network device given its IP address.
        """
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror:
            return None
        
    def _get_manufacturer(self,mac_addr=None):
        """
        Get the manufacturer of a network device given its MAC address.
        """
        return lookup_mac(mac_addr) if mac_addr else None
    

class MacSelector:
    """
    Essentially filters out bad mac addresses
    you send in a list of macs, 
    it will return the one that has been seen the least
    (ideally meaning it is the most likely to be the correct one)
    this was added because some lookups return multiple macs,
    usually the hwid of a vpn tunnel etc
    """
    def __init__(self):
        self.macs = {}
    
    def choose_mac(self,macs:List[str]) -> str:
        if len(macs) == 1:
            return macs[0]
        lowest = 9999
        lowest_i = -1

        for mac in macs:
            if self.macs[mac] < lowest:
                lowest = self.macs[mac]
                lowest_i = macs.index(mac)
        return macs[lowest_i] if lowest_i != -1 else None

    
    def import_macs(self,macs:List[str]):
        for mac in macs:
            self.macs[mac] = self.macs.get(mac,0) + 1
    
    def clear(self):
        self.macs = {}

mac_selector = MacSelector()
    

def get_ip_address(interface: str):
    """
    Get the IP address of a network interface on Windows or Linux.
    """
    def linux():
        try:
            import fcntl
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24])
            return ip_address
        except IOError:
            return None

    def windows():
        # Get network interfaces and IP addresses using psutil
        net_if_addrs = psutil.net_if_addrs()
        if interface in net_if_addrs:
            for addr in net_if_addrs[interface]:
                if addr.family == socket.AF_INET:  # Check for IPv4
                    return addr.address
        return None

    # Call the appropriate function based on the platform
    if psutil.WINDOWS:
        return windows()
    elif psutil.LINUX:
        return linux()
    else:
        return None

def get_netmask(interface: str):
    """
    Get the netmask of a network interface.
    """
    
    def linux():
        try:
            import fcntl
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            netmask = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x891b,  # SIOCGIFNETMASK
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24])
            return netmask
        except IOError:
            return None

    def windows():
        output = subprocess.check_output("ipconfig", shell=True).decode()
        # Use a regular expression to match both interface and subnet mask
        interface_section_pattern = rf"{interface}.*?Subnet Mask.*?:\s+(\d+\.\d+\.\d+\.\d+)"
        match = re.search(interface_section_pattern, output, re.S)  # Use re.S to allow dot to match newline
        if match:
            return match.group(1)
        return None
    
    if psutil.WINDOWS:
        return windows()
    return linux()

def get_cidr_from_netmask(netmask: str):
    """
    Get the CIDR notation of a netmask.
    """
    binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8) for x in netmask.split('.')])
    return str(len(binary_str.rstrip('0')))

def get_primary_interface():
    """
    Get the primary network interface based on the default gateway.
    """
    # Get the default gateway information
    gateways = psutil.net_if_addrs()
    default_gw = psutil.net_if_stats()

    # Iterate over the default gateways
    for interface, addrs in gateways.items():
        if default_gw[interface].isup:  # Ensure the interface is up
            for addr in addrs:
                if addr.family == socket.AF_INET:  # Look for IPv4 addresses
                    return interface

    return None

def get_host_ip_mask(ip_with_cidr: str):
    """
    Get the IP address and netmask of a network interface.
    """
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'

def get_network_subnet(interface = get_primary_interface()):
    """
    Get the network interface and subnet.
    Default is primary interface
    """ 
    try:
        ip_address = get_ip_address(interface)
        netmask = get_netmask(interface)
        # is valid interface?
        if ip_address and netmask:
            cidr = get_cidr_from_netmask(netmask)

            ip_mask = f'{ip_address}/{cidr}'

            return get_host_ip_mask(ip_mask)
    except:
        log.info(f'Unable to parse subnet for interface: {interface}')
        log.debug(traceback.format_exc())
    return

def get_all_network_subnets():
    """
    Get the primary network interface.
    """
    addrs = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()
    subnets = []
    
    for interface, snicaddrs in addrs.items():
        for snicaddr in snicaddrs:
            if snicaddr.family == socket.AF_INET and gateways[interface].isup:
                subnet = get_network_subnet(interface)
                if subnet: 
                    subnets.append({ 
                        'subnet': subnet, 
                        'address_cnt': get_address_count(subnet) 
                    })

    return subnets

def smart_select_primary_subnet(subnets: List[dict]=get_all_network_subnets()) -> str:
    """
     Finds the largest subnet within max ip range
     not perfect, but works better than subnets[0]
    """
    selected = {}
    for subnet in subnets:
        if selected.get('address_cnt',0) < subnet['address_cnt'] < MAX_IPS_ALLOWED:
            selected = subnet
    if not selected and len(subnets):
        selected = subnets[0]
    return selected['subnet']


