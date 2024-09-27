import socket
import struct
import platform
import subprocess
import re
import psutil
import ipaddress
import traceback
import logging
from .mac_lookup import lookup_mac
from .ip_parser import get_address_count
from scapy.all import ARP, Ether, srp
from time import sleep
from typing import List

log = logging.getLogger('NetTools')


class IPAlive:
    
    def is_alive(self,ip:str) -> bool:
        try:
            self.alive = self._arp_lookup(ip)
        except:
            self.log.debug('failed ARP, falling back to ping')
            self.alive = self._ping_lookup(ip)

        return self.alive

    def _arp_lookup(self,ip,timeout=4):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and receive the response
        answered, _ = srp(arp_request_broadcast, timeout=timeout, verbose=False)

        for sent, received in answered:
            if received.psrc == ip:
                if received.hwsrc:
                    self.mac_addr = received.hwsrc
                return True
        return False

    def _ping_lookup(self,host, retries=1, retry_delay=1, ping_count=2, timeout=1):
            """
            Ping the given host and return True if it's reachable, False otherwise.
            """
            os = platform.system().lower()
            if os == "windows":
                ping_command = ['ping', '-n', str(ping_count), '-w', str(timeout*1000)]  
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

class Device(IPAlive):
    def __init__(self,ip:str):
        self.ip: str = ip
        self.alive: bool = None
        self.hostname: str = None
        self.mac_addr: str = None
        self.manufacturer: str = None
        self.ports: List[int] = []
        self.stage: str = 'found'
        self.log = logging.getLogger('Device')

    def get_metadata(self):
        if self.alive:
            self.hostname = self._get_hostname()
            if not self.mac_addr:
                self.mac_addr = self._get_mac_address()
            self.manufacturer = self._get_manufacturer()
            
    
    def test_port(self,port:int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.ip, port))
        sock.close()
        if result == 0:
            self.ports.append(port)
            return True
        return False

    def _get_mac_address(self):
        """
        Get the MAC address of a network device given its IP address.
        """
        os = platform.system().lower()
        if os == "windows":
            arp_command = ['arp', '-a', self.ip]
        else:
            arp_command = ['arp', self.ip]
        try:
            output = subprocess.check_output(arp_command, stderr=subprocess.STDOUT, universal_newlines=True)
            output = output.replace('-', ':')
            mac = re.search(r'..:..:..:..:..:..', output)
            return mac.group() if mac else None
        except:
            return None
        
    def _get_hostname(self):
        """
        Get the hostname of a network device given its IP address.
        """
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror:
            return None
        
    def _get_manufacturer(self):
        """
        Get the manufacturer of a network device given its MAC address.
        """
        return lookup_mac(self.mac_addr) if self.mac_addr else None
    

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


