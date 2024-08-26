import socket
import struct
import platform
import subprocess
import re
import psutil
import ipaddress
from libraries.mac_lookup import lookup_mac


class DeviceInfo:
    def __init__(self,ip:str):
        self.ip = ip
        self.hostname = self.get_hostname()
        self.mac_addr = self.get_mac_address()
        self.manufacturer = self.get_manufacturer()
    
    def get_mac_address(self):
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
        
    def get_hostname(self):
        """
        Get the hostname of a network device given its IP address.
        """
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror:
            return None
        
    def get_manufacturer(self):
        """
        Get the manufacturer of a network device given its MAC address.
        """
        return lookup_mac(self.mac_addr) if self.mac_addr else None
    

def get_ip_address(interface: str):
    """
    Get the IP address of a network interface.
    """
    def linux():
        try:
            import fcntl
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
        output = subprocess.check_output("ipconfig", shell=True).decode()
        match = re.search(r"IPv4 Address.*?:\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
        return None
    
    if platform.system() == "Windows":
        return windows()
    return linux()

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
        match = re.search(r"Subnet Mask.*?:\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
        return None
    
    if platform.system() == "Windows":
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
    Get the primary network interface.
    """
    addrs = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()
    
    for interface, snicaddrs in addrs.items():
        for snicaddr in snicaddrs:
            if snicaddr.family == socket.AF_INET and gateways[interface].isup:
                return interface
    return None

def get_host_ip_mask(ip_with_cidr: str):
    """
    Get the IP address and netmask of a network interface.
    """
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'

def get_primary_network_subnet():
    """
    Get the primary network interface and subnet.
    """
    primary_interface = get_primary_interface() 
    ip_address = get_ip_address(primary_interface)
    netmask = get_netmask(primary_interface)
    cidr = get_cidr_from_netmask(netmask)

    ip_mask = f'{ip_address}/{cidr}'

    return get_host_ip_mask(ip_mask)
