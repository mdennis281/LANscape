import socket
import struct
import platform
import subprocess
import re
import psutil
import ipaddress

def get_ip_address(interface: str):
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
    binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8) for x in netmask.split('.')])
    return str(len(binary_str.rstrip('0')))

def get_primary_interface():
    addrs = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()
    
    for interface, snicaddrs in addrs.items():
        for snicaddr in snicaddrs:
            if snicaddr.family == socket.AF_INET and gateways[interface].isup:
                return interface
    return None

def get_host_ip_mask(ip_with_cidr: str):
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'

def get_primary_network_subnet():
    primary_interface = get_primary_interface() 
    ip_address = get_ip_address(primary_interface)
    netmask = get_netmask(primary_interface)
    cidr = get_cidr_from_netmask(netmask)

    ip_mask = f'{ip_address}/{cidr}'

    return get_host_ip_mask(ip_mask)
