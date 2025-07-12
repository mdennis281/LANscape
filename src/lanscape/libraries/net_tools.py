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
from scapy.sendrecv import srp
from scapy.layers.l2 import ARP, Ether
from scapy.error import Scapy_Exception
from concurrent.futures import ThreadPoolExecutor, as_completed

from .service_scan import scan_service
from .mac_lookup import lookup_mac, get_macs
from .ip_parser import get_address_count, MAX_IPS_ALLOWED
from .errors import DeviceError

log = logging.getLogger('NetTools')


class IPAlive:
    caught_errors: List[DeviceError] = []

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
                    # one check succeeded — don't block on the other
                    # Cancel remaining futures in a version-compatible way
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    
                    executor.shutdown(wait=False)  # Python 3.8 compatible
                    return True
            except Exception as e:
                # treat any error as a False response
                log.debug(f'Error while checking {ip}: {e}')
                self.caught_errors.append(DeviceError(e))


        # neither check found the host alive
        executor.shutdown()
        return False

    def _arp_lookup(self, ip: str, timeout: int = 3) -> bool:
        arp_request = ARP(pdst=ip)
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request

        answered, _ = srp(packet, timeout=timeout, verbose=False)
        return any(resp.psrc == ip for _, resp in answered)

    def _ping_lookup(
        self, host: str,
        retries: int = 2,
        retry_delay: int = .25,
        ping_count: int = 2,
        timeout: int = 2
    ) -> bool:
        cmd = []
        os_name = platform.system().lower()
        if os_name == "windows":
            # -n count, -w timeout in ms
            cmd = ['ping', '-n', str(ping_count), '-w', str(timeout*1000)]
        else:  # Linux, macOS, and other Unix-like systems
            # -c count, -W timeout in s
            cmd = ['ping', '-c', str(ping_count), '-W', str(timeout)]

        cmd = cmd + [host]

        for r in range(retries):
            try:
                proc = subprocess.run(
                    cmd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if proc.returncode == 0:
                    output = proc.stdout.lower()

                    # Windows/Linux both include “TTL” on a successful reply
                    if psutil.WINDOWS or psutil.LINUX:
                        if 'ttl' in output:
                            return True
                    # some distributions of Linux and macOS
                    if psutil.MACOS or psutil.LINUX:
                        bad = '100.0% packet loss'
                        good = 'ping statistics'
                        # mac doesnt include TTL, so we check good is there, and bad is not
                        if good in output and bad not in output:
                            return True
            except subprocess.CalledProcessError as e:
                self.caught_errors.append(DeviceError(e))
                pass
            if r < retries - 1:
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
        self.caught_errors: List[DeviceError] = []
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
        except socket.herror as e:
            self.caught_errors.append(DeviceError(e))
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
    Get the IP address of a network interface on Windows, Linux, or macOS.
    """
    def unix_like():  # Combined Linux and macOS
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
    else:  # Linux, macOS, and other Unix-like systems
        return unix_like()

def get_netmask(interface: str):
    """
    Get the netmask of a network interface.
    """
    
    def unix_like():  # Combined Linux and macOS
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
    else:  # Linux, macOS, and other Unix-like systems
        return unix_like()

def get_cidr_from_netmask(netmask: str):
    """
    Get the CIDR notation of a netmask.
    """
    binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8) for x in netmask.split('.')])
    return str(len(binary_str.rstrip('0')))

def get_primary_interface():
    """
    Get the primary network interface that is likely handling internet traffic.
    Uses heuristics to identify the most probable interface.
    """
    # Try to find the interface with the default gateway
    try:
        if psutil.WINDOWS:
            # On Windows, parse route print output
            output = subprocess.check_output("route print 0.0.0.0", shell=True, text=True)
            lines = output.strip().split('\n')
            for line in lines:
                if '0.0.0.0' in line and 'Gateway' not in line:  # Skip header
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 4:
                        interface_idx = parts[3]
                        # Find interface name in the output
                        for iface_name, addrs in psutil.net_if_addrs().items():
                            if str(interface_idx) in iface_name:
                                return iface_name
        else:
            # Linux/Unix/Mac - use ip route or netstat
            try:
                output = subprocess.check_output("ip route show default 2>/dev/null || netstat -rn | grep default", 
                                               shell=True, text=True)
                for line in output.split('\n'):
                    if 'default via' in line and 'dev' in line:
                        return line.split('dev')[1].split()[0]
                    elif 'default' in line:
                        parts = line.split()
                        if len(parts) > 3:
                            return parts[-1]  # Interface is usually the last column
            except (subprocess.SubprocessError, IndexError, FileNotFoundError):
                pass
    except Exception as e:
        log.debug(f"Error determining primary interface: {e}")
    
    # Fallback: Identify likely candidates based on heuristics
    candidates = []
    
    for interface, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(interface)
        if stats and stats.isup:
            ipv4_addrs = [addr for addr in addrs if addr.family == socket.AF_INET]
            if ipv4_addrs:
                # Skip loopback and common virtual interfaces
                is_loopback = any(addr.address.startswith('127.') for addr in ipv4_addrs)
                is_virtual = any(name in interface.lower() for name in 
                                ['loop', 'vmnet', 'vbox', 'docker', 'virtual', 'veth'])
                
                if not is_loopback and not is_virtual:
                    candidates.append(interface)
    
    # Prioritize interfaces with names typically used for physical connections
    for prefix in ['eth', 'en', 'wlan', 'wifi', 'wl', 'wi']:
        for interface in candidates:
            if interface.lower().startswith(prefix):
                return interface
    
    # Otherwise return the first candidate or None
    return candidates[0] if candidates else None

def get_host_ip_mask(ip_with_cidr: str):
    """
    Get the IP address and netmask of a network interface.
    """
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'

def get_network_subnet(interface = None):
    """
    Get the network subnet for a given interface.
    Uses network_from_snicaddr for conversion.
    Default is primary interface.
    """
    interface = interface or get_primary_interface()
    
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for snicaddr in addrs[interface]:
                if snicaddr.family == socket.AF_INET and snicaddr.address and snicaddr.netmask:
                    subnet = network_from_snicaddr(snicaddr)
                    if subnet:
                        return subnet
    except Exception:
        log.info(f'Unable to parse subnet for interface: {interface}')
        log.debug(traceback.format_exc())
    return None

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

                subnet = network_from_snicaddr(snicaddr)

                if subnet: 
                    subnets.append({ 
                        'subnet': subnet, 
                        'address_cnt': get_address_count(subnet) 
                    })

    return subnets

def network_from_snicaddr(snicaddr: psutil._common.snicaddr) -> str:
    """
    Convert a psutil snicaddr object to a human-readable string.
    """
    if not snicaddr.address or not snicaddr.netmask:
        return None
    elif snicaddr.family == socket.AF_INET:
        addr = f"{snicaddr.address}/{get_cidr_from_netmask(snicaddr.netmask)}"
    elif snicaddr.family == socket.AF_INET6:
        addr = f"{snicaddr.address}/{snicaddr.netmask}"
    else:
        return f"{snicaddr.address}"
    return get_host_ip_mask(addr)

def smart_select_primary_subnet(subnets: List[dict] | None = None) -> str:
    """
    Intelligently select the primary subnet that is most likely handling internet traffic.
    
    Selection priority:
    1. Subnet associated with the primary interface (with default gateway)
    2. Largest subnet within maximum allowed IP range
    3. First subnet in the list as fallback
    
    Returns an empty string if no subnets are available.
    """
    subnets = subnets or get_all_network_subnets()

    if not subnets:
        return ""
        
    # First priority: Get subnet for the primary interface
    primary_if = get_primary_interface()
    print(f"Primary interface: {primary_if}")
    if primary_if:
        primary_subnet = get_network_subnet(primary_if)
        if primary_subnet:
            # Return this subnet if it's within our list
            for subnet in subnets:
                if subnet["subnet"] == primary_subnet:
                    return primary_subnet

    # Second priority: Find a reasonable sized subnet (existing logic)
    selected = {}
    for subnet in subnets:
        if selected.get("address_cnt", 0) < subnet["address_cnt"] < MAX_IPS_ALLOWED:
            selected = subnet

    # Third priority: Just take the first subnet if nothing else matched
    if not selected and subnets:
        selected = subnets[0]

    return selected.get("subnet", "")

def is_arp_supported():
    """
    Check if ARP requests are supported on the current platform.
    """
    try:
        arp_request = ARP(pdst='0.0.0.0')
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request

        srp(packet, timeout=0, verbose=False)
        return True
    except Scapy_Exception:
        return False


