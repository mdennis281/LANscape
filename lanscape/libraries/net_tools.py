"""Network tools for scanning and managing devices on a network."""

import logging
import ipaddress
import traceback
import subprocess
from time import sleep
from typing import List, Dict
import socket
import struct
import re
import psutil
from icmplib import ping

from scapy.sendrecv import srp
from scapy.layers.l2 import ARP, Ether
from scapy.error import Scapy_Exception

from lanscape.libraries.service_scan import scan_service
from lanscape.libraries.mac_lookup import MacLookup, get_macs
from lanscape.libraries.ip_parser import get_address_count, MAX_IPS_ALLOWED
from lanscape.libraries.errors import DeviceError
from lanscape.libraries.decorators import job_tracker, JobStatsMixin, timeout_enforcer
from lanscape.libraries.scan_config import ScanType, PingConfig, ArpConfig

log = logging.getLogger('NetTools')


class IPAlive(JobStatsMixin):
    """Class to check if a device is alive using ARP and/or ping scans."""
    caught_errors: List[DeviceError] = []
    _icmp_alive: bool = False
    _arp_alive: bool = False

    @job_tracker
    def is_alive(
        self,
        ip: str,
        scan_type: ScanType = ScanType.BOTH,
        arp_config: ArpConfig = ArpConfig(),
        ping_config: PingConfig = PingConfig()
    ) -> bool:
        """
        Check if a device is alive by performing ARP and/or ping scans.
        """
        if scan_type == ScanType.ARP:
            return self._arp_lookup(ip, arp_config)
        if scan_type == ScanType.PING:
            return self._ping_lookup(ip, ping_config)
        return self._ping_lookup(ip, ping_config) or self._arp_lookup(ip, arp_config)

    @job_tracker
    def _arp_lookup(
        self, ip: str,
        cfg: ArpConfig = ArpConfig()
    ) -> bool:
        """Perform an ARP lookup to check if the device is alive."""
        enforcer_timeout = cfg.timeout * 1.3

        @timeout_enforcer(enforcer_timeout, raise_on_timeout=True)
        def do_arp_lookup():
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=cfg.timeout, verbose=False)
            self._arp_alive = any(resp.psrc == ip for _, resp in answered)
            return self._arp_alive

        try:
            for _ in range(cfg.attempts):
                if do_arp_lookup():
                    return True
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
        return False

    @job_tracker
    def _ping_lookup(
        self, ip: str,
        cfg: PingConfig = PingConfig()
    ) -> bool:
        """Perform a ping lookup to check if the device is alive using icmplib."""
        enforcer_timeout = cfg.timeout * cfg.ping_count * 1.3

        @timeout_enforcer(enforcer_timeout, raise_on_timeout=False)
        def do_icmp_ping():
            try:
                result = ping(
                    ip,
                    count=cfg.ping_count,
                    interval=cfg.retry_delay,
                    timeout=cfg.timeout,
                    privileged=psutil.WINDOWS  # Use privileged mode on Windows
                )
                return result.is_alive
            except Exception as e:
                self.caught_errors.append(DeviceError(e))
                # Fallback to system ping command
                try:
                    if psutil.WINDOWS:
                        cmd = [
                            "ping", "-n", str(cfg.ping_count),
                            "-w", str(int(cfg.timeout * 1000)), ip
                        ]
                    else:
                        cmd = ["ping", "-c",
                               str(cfg.ping_count), "-W", str(cfg.timeout), ip]

                    result = subprocess.run(
                        cmd, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True, check=False
                    )
                    return result.returncode == 0
                except subprocess.CalledProcessError as fallback_error:
                    self.caught_errors.append(DeviceError(fallback_error))
                    return False

        try:
            for _ in range(cfg.attempts):
                if do_icmp_ping():
                    self._icmp_alive = True
                    return True
                sleep(cfg.retry_delay)
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
        self._icmp_alive = False
        return False


class Device(IPAlive):
    """Represents a network device with metadata and scanning capabilities."""

    def __init__(self, ip: str):
        super().__init__()
        self.ip: str = ip
        self.alive: bool = None
        self.hostname: str = None
        self.macs: List[str] = []
        self.manufacturer: str = None
        self.ports: List[int] = []
        self.stage: str = 'found'
        self.services: Dict[str, List[int]] = {}
        self.caught_errors: List[DeviceError] = []
        self.log = logging.getLogger('Device')
        self._mac_lookup = MacLookup()

    def get_metadata(self):
        """Retrieve metadata such as hostname and MAC addresses."""
        if self.alive:
            self.hostname = self._get_hostname()
            self.macs = self._get_mac_addresses()

    def dict(self) -> dict:
        """Convert the device object to a dictionary."""
        obj = vars(self).copy()
        obj.pop('log')
        obj.pop('job_stats', None)  # Remove job_stats if it exists
        primary_mac = self.get_mac()
        obj['mac_addr'] = primary_mac
        obj['manufacturer'] = self._get_manufacturer(primary_mac)

        return obj

    def test_port(self, port: int) -> bool:
        """Test if a specific port is open on the device."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.ip, port))
        sock.close()
        if result == 0:
            self.ports.append(port)
            return True
        return False

    @job_tracker
    def scan_service(self, port: int):
        """Scan a specific port for services."""
        service = scan_service(self.ip, port)
        service_ports = self.services.get(service, [])
        service_ports.append(port)
        self.services[service] = service_ports

    def get_mac(self):
        """Get the primary MAC address of the device."""
        if not self.macs:
            return ''
        return mac_selector.choose_mac(self.macs)

    @job_tracker
    def _get_mac_addresses(self):
        """Get the possible MAC addresses of a network device given its IP address."""
        macs = get_macs(self.ip)
        mac_selector.import_macs(macs)
        return macs

    @job_tracker
    def _get_hostname(self):
        """Get the hostname of a network device given its IP address."""
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror as e:
            self.caught_errors.append(DeviceError(e))
            return None

    @job_tracker
    def _get_manufacturer(self, mac_addr=None):
        """Get the manufacturer of a network device given its MAC address."""
        return self._mac_lookup.lookup_vendor(mac_addr) if mac_addr else None


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

    def choose_mac(self, macs: List[str]) -> str:
        """
        Choose the most appropriate MAC address from a list.
        The mac address that has been seen the least is returned.
        """
        if len(macs) == 1:
            return macs[0]
        lowest = 9999
        lowest_i = -1
        for mac in macs:
            if self.macs[mac] < lowest:
                lowest = self.macs[mac]
                lowest_i = macs.index(mac)
        return macs[lowest_i] if lowest_i != -1 else None

    def import_macs(self, macs: List[str]):
        """
        Import a list of MAC addresses associated with a device.
        """
        for mac in macs:
            self.macs[mac] = self.macs.get(mac, 0) + 1

    def clear(self):
        """Clear the stored MAC addresses."""
        self.macs = {}


mac_selector = MacSelector()


def get_ip_address(interface: str):
    """
    Get the IP address of a network interface on Windows, Linux, or macOS.
    """
    def unix_like():  # Combined Linux and macOS
        try:
            # pylint: disable=import-outside-toplevel, import-error
            import fcntl
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDRf
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

    # Linux, macOS, and other Unix-like systems
    return unix_like()


def get_netmask(interface: str):
    """
    Get the netmask of a network interface.
    """
    def unix_like():  # Combined Linux and macOS
        try:
            # pylint: disable=import-outside-toplevel, import-error
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
        # Use re.S to allow dot to match newline
        match = re.search(interface_section_pattern, output, re.S)
        if match:
            return match.group(1)
        return None

    if psutil.WINDOWS:
        return windows()

    # Linux, macOS, and other Unix-like systems
    return unix_like()


def get_cidr_from_netmask(netmask: str):
    """
    Get the CIDR notation of a netmask.
    """
    binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8)
                         for x in netmask.split('.')])
    return str(len(binary_str.rstrip('0')))


def _find_interface_by_default_gateway_windows():
    """Find the network interface with the default gateway on Windows."""
    try:
        output = subprocess.check_output(
            "route print 0.0.0.0", shell=True, text=True)
        return _parse_windows_route_output(output)
    except Exception as e:
        log.debug(f"Error finding Windows interface by gateway: {e}")
    return None


def _parse_windows_route_output(output):
    """Parse the output of Windows route command to extract interface index."""
    lines = output.strip().split('\n')
    interface_idx = None

    # First find the interface index from the routing table
    for line in lines:
        if '0.0.0.0' in line and 'Gateway' not in line:  # Skip header
            parts = [p for p in line.split() if p]
            if len(parts) >= 4:
                interface_idx = parts[3]
                break

    # If we found an index, find the corresponding interface name
    if interface_idx:
        for iface_name in psutil.net_if_addrs():
            if str(interface_idx) in iface_name:
                return iface_name

    return None


def _find_interface_by_default_gateway_unix():
    """Find the network interface with the default gateway on Unix-like systems."""
    try:
        cmd = "ip route show default 2>/dev/null || netstat -rn | grep default"
        output = subprocess.check_output(cmd, shell=True, text=True)
        return _parse_unix_route_output(output)
    except Exception as e:
        log.debug(f"Error finding Unix interface by gateway: {e}")
    return None


def _parse_unix_route_output(output):
    """Parse the output of Unix route commands to extract interface name."""
    for line in output.split('\n'):
        # Parse lines with 'default via ... dev ...'
        if 'default via' in line and 'dev' in line:
            return line.split('dev')[1].split()[0]

        # Parse simpler 'default ...' lines
        if 'default' in line:
            parts = line.split()
            if len(parts) > 3:
                # Interface is usually the last column
                return parts[-1]
    return None


def _get_candidate_interfaces():
    """Get a list of candidate network interfaces."""
    candidates = []
    for interface, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(interface)
        if not stats or not stats.isup:
            continue

        ipv4_addrs = [addr for addr in addrs if addr.family == socket.AF_INET]
        if not ipv4_addrs:
            continue

        # Skip loopback and common virtual interfaces
        is_loopback = any(addr.address.startswith('127.')
                          for addr in ipv4_addrs)
        if is_loopback:
            continue

        virtual_names = ['loop', 'vmnet', 'vbox', 'docker', 'virtual', 'veth']
        is_virtual = any(name in interface.lower() for name in virtual_names)
        if is_virtual:
            continue

        candidates.append(interface)
    return candidates


def get_primary_interface():
    """
    Get the primary network interface that is likely handling internet traffic.
    Uses heuristics to identify the most probable interface.
    """
    # Try to find the interface with the default gateway
    if psutil.WINDOWS:
        interface = _find_interface_by_default_gateway_windows()
        if interface:
            return interface
    else:
        interface = _find_interface_by_default_gateway_unix()
        if interface:
            return interface

    # Fallback: Identify likely candidates based on heuristics
    candidates = _get_candidate_interfaces()
    if not candidates:
        return None

    # Prioritize interfaces with names typically used for physical connections
    physical_prefixes = ['eth', 'en', 'wlan', 'wifi', 'wl', 'wi']
    for prefix in physical_prefixes:
        for interface in candidates:
            if interface.lower().startswith(prefix):
                return interface

    # Otherwise return the first candidate
    return candidates[0]


def get_host_ip_mask(ip_with_cidr: str):
    """
    Get the IP address and netmask of a network interface.
    """
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'


def get_network_subnet(interface=None):
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

    if snicaddr.family == socket.AF_INET:
        addr = f"{snicaddr.address}/{get_cidr_from_netmask(snicaddr.netmask)}"
        return get_host_ip_mask(addr)

    if snicaddr.family == socket.AF_INET6:
        addr = f"{snicaddr.address}/{snicaddr.netmask}"
        return get_host_ip_mask(addr)

    return f"{snicaddr.address}"


def smart_select_primary_subnet(subnets: List[dict] = None) -> str:
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
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        srp(packet, timeout=0, verbose=False)
        return True
    # Scapy_Exception = MacOS
    # PermissionError = Linux
    # RuntimeError = Windows
    except (Scapy_Exception, PermissionError, RuntimeError):
        return False
