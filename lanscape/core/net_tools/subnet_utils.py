"""Subnet/network utility functions."""

import ipaddress
import logging
import socket
import traceback
from typing import List

import psutil
from scapy.error import Scapy_Exception

from lanscape.core.ip_parser import get_address_count, parse_ip_input

# Cap used in subnet listing to avoid JS integer overflow for very large IPv6 subnets
_SUBNET_LIST_CAP = 100_000
from lanscape.core.decorators import run_once
from lanscape.core.scan_config import ScanType
from lanscape.core.system_compat import (
    get_primary_interface,
    send_arp_request,
)

log = logging.getLogger('NetTools')


def get_cidr_from_netmask(netmask: str) -> str:
    """Convert a dotted netmask to CIDR prefix length string."""
    binary_str = ''.join([bin(int(x)).lstrip('0b').zfill(8)
                         for x in netmask.split('.')])
    return str(len(binary_str.rstrip('0')))


def get_host_ip_mask(ip_with_cidr: str) -> str:
    """Normalise an IP/CIDR string to network-address/prefix form."""
    cidr = ip_with_cidr.split('/')[1]
    network = ipaddress.ip_network(ip_with_cidr, strict=False)
    return f'{network.network_address}/{cidr}'


def _get_ipv6_prefix(addr: str, netmask: str | None) -> int:
    """
    Determine the IPv6 prefix length.

    On Linux/macOS, psutil provides the prefix in netmask.
    On Windows, netmask is None - we use common defaults:
    - /10 for link-local (fe80::/10 range)
    - /64 for global addresses (most common)
    """
    if netmask is not None:
        try:
            return int(netmask)
        except ValueError:
            pass

    # Windows fallback: determine prefix from address type
    try:
        addr_obj = ipaddress.IPv6Address(addr.split('%')[0])
        if addr_obj.is_link_local:
            return 10  # Link-local /10 range
        if addr_obj.is_loopback:
            return 128  # Loopback is a single host
    except ValueError:
        pass
    return 64  # Assume /64 for global (most common prefix)


def _is_scannable_ipv6(addr: str) -> bool:
    """Return True if the IPv6 address is in a scannable range (not link-local/loopback)."""
    try:
        addr_obj = ipaddress.IPv6Address(addr.split('%')[0])
        if addr_obj.is_link_local:
            return False  # Link-local - not scannable across network
        if addr_obj.is_loopback:
            return False  # Loopback
    except ValueError:
        return False
    return True


def network_from_snicaddr(snicaddr: psutil._common.snicaddr) -> str | None:
    """Convert a psutil snicaddr to a ``network/prefix`` string, or ``None`` if not derivable."""
    if not snicaddr.address:
        return None

    if snicaddr.family == socket.AF_INET:
        if not snicaddr.netmask:
            return None
        addr = f"{snicaddr.address}/{get_cidr_from_netmask(snicaddr.netmask)}"
        return get_host_ip_mask(addr)

    if snicaddr.family == socket.AF_INET6:
        # Filter out non-scannable IPv6 addresses
        if not _is_scannable_ipv6(snicaddr.address):
            return None
        prefix = _get_ipv6_prefix(snicaddr.address, snicaddr.netmask)
        # Strip zone ID (e.g., %eth0) if present
        addr_clean = snicaddr.address.split('%')[0]
        addr = f"{addr_clean}/{prefix}"
        return get_host_ip_mask(addr)

    return f"{snicaddr.address}"


def get_network_subnet(interface=None) -> str | None:
    """Return the ``network/prefix`` for *interface* (default: primary)."""
    interface = interface or get_primary_interface()

    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for snicaddr in addrs[interface]:
                # IPv4 requires netmask; IPv6 can infer prefix via _get_ipv6_prefix()
                if (
                    snicaddr.family == socket.AF_INET
                    and snicaddr.address
                    and snicaddr.netmask
                ) or (
                    snicaddr.family == socket.AF_INET6
                    and snicaddr.address
                ):
                    subnet = network_from_snicaddr(snicaddr)
                    if subnet:
                        return subnet
    except Exception:
        log.info(f'Unable to parse subnet for interface: {interface}')
        log.debug(traceback.format_exc())
    return None


def get_all_network_subnets() -> List[dict]:
    """Return a list of ``{subnet, address_cnt, interface}`` dicts for every active interface.

    Deduplicates subnets per interface (multiple IPs on same subnet return one entry).
    """
    addrs = psutil.net_if_addrs()
    gateways = psutil.net_if_stats()
    subnets = []
    seen = set()  # Track (subnet, interface) pairs to dedupe

    for interface, snicaddrs in addrs.items():
        iface_stats = gateways.get(interface)
        if not iface_stats or not iface_stats.isup:
            continue
        for snicaddr in snicaddrs:
            if snicaddr.family in (socket.AF_INET, socket.AF_INET6):
                subnet = network_from_snicaddr(snicaddr)
                if subnet:
                    key = (subnet, interface)
                    if key in seen:
                        continue
                    seen.add(key)
                    # Cap address_cnt to avoid JS integer overflow for large IPv6 subnets
                    raw_count = get_address_count(subnet)
                    capped_count = min(raw_count, _SUBNET_LIST_CAP)
                    subnets.append({
                        'subnet': subnet,
                        'address_cnt': capped_count,
                        'interface': interface,
                    })

    return subnets


def smart_select_primary_subnet(subnets: List[dict] = None) -> str:
    """Intelligently select the primary subnet most likely handling internet traffic.

    Selection priority:
    1. Subnet associated with the primary interface (with default gateway)
    2. Largest non-deprioritized subnet within maximum allowed IP range
    3. Largest deprioritized subnet as fallback
    4. First subnet in the list as final fallback
    """
    subnets = subnets or get_all_network_subnets()

    if not subnets:
        return ""

    primary_if = get_primary_interface()
    if primary_if:
        primary_subnet = get_network_subnet(primary_if)
        if primary_subnet:
            for subnet in subnets:
                if subnet["subnet"] == primary_subnet:
                    return primary_subnet

    selected = {}
    deprioritized_selected = {}

    for subnet in subnets:
        subnet_str = subnet.get("subnet", "")
        address_cnt = subnet.get("address_cnt", 0)

        if address_cnt >= _SUBNET_LIST_CAP:
            continue

        if _is_deprioritized_subnet(subnet_str):
            if address_cnt > deprioritized_selected.get("address_cnt", 0):
                deprioritized_selected = subnet
        else:
            if address_cnt > selected.get("address_cnt", 0):
                selected = subnet

    if not selected:
        selected = deprioritized_selected

    if not selected and subnets:
        selected = subnets[0]

    return selected.get("subnet", "")


def _is_deprioritized_subnet(subnet: str) -> bool:
    """Check if a subnet should be deprioritized (loopback, WSL, Docker, link-local)."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)

        deprioritized = [
            ipaddress.ip_network('127.0.0.0/8'),       # IPv4 loopback
            ipaddress.ip_network('::1/128'),            # IPv6 loopback
            ipaddress.ip_network('fe80::/10'),          # IPv6 link-local
            ipaddress.ip_network('172.27.64.0/20'),     # WSL
            ipaddress.ip_network('172.17.0.0/16'),      # Docker
        ]

        return any(network.overlaps(net) for net in deprioritized)
    except ValueError:
        return False


def is_internal_block(subnet: str) -> bool:
    """Check if a subnet contains only internal/private IP addresses."""
    try:
        if ',' in subnet:
            return all(is_internal_block(part.strip()) for part in subnet.split(','))

        if '/' in subnet:
            return ipaddress.ip_network(subnet, strict=False).is_private

        ip_list = parse_ip_input(subnet)
        sample_ips = ([ip_list[0], ip_list[-1]] if len(ip_list) > 1 else ip_list)
        return all(ipaddress.ip_address(str(ip)).is_private for ip in sample_ips)

    except (ValueError, ipaddress.AddressValueError):
        return False


def scan_config_uses_arp(config) -> bool:
    """Check if a scan configuration uses ARP-based scanning methods."""
    arp_scan_types = {
        ScanType.ARP_LOOKUP,
        ScanType.POKE_THEN_ARP,
        ScanType.ICMP_THEN_ARP
    }
    return any(scan_type in arp_scan_types for scan_type in config.lookup_type)


@run_once
def is_arp_supported() -> bool:
    """Check if ARP requests are supported on the current system."""
    try:
        send_arp_request('0.0.0.0', timeout=0)
        return True
    except (Scapy_Exception, PermissionError, RuntimeError, Exception):  # noqa: BLE001
        return False


# ═══════════════════════════════════════════════════════════════════
#  Subnet classification helpers (used by auto_stages & scan_pipeline)
# ═══════════════════════════════════════════════════════════════════


def is_ipv6_subnet(subnet: str) -> bool:
    """Return True if *subnet* is an IPv6 address, network, or range."""
    try:
        return isinstance(
            ipaddress.ip_network(subnet, strict=False),
            ipaddress.IPv6Network,
        )
    except ValueError:
        return ':' in subnet.split('/')[0]


def is_local_subnet(subnet: str) -> bool:
    """Return True if *subnet* overlaps with any interface on this machine."""
    try:
        target = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False

    for entry in get_all_network_subnets():
        try:
            iface_net = ipaddress.ip_network(entry['subnet'], strict=False)
            if target.overlaps(iface_net):
                return True
        except ValueError:
            continue
    return False


def matching_interface(subnet: str) -> str | None:
    """Return the name of the first interface whose subnet overlaps *subnet*."""
    try:
        target = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None

    for entry in get_all_network_subnets():
        try:
            iface_net = ipaddress.ip_network(entry['subnet'], strict=False)
            if target.overlaps(iface_net):
                return entry.get('interface')
        except ValueError:
            continue
    return None


def get_os_platform() -> str:
    """Return a normalised OS identifier: 'windows', 'linux', or 'darwin'."""
    if psutil.WINDOWS:
        return 'windows'
    if psutil.LINUX:
        return 'linux'
    return 'darwin'
