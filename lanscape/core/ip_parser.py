"""IP address parsing utilities (single, CIDR, ranges) — IPv4 & IPv6."""
import ipaddress
from typing import List, Union

from lanscape.core.errors import SubnetTooLargeError

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

MAX_IPS_ALLOWED = 100000


def _is_ipv6(text: str) -> bool:
    """Return True when *text* looks like an IPv6 address or prefix."""
    return ':' in text.split('/')[0]


def parse_ip_input(ip_input: str) -> List[IPAddress]:
    """
    Parse various IP address format inputs into a list of IP address objects.

    Supports (both IPv4 **and** IPv6):
    - Comma-separated entries
    - CIDR notation (e.g., 192.168.1.0/24 or fd00::/120)
    - IP ranges with a hyphen (e.g., 192.168.1.1-192.168.1.10 or fd00::1-fd00::ff)
    - Shorthand IPv4 ranges (e.g., 192.168.1.1-10)
    - Single IP addresses

    Args:
        ip_input (str): String containing IP addresses in various formats

    Returns:
        list: List of IPv4Address / IPv6Address objects

    Raises:
        SubnetTooLargeError: If the number of IPs exceeds MAX_IPS_ALLOWED
    """
    entries = [entry.strip() for entry in ip_input.split(',')]
    ip_ranges: List[IPAddress] = []

    for entry in entries:
        # Handle CIDR notation
        if '/' in entry:
            net = ipaddress.ip_network(entry, strict=False)
            if net.num_addresses > MAX_IPS_ALLOWED:
                raise SubnetTooLargeError(ip_input, net.num_addresses)
            for ip in net.hosts():
                ip_ranges.append(ip)

        # Handle IP range (e.g., 10.0.0.15-10.0.0.25 or fd00::1-fd00::ff)
        elif '-' in entry:
            ip_ranges += parse_ip_range(entry)

        # Single IP address
        else:
            ip_ranges.append(ipaddress.ip_address(entry))

        if len(ip_ranges) > MAX_IPS_ALLOWED:
            raise SubnetTooLargeError(ip_input, len(ip_ranges))
    return ip_ranges


def get_address_count(subnet: str) -> int:
    """
    Get the number of addresses in an IP subnet (IPv4 or IPv6).

    Args:
        subnet (str): Subnet in CIDR notation

    Returns:
        int: Number of addresses in the subnet, or 0 if invalid
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        return net.num_addresses
    except (ValueError, TypeError):
        return 0


def parse_ip_range(entry: str) -> List[IPAddress]:
    """
    Parse an IP range specified with a hyphen.

    IPv4 examples:
    - ``192.168.1.1-192.168.1.10``
    - ``192.168.1.1-10``  (shorthand — last octet only)

    IPv6 examples:
    - ``fd00::1-fd00::ff``
    - ``fd00::1-ff``  (shorthand — last group only)

    Args:
        entry (str): String containing an IP range with a hyphen

    Returns:
        list: List of IPv4Address / IPv6Address objects in the range (inclusive)
    """
    # For IPv6 we must split on the *last* hyphen so that the address
    # portion (which contains colons but no hyphens) stays intact.
    if _is_ipv6(entry):
        return _parse_ipv6_range(entry)
    return _parse_ipv4_range(entry)


def _parse_ipv4_range(entry: str) -> List[ipaddress.IPv4Address]:
    """Parse an IPv4 range like ``192.168.1.1-10`` or ``192.168.1.1-192.168.1.10``."""
    start_str, end_str = entry.split('-')
    start_ip = ipaddress.IPv4Address(start_str.strip())

    # Shorthand: second part is just the last octet
    if '.' not in end_str:
        end_str = start_ip.exploded.rsplit('.', 1)[0] + '.' + end_str.strip()

    end_ip = ipaddress.IPv4Address(end_str.strip())
    return list(ip_range_to_list(start_ip, end_ip))


def _parse_ipv6_range(entry: str) -> List[ipaddress.IPv6Address]:
    """Parse an IPv6 range like ``fd00::1-fd00::ff`` or ``fd00::1-ff``."""
    # Split on the last hyphen so addresses with ``::`` remain intact.
    idx = entry.rfind('-')
    start_str = entry[:idx].strip()
    end_str = entry[idx + 1:].strip()

    start_ip = ipaddress.IPv6Address(start_str)

    # Shorthand: end part contains no colons → replace last group of start
    if ':' not in end_str:
        prefix = start_ip.exploded.rsplit(':', 1)[0]
        end_str = f"{prefix}:{int(end_str, 16):04x}"

    end_ip = ipaddress.IPv6Address(end_str)
    return list(ip_range_to_list(start_ip, end_ip))


def ip_range_to_list(
    start_ip: IPAddress,
    end_ip: IPAddress,
):
    """
    Convert an IP range defined by start and end addresses to a list of addresses.

    Args:
        start_ip: The starting IP address (IPv4Address or IPv6Address)
        end_ip: The ending IP address (IPv4Address or IPv6Address)

    Yields:
        IPv4Address | IPv6Address: Each IP address in the range (inclusive)
    """
    addr_cls = type(start_ip)
    for ip_int in range(int(start_ip), int(end_ip) + 1):
        yield addr_cls(ip_int)
