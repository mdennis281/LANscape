"""
IP address parsing module for network scanning operations.

This module provides utilities for parsing various IP address formats including:
- Single IP addresses
- CIDR notation subnets
- IP ranges with hyphens (e.g., 192.168.1.1-192.168.1.10)
- Shorthand IP ranges (e.g., 192.168.1.1-10)

It also includes validation to prevent processing excessively large IP ranges.
"""
import ipaddress
import re

from lanscape.libraries.errors import SubnetTooLargeError

MAX_IPS_ALLOWED = 100000


def parse_ip_input(ip_input):
    """
    Parse various IP address format inputs into a list of IPv4Address objects.

    Supports:
    - Comma-separated entries
    - CIDR notation (e.g., 192.168.1.0/24)
    - IP ranges with a hyphen (e.g., 192.168.1.1-192.168.1.10)
    - Shorthand IP ranges (e.g., 192.168.1.1-10)
    - Single IP addresses

    Args:
        ip_input (str): String containing IP addresses in various formats

    Returns:
        list: List of IPv4Address objects

    Raises:
        SubnetTooLargeError: If the number of IPs exceeds MAX_IPS_ALLOWED
    """
    # Split input on commas for multiple entries
    entries = [entry.strip() for entry in ip_input.split(',')]
    ip_ranges = []

    for entry in entries:
        # Handle CIDR notation or IP/32
        if '/' in entry:
            net = ipaddress.IPv4Network(entry, strict=False)
            if net.num_addresses > MAX_IPS_ALLOWED:
                raise SubnetTooLargeError(ip_input)
            for ip in net.hosts():
                ip_ranges.append(ip)

        # Handle IP range (e.g., 10.0.0.15-10.0.0.25)
        elif '-' in entry:
            ip_ranges += parse_ip_range(entry)

        # Handle shorthand IP range (e.g., 10.0.9.1-253)
        elif re.search(r'\d+\-\d+', entry):
            ip_ranges += parse_shorthand_ip_range(entry)

        # If no CIDR or range, assume a single IP
        else:
            ip_ranges.append(ipaddress.IPv4Address(entry))
        if len(ip_ranges) > MAX_IPS_ALLOWED:
            raise SubnetTooLargeError(ip_input)
    return ip_ranges


def get_address_count(subnet: str):
    """
    Get the number of addresses in an IP subnet.

    Args:
        subnet (str): Subnet in CIDR notation

    Returns:
        int: Number of addresses in the subnet, or 0 if invalid
    """
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        return net.num_addresses
    except BaseException:
        return 0


def parse_ip_range(entry):
    """
    Parse an IP range specified with a hyphen (e.g., 192.168.1.1-192.168.1.10).

    Also handles partial end IPs by using the start IP's prefix.

    Args:
        entry (str): String containing an IP range with a hyphen

    Returns:
        list: List of IPv4Address objects in the range (inclusive)
    """
    start_ip, end_ip = entry.split('-')
    start_ip = ipaddress.IPv4Address(start_ip.strip())

    # Handle case where the second part is a partial IP (e.g., '253')
    if '.' not in end_ip:
        end_ip = start_ip.exploded.rsplit('.', 1)[0] + '.' + end_ip.strip()

    end_ip = ipaddress.IPv4Address(end_ip.strip())
    return list(ip_range_to_list(start_ip, end_ip))


def parse_shorthand_ip_range(entry):
    """
    Parse a shorthand IP range (e.g., 192.168.1.1-10).

    In this format, only the last octet of the end IP is specified.

    Args:
        entry (str): String containing a shorthand IP range

    Returns:
        list: List of IPv4Address objects in the range (inclusive)
    """
    start_ip, end_part = entry.split('-')
    start_ip = ipaddress.IPv4Address(start_ip.strip())
    end_ip = start_ip.exploded.rsplit('.', 1)[0] + '.' + end_part.strip()

    return list(ip_range_to_list(start_ip, ipaddress.IPv4Address(end_ip)))


def ip_range_to_list(start_ip, end_ip):
    """
    Convert an IP range defined by start and end addresses to a list of addresses.

    Args:
        start_ip (IPv4Address): The starting IP address
        end_ip (IPv4Address): The ending IP address

    Yields:
        IPv4Address: Each IP address in the range (inclusive)
    """
    # Yield the range of IPs
    for ip_int in range(int(start_ip), int(end_ip) + 1):
        yield ipaddress.IPv4Address(ip_int)
