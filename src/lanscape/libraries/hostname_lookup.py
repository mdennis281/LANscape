import socket
from zeroconf import Zeroconf
import dns.resolver
import dns.reversename
from scapy.all import arping

def get_hostname(ip: str) -> str:
    """
    Get the hostname of a network device given its IP address.
    Tries multiple methods in sequence until successful.
    """
    # Method 1: Try DNS resolution using socket.gethostbyaddr
    hostname = _get_hostname_dns(ip)
    if hostname:
        return hostname, 'socket'

    # Method 2: Try Reverse DNS using dnspython
    hostname = _get_hostname_reverse_dns(ip)
    if hostname:
        return hostname, 'dnspython'

    # Method 3: Try mDNS lookup using zeroconf
    hostname = _get_hostname_mdns(ip)
    if hostname:
        return hostname, 'zeroconf'

    # Method 4: Try ARP lookup using scapy
    hostname = _get_hostname_arp(ip)
    if hostname:
        return hostname, 'scapy'

    # If all methods fail, return None
    return None, 'none'

def _get_hostname_dns(ip: str) -> str:
    """Attempt to get hostname via socket DNS resolution."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def _get_hostname_reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup using dnspython."""
    try:
        addr = dns.reversename.from_address(ip)
        return str(dns.resolver.resolve(addr, "PTR")[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None

def _get_hostname_mdns(ip: str) -> str:
    """Attempt mDNS lookup using zeroconf."""
    try:
        zeroconf = Zeroconf()
        info = zeroconf.get_service_info("_http._tcp.local.", f"{ip}.local.")
        return info.server if info else None
    except Exception:
        return None
    finally:
        zeroconf.close()

def _get_hostname_arp(ip: str) -> str:
    """Attempt to get hostname via ARP lookup using scapy."""
    try:
        ans, _ = arping(ip, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv.hwsrc  # Return MAC address if hostname isn't available
    except Exception:
        return None

