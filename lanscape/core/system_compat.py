"""
System compatibility utilities.

Single source of truth for all platform-specific logic in LANscape.
All OS-branching code should live here so the rest of the codebase
can remain platform-agnostic.
"""

import ipaddress
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
from typing import List, Optional

import psutil

log = logging.getLogger(__name__)


# ─── IPv6 helpers ───────────────────────────────────────────────────

def _resolve_ipv6_scope_id(addr: ipaddress.IPv6Address) -> int:
    """Return the OS scope-id for reaching *addr* over IPv6, or 0."""
    try:
        info = socket.getaddrinfo(str(addr), 0, socket.AF_INET6, socket.SOCK_DGRAM)
        if info and len(info[0]) >= 5 and len(info[0][4]) >= 4:
            return info[0][4][3]
    except OSError:
        pass
    return 0


def is_ipv6(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv6 address string."""
    ip_no_zone = ip.split('%', 1)[0]
    try:
        return isinstance(ipaddress.ip_address(ip_no_zone), ipaddress.IPv6Address)
    except ValueError:
        return False


def get_socket_family(ip: str) -> int:
    """Return ``AF_INET6`` for IPv6 addresses, ``AF_INET`` otherwise."""
    return socket.AF_INET6 if is_ipv6(ip) else socket.AF_INET





# ─── Virtual interface filtering ────────────────────────────────────
# Canonical list of interface name substrings that indicate non-LAN adapters.
# Covers: loopback, VMware, VirtualBox, Docker, Hyper-V/WSL, ZeroTier,
# Tailscale, WireGuard, TUN/TAP, Cisco VPN, libvirt bridges.
VIRTUAL_IFACE_NAMES: tuple[str, ...] = (
    'loop', 'vmnet', 'vbox', 'docker', 'virtual', 'veth',
    'vethernet', 'zerotier', 'tailscale', 'tun', 'tap',
    'wg', 'utun', 'virbr', 'br-', 'ham',
)


# ─── NDP / IPv6 interface helpers ───────────────────────────────────

def get_ipv6_interface_scopes() -> List[str]:
    """Return scope identifiers for ``ff02::1%<scope>`` multicast pings.

    On Windows the scope is the numeric interface index; on Linux/macOS
    it is the interface name.  Only active, non-loopback interfaces with
    IPv6 connectivity are returned.
    """
    scopes: list[str] = []

    if psutil.WINDOWS:
        try:
            out = subprocess.check_output(
                'netsh interface ipv6 show interfaces',
                shell=True, timeout=5, stderr=subprocess.DEVNULL,
            ).decode(errors='replace')
            for line in out.splitlines():
                parts = line.split()
                # Format: Idx  Met  MTU  State  Name
                if len(parts) >= 5 and parts[3].lower() == 'connected':
                    idx = parts[0]
                    name = ' '.join(parts[4:])
                    if 'loopback' not in name.lower():
                        scopes.append(idx)
        except Exception:  # pylint: disable=broad-except
            pass
    else:
        for name, addrs in psutil.net_if_addrs().items():
            has_v6 = any(
                a.family == socket.AF_INET6
                and a.address
                and not a.address.startswith('::1')
                for a in addrs
            )
            if has_v6:
                stats = psutil.net_if_stats().get(name)
                if stats and stats.isup:
                    scopes.append(name)

    return scopes


def get_ndp_ping_command(target: str) -> List[str]:
    """Return a command list to ICMPv6-ping *target* (e.g. ``ff02::1%scope``)."""
    if psutil.WINDOWS:
        return ['ping', '-6', '-n', '2', '-w', '1000', target]
    if psutil.MACOS:
        return ['ping6', '-c', '2', '-W', '2', target]
    return ['ping', '-6', '-c', '2', '-W', '2', target]


# ─── ARP packet helpers (Scapy) ────────────────────────────────────

def send_arp_request(ip: str, timeout: float = 1.0) -> tuple:
    """Build and send a broadcast ARP request via Scapy.

    Returns the ``(answered, unanswered)`` tuple from ``srp``.
    Imports Scapy lazily so non-Scapy code paths never pay the cost.

    ARP is IPv4-only; calling with an IPv6 address returns ``([], [])``.
    The outgoing interface is resolved from the OS routing table so the
    packet is always sent on the correct adapter (e.g. not a VPN / virtual
    interface) even when the system has multiple network adapters.
    """
    if is_ipv6(ip):
        return ([], [])

    from scapy.sendrecv import srp          # pylint: disable=import-outside-toplevel
    from scapy.layers.l2 import ARP, Ether  # pylint: disable=import-outside-toplevel
    from scapy.config import conf as scapy_conf  # pylint: disable=import-outside-toplevel

    # Resolve the outbound interface via Scapy's routing table so we pick
    # the correct adapter when multiple interfaces are present (e.g. a
    # ZeroTier / VPN adapter is the "default" but the physical NIC is the
    # right one for a LAN target).
    try:
        iface = scapy_conf.route.route(ip)[0]
    except Exception:  # pylint: disable=broad-except
        iface = scapy_conf.iface

    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, unanswered = srp(packet, timeout=timeout, verbose=False, iface=iface)
    return answered, unanswered


# ─── ICMP / Ping ───────────────────────────────────────────────────

def icmp_requires_privileged() -> bool:
    """Whether ICMP raw sockets require privileged mode on this OS."""
    return bool(psutil.WINDOWS)


def get_ping_command(count: int, timeout_ms: int, ip: str) -> List[str]:
    """Build the platform-appropriate ping command.

    *timeout_ms* is always in milliseconds; conversion to seconds for
    Unix platforms is handled internally.
    Handles both IPv4 and IPv6 addresses.
    """
    v6 = is_ipv6(ip)
    if psutil.WINDOWS:
        flag = '-6' if v6 else '-4'
        return ['ping', flag, '-n', str(count), '-w', str(timeout_ms), ip]
    # Linux, macOS, and other Unix-like systems (-W takes seconds)
    timeout_sec = str(max(1, timeout_ms // 1000))
    if v6:
        # Linux: prefer `ping -6` (works in minimal containers where ping6 may be missing)
        # macOS/others: use ping6 if available, else fall back to `ping -6`
        if psutil.LINUX:
            return ['ping', '-6', '-c', str(count), '-W', timeout_sec, ip]
        ping6_path = shutil.which('ping6')
        if ping6_path:
            return [ping6_path, '-c', str(count), '-W', timeout_sec, ip]
        return ['ping', '-6', '-c', str(count), '-W', timeout_sec, ip]
    return ['ping', '-c', str(count), '-W', timeout_sec, ip]


def parse_ping_success(output: str) -> bool:
    """Determine whether *output* from a ping command indicates success."""
    lower = output.lower()

    # Windows/Linux both include "TTL" on a successful reply
    if psutil.WINDOWS or psutil.LINUX:
        if 'ttl' in lower:
            return True

    # macOS (and some Linux distros) don't always show TTL
    if psutil.MACOS or psutil.LINUX:
        if 'ping statistics' in lower and '100.0% packet loss' not in lower:
            return True

    return False


# ─── Hostname resolution strategy ──────────────────────────────────

def os_handles_hostname_resolution() -> bool:
    """Return True if the OS resolver already chains mDNS/NetBIOS/LLMNR.

    On Windows, ``gethostbyaddr`` natively queries NetBIOS+LLMNR+mDNS,
    so manual fallback to raw mDNS/NetBIOS is unnecessary.
    """
    return bool(psutil.WINDOWS)


def resolve_hostname_avahi(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve hostname via avahi-resolve-address (Linux mDNS daemon).

    This is the recommended approach on Linux when avahi is installed,
    as it uses the system's mDNS responder which maintains a cache and
    handles IPv6 properly.

    Returns the hostname (without .local suffix) or None on failure.
    """
    if psutil.WINDOWS or psutil.MACOS:
        return None

    avahi_path = shutil.which('avahi-resolve-address')
    if not avahi_path:
        return None

    try:
        # Strip scope ID for avahi
        clean_ip = ip.split('%')[0]
        result = subprocess.run(
            [avahi_path, '-a', clean_ip],
            capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output format: "192.168.1.1\tmyhostname.local"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                hostname = parts[-1]
                # Remove .local suffix if present
                if hostname.endswith('.local'):
                    hostname = hostname[:-6]
                return hostname
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None


def resolve_hostname_dnssd(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve hostname via dns-sd (macOS mDNS system service).

    Uses the macOS mDNSResponder daemon for reverse lookups. This is the
    preferred approach on macOS as it accesses the system's full mDNS
    cache and handles both IPv4 and IPv6.

    Returns the hostname (without .local suffix) or None on failure.
    """
    if not psutil.MACOS:
        return None

    dnssd_path = shutil.which('dns-sd')
    if not dnssd_path:
        return None

    try:
        # Build the PTR query name
        clean_ip = ip.split('%')[0]
        if is_ipv6(clean_ip):
            addr = ipaddress.IPv6Address(clean_ip)
            nibbles = addr.exploded.replace(':', '')
            reversed_name = '.'.join(reversed(nibbles)) + '.ip6.arpa'
        else:
            reversed_name = '.'.join(reversed(clean_ip.split('.'))) + '.in-addr.arpa'

        # dns-sd -Q <name> PTR - queries for PTR record
        result = subprocess.run(
            [dnssd_path, '-t', str(timeout), '-Q', reversed_name, 'PTR'],
            capture_output=True, text=True, timeout=timeout + 1, check=False
        )
        # Parse output for hostname
        for line in result.stdout.splitlines():
            # Look for PTR record in output
            if 'PTR' in line and '.local' in line.lower():
                # Extract hostname from PTR record value
                match = re.search(r'PTR\s+(\S+)', line)
                if match:
                    hostname = match.group(1).rstrip('.')
                    if hostname.endswith('.local'):
                        hostname = hostname[:-6]
                    return hostname
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None


# ─── Shared DNS / hostname helpers ──────────────────────────────────

_HOSTNAME_SUFFIXES = ('.local', '.lan', '.home')


def _strip_hostname_suffix(hostname: str) -> str:
    """Remove common hostname suffixes (.local, .lan, .home)."""
    for suffix in _HOSTNAME_SUFFIXES:
        if hostname.endswith(suffix):
            return hostname[:-len(suffix)]
    return hostname


def _encode_dns_name(qname: str) -> bytes:
    """Encode a dotted domain name into DNS wire format."""
    name_bytes = b''
    for label in qname.split('.'):
        name_bytes += bytes([len(label)]) + label.encode('ascii')
    return name_bytes + b'\x00'


def _build_ptr_query(qname: str, txn_id: bytes = b'\x00\x00',
                     qclass: bytes = b'\x00\x01') -> bytes:
    """Build a DNS PTR query packet for the given query name."""
    return (
        txn_id
        + b'\x00\x00'   # Flags: standard query
        + b'\x00\x01'   # Questions: 1
        + b'\x00\x00'   # Answers: 0
        + b'\x00\x00'   # Authority: 0
        + b'\x00\x00'   # Additional: 0
        + _encode_dns_name(qname)
        + b'\x00\x0c'   # Type: PTR
        + qclass
    )


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Skip a DNS name in wire format, returning the offset past the name."""
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            return offset + 2
        offset += data[offset] + 1
    return offset + 1


def _read_dns_labels(data: bytes, offset: int) -> List[str]:
    """Read DNS name labels starting at *offset*, following compression pointers."""
    labels: List[str] = []
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((data[offset] & 0x3F) << 8) | data[offset + 1]
            labels.extend(_read_dns_labels(data, pointer))
            break
        length = data[offset]
        offset += 1
        if offset + length <= len(data):
            labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length
    return labels


def _extract_ptr_hostname(output: str) -> Optional[str]:
    """Extract hostname from 'host' command PTR output."""
    for line in output.splitlines():
        if 'domain name pointer' not in line.lower():
            continue
        parts = line.strip().rstrip('.').split()
        if parts:
            return _strip_hostname_suffix(parts[-1])
    return None


def resolve_hostname_getent(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve hostname via getent hosts (Linux NSS resolution).

    Uses the system's Name Service Switch (NSS) which chains multiple
    resolution methods including DNS, mDNS (via nss-mdns), WINS, etc.
    Often more reliable than direct mDNS calls on properly configured systems.

    Returns the hostname or None on failure.
    """
    if not psutil.LINUX:
        return None

    getent_path = shutil.which('getent')
    if not getent_path:
        return None

    try:
        clean_ip = ip.split('%')[0]
        result = subprocess.run(
            [getent_path, 'hosts', clean_ip],
            capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output format: "192.168.1.1 hostname hostname.local"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                # Take the first hostname (shortest, usually without domain)
                return _strip_hostname_suffix(parts[1])
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None


def resolve_hostname_host_cmd(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve hostname via the 'host' command (reverse DNS lookup).

    Uses the standard DNS 'host' utility available on most Unix systems.
    Works for both IPv4 and IPv6 addresses.

    Returns the hostname or None on failure.
    """
    if psutil.WINDOWS:
        return None

    host_path = shutil.which('host')
    if not host_path:
        return None

    try:
        clean_ip = ip.split('%')[0]
        result = subprocess.run(
            [host_path, clean_ip],
            capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            return _extract_ptr_hostname(result.stdout)
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None


def resolve_hostname_llmnr(ip: str, timeout: float = 1.5) -> Optional[str]:
    """Resolve hostname via LLMNR reverse query.

    Link-Local Multicast Name Resolution (RFC 4795) is commonly used by
    Windows devices and can resolve hostnames even when mDNS/NetBIOS fail.
    Supports both IPv4 and IPv6 targets.

    Returns the hostname or None on failure.
    """
    try:
        clean_ip = ip.split('%')[0]
        addr = ipaddress.ip_address(clean_ip)
    except ValueError:
        return None

    # Build reverse query name
    if addr.version == 6:
        nibbles = addr.exploded.replace(':', '')
        qname = '.'.join(reversed(nibbles)) + '.ip6.arpa'
    else:
        qname = '.'.join(reversed(str(addr).split('.'))) + '.in-addr.arpa'

    # Build LLMNR PTR query packet
    request = _build_ptr_query(qname, txn_id=b'\x00\x01')

    sock = None
    try:
        if addr.version == 6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            scope_id = _resolve_ipv6_scope_id(addr)
            if scope_id:
                sock.sendto(request, ('ff02::1:3', 5355, 0, scope_id))
            else:
                sock.sendto(request, ('ff02::1:3', 5355))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # LLMNR IPv4 multicast address
            sock.sendto(request, ('224.0.0.252', 5355))

        data, _ = sock.recvfrom(1500)
        return _parse_llmnr_ptr_response(data)
    except (socket.timeout, OSError):
        return None
    finally:
        if sock:
            sock.close()


def _parse_llmnr_ptr_response(data: bytes) -> Optional[str]:
    """Parse an LLMNR PTR response and extract the hostname."""
    if len(data) < 12:
        return None

    answer_count = (data[6] << 8) | data[7]
    if answer_count == 0:
        return None

    # Skip question name + QTYPE/QCLASS, then answer name + TYPE/CLASS/TTL/RDLENGTH
    offset = _skip_dns_name(data, 12) + 4
    offset = _skip_dns_name(data, offset) + 10

    if offset > len(data):
        return None

    rdlength = (data[offset - 2] << 8) | data[offset - 1]
    if rdlength == 0 or offset >= len(data):
        return None

    labels = _read_dns_labels(data, offset)
    return labels[0] if labels else None


# ─── Network interface helpers ──────────────────────────────────────

def get_ip_address(interface: str) -> Optional[str]:
    """Get the IPv4 address assigned to *interface*."""
    if psutil.WINDOWS:
        return _get_ip_address_windows(interface)
    return _get_ip_address_unix(interface)


def _get_ip_address_windows(interface: str) -> Optional[str]:
    net_if_addrs = psutil.net_if_addrs()
    if interface in net_if_addrs:
        for addr in net_if_addrs[interface]:
            if addr.family == socket.AF_INET:
                return addr.address
    return None


def _get_ip_address_unix(interface: str) -> Optional[str]:
    try:
        import fcntl  # pylint: disable=import-outside-toplevel,import-error
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24])
        finally:
            sock.close()
    except (IOError, ImportError):
        return None


def get_netmask(interface: str) -> Optional[str]:
    """Get the netmask of *interface*."""
    if psutil.WINDOWS:
        return _get_netmask_windows(interface)
    return _get_netmask_unix(interface)


def _get_netmask_windows(interface: str) -> Optional[str]:
    output = subprocess.check_output("ipconfig", shell=True).decode()
    pattern = rf"{interface}.*?Subnet Mask.*?:\s+(\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, output, re.S)
    return match.group(1) if match else None


def _get_netmask_unix(interface: str) -> Optional[str]:
    try:
        import fcntl  # pylint: disable=import-outside-toplevel,import-error
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x891b,  # SIOCGIFNETMASK
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24])
        finally:
            sock.close()
    except (IOError, ImportError):
        return None


def get_primary_interface() -> Optional[str]:
    """Detect the primary network interface (the one with a default gateway).

    Falls back to heuristic-based candidate selection.
    """
    if psutil.WINDOWS:
        iface = _find_interface_by_default_gateway_windows()
    else:
        iface = _find_interface_by_default_gateway_unix()

    if iface:
        return iface

    # Fallback: pick best candidate by heuristic
    candidates = get_candidate_interfaces()
    if not candidates:
        return None

    physical_prefixes = ['eth', 'en', 'wlan', 'wifi', 'wl', 'wi']
    for prefix in physical_prefixes:
        for candidate in candidates:
            if candidate.lower().startswith(prefix):
                return candidate

    return candidates[0]


def get_candidate_interfaces() -> List[str]:
    """Return non-virtual, IP-capable (IPv4 or IPv6), up interfaces."""
    candidates = []
    for interface, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(interface)
        if not stats or not stats.isup:
            continue

        ip_families = {socket.AF_INET, socket.AF_INET6}
        ip_addrs = [a for a in addrs if a.family in ip_families]
        if not ip_addrs:
            continue

        # Skip loopback
        if any(a.address.startswith('127.') for a in ip_addrs if a.family == socket.AF_INET):
            continue
        v6_addrs = [a for a in ip_addrs if a.family == socket.AF_INET6]
        if v6_addrs and all(a.address == '::1' for a in v6_addrs):
            continue

        if any(name in interface.lower() for name in VIRTUAL_IFACE_NAMES):
            continue

        candidates.append(interface)
    return candidates


# ── Private gateway detection helpers ───────────────────────────────

def _find_interface_by_default_gateway_windows() -> Optional[str]:
    try:
        output = subprocess.check_output(
            "route print 0.0.0.0", shell=True, text=True)
        return _parse_windows_route_output(output)
    except Exception as exc:
        log.debug("Error finding Windows interface by gateway: %s", exc)
    return None


def _parse_windows_route_output(output: str) -> Optional[str]:
    lines = output.strip().split('\n')
    interface_idx = None

    for line in lines:
        if '0.0.0.0' in line and 'Gateway' not in line:
            parts = [p for p in line.split() if p]
            if len(parts) >= 4:
                interface_idx = parts[3]
                break

    if interface_idx:
        for iface_name in psutil.net_if_addrs():
            if str(interface_idx) in iface_name:
                return iface_name
    return None


def _find_interface_by_default_gateway_unix() -> Optional[str]:
    try:
        cmd = "ip route show default 2>/dev/null || netstat -rn | grep default"
        output = subprocess.check_output(cmd, shell=True, text=True)
        return _parse_unix_route_output(output)
    except Exception as exc:
        log.debug("Error finding Unix interface by gateway: %s", exc)
    return None


def _parse_unix_route_output(output: str) -> Optional[str]:
    for line in output.split('\n'):
        if 'default via' in line and 'dev' in line:
            return line.split('dev')[1].split()[0]
        if 'default' in line:
            parts = line.split()
            if len(parts) > 3:
                return parts[-1]
    return None


def clear_screen() -> None:
    """Clear the terminal (debug utility)."""
    os.system('cls' if psutil.WINDOWS else 'clear')


# ── Local interface MAC lookup ──────────────────────────────────────

# Cache mapping local IPs → MACs (built lazily on first call).
_LOCAL_IP_MAC_CACHE: Optional[dict] = None


def _build_local_ip_mac_map() -> dict[str, str]:
    """Build a mapping of every local IP address to its interface MAC."""
    ip_to_mac: dict[str, str] = {}
    for _iface, addrs in psutil.net_if_addrs().items():
        mac = None
        ips: list[str] = []
        for a in addrs:
            # psutil uses AF_LINK on macOS/BSD, AF_PACKET on Linux,
            # and a negative sentinel on Windows — all for L2 addresses.
            if a.family in (psutil.AF_LINK, getattr(socket, 'AF_PACKET', -1)):
                if a.address and a.address != '00:00:00:00:00:00':
                    mac = a.address.lower().replace('-', ':')
            elif a.family in (socket.AF_INET, socket.AF_INET6):
                addr = a.address.split('%')[0]  # strip scope-id
                ips.append(addr)
        if mac:
            for ip in ips:
                ip_to_mac[ip] = mac
    return ip_to_mac


def get_local_mac_for_ip(ip: str) -> Optional[str]:
    """Return the MAC address of the local interface that owns *ip*, or ``None``."""
    global _LOCAL_IP_MAC_CACHE  # pylint: disable=global-statement
    if _LOCAL_IP_MAC_CACHE is None:
        _LOCAL_IP_MAC_CACHE = _build_local_ip_mac_map()
    return _LOCAL_IP_MAC_CACHE.get(ip)


def refresh_local_ip_mac_cache() -> None:
    """Force-rebuild the local IP→MAC cache (e.g. after interface changes)."""
    global _LOCAL_IP_MAC_CACHE  # pylint: disable=global-statement
    _LOCAL_IP_MAC_CACHE = _build_local_ip_mac_map()


def configure_asyncio_exception_handler(loop) -> None:
    """
    Configure a custom exception handler for asyncio event loops.

    On Windows, the ProactorEventLoop raises ConnectionResetError during
    socket cleanup when a connection is forcibly closed by the remote host.
    This is a known issue (WinError 10054) that occurs in internal callbacks
    like ``_call_connection_lost()`` and should be suppressed.

    Args:
        loop: The asyncio event loop to configure
    """
    if not psutil.WINDOWS:
        return  # Only needed on Windows

    original_handler = loop.get_exception_handler()

    def _windows_exception_handler(loop, context):
        exc = context.get('exception')

        # Suppress ConnectionResetError (WinError 10054) during socket cleanup
        if isinstance(exc, ConnectionResetError):
            # This is expected when connections are forcibly closed
            return

        # Suppress OSError with specific Windows error codes during cleanup
        if isinstance(exc, OSError) and getattr(exc, 'winerror', None) in (
            10054,  # Connection reset by remote host
            10053,  # Connection aborted by local software
            10038,  # Operation on non-socket
        ):
            return

        # For all other exceptions, use the original handler or default
        if original_handler:
            original_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_windows_exception_handler)


# ─── Per-device ARP/NDP cache query ────────────────────────────────

# Regex for extracting a MAC from a single-target ARP/NDP result.
# Uses {1,2} per octet because macOS arp(8) omits leading zeros
# (e.g. "6:94:e6:c8:e4:22" instead of "06:94:e6:c8:e4:22").
_SINGLE_ARP_MAC_RE = re.compile(
    r'([0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}'
    r'[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2})'
)


def query_single_arp_entry(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Query the OS ARP/NDP cache for a single IP and return its MAC.

    This is the pre-3.5.0 style per-device subprocess approach:
    - Windows:  ``arp -a <ip>``
    - Linux:    ``ip neigh show <ip>``
    - macOS:    ``arp -n <ip>``

    For IPv6 targets Linux uses ``ip -6 neigh show <ip>``.

    Returns the MAC address string (lowercase, colon-separated) or
    ``None`` if the entry is not found / incomplete.
    """
    clean_ip = ip.split('%')[0]
    v6 = is_ipv6(clean_ip)

    try:
        if psutil.WINDOWS:
            if v6:
                cmd = ['netsh', 'interface', 'ipv6', 'show', 'neighbors']
            else:
                cmd = ['arp', '-a', clean_ip]
        elif psutil.LINUX:
            flag = '-6' if v6 else '-4'
            cmd = ['ip', flag, 'neigh', 'show', clean_ip]
        else:
            # macOS / BSD
            if v6:
                cmd = ['ndp', '-an']
            else:
                cmd = ['arp', '-n', clean_ip]

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False
        )
        output = result.stdout

        # For commands that dump the full table, filter for our target IP
        if v6 and (psutil.WINDOWS or psutil.MACOS):
            target_lines = [
                ln for ln in output.splitlines()
                if clean_ip in ln
            ]
            output = '\n'.join(target_lines)

        match = _SINGLE_ARP_MAC_RE.search(output)
        if match:
            raw = match.group(1).lower().replace('-', ':')
            # Zero-pad each octet (macOS omits leading zeros)
            mac = ':'.join(o.zfill(2) for o in raw.split(':'))
            # Reject null / broadcast MACs
            if mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                return mac
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None
