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
from typing import List, Optional, Tuple

import psutil

from lanscape.core.decorators import run_once


log = logging.getLogger(__name__)


# ─── IPv6 helpers ───────────────────────────────────────────────────

def is_ipv6(ip: str) -> bool:
    """Return True if *ip* is an IPv6 address string."""
    return ':' in ip


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


# ─── ARP commands ───────────────────────────────────────────────────

@run_once
def get_linux_arp_command() -> Tuple[List[str], str]:
    """Get the ARP cache command for Linux, with fallback.

    Prefers ``ip neigh show`` (iproute2) over ``arp -n`` (net-tools).
    Result is cached via ``@run_once``.
    """
    if shutil.which('ip'):
        return (['ip', 'neigh', 'show'], 'ip neigh show')

    if shutil.which('arp'):
        return (['arp', '-n'], 'arp -n')

    log.warning(
        "Neither 'ip' nor 'arp' command found - ARP lookup is unavailable. "
        "Please install the 'iproute2' or 'net-tools' package to enable ARP cache lookups."
    )
    raise RuntimeError(
        "No suitable ARP command found on this Linux system. "
        "Install 'iproute2' (providing 'ip') or 'net-tools' (providing 'arp')."
    )


def get_arp_cache_command() -> List[str]:
    """Get the platform-appropriate ARP cache command (list form, no IP arg)."""
    if psutil.WINDOWS:
        return ['arp', '-a']
    if psutil.LINUX:
        cmd_list, _ = get_linux_arp_command()
        return cmd_list
    if psutil.MACOS:
        return ['arp', '-n']

    raise NotImplementedError("Unsupported platform")


def get_arp_lookup_command(ip: str) -> str:
    """Get a shell-string command for resolving a single IP's MAC/link-layer address.

    For IPv6 targets, uses the appropriate neighbor-discovery command.
    """
    if is_ipv6(ip):
        return _get_ipv6_neighbor_command(ip)
    if psutil.WINDOWS:
        return f"arp -a {ip}"
    if psutil.LINUX:
        _, cmd_str = get_linux_arp_command()
        return f"{cmd_str} {ip}"
    return f"arp {ip}"


def _get_ipv6_neighbor_command(ip: str) -> str:
    """Get the platform-appropriate IPv6 neighbor cache command for a single IP.

    Note: For Windows and macOS, we return the full neighbor table and rely on
    Python-side parsing to perform an exact IP match, avoiding fragile shell-level
    substring filters (e.g., `findstr {ip}` / `grep {ip}`) that can incorrectly
    match partial IPv6 addresses.
    """
    if psutil.WINDOWS:
        # Full table; caller must perform exact IP matching when parsing.
        return "netsh interface ipv6 show neighbors"
    if psutil.LINUX:
        # `ip -6 neigh show {ip}` already performs an exact lookup for the IP.
        return f"ip -6 neigh show {ip}"
    if psutil.MACOS:
        # Full table; caller must perform exact IP matching when parsing.
        return "ndp -an"
    return f"ip -6 neigh show {ip}"


# ─── Neighbor-table dump (full table) ──────────────────────────────

# (want_v6, platform) → shell command for dumping the full neighbor table.
_NEIGHBOR_DUMP_CMDS: dict[tuple[bool, str], str] = {
    (True, 'windows'): 'netsh interface ipv6 show neighbors',
    (True, 'linux'): 'ip -6 neigh show',
    (True, 'macos'): 'ndp -an',
    (False, 'windows'): 'arp -a',
    (False, 'linux'): 'ip -4 neigh show',
    (False, 'macos'): 'arp -an',
}


def get_neighbor_dump_command(want_v6: bool) -> str | None:
    """Return a shell command that dumps the full neighbor table for a protocol.

    *want_v6* selects IPv6 (``True``) or IPv4 (``False``) entries.
    Returns ``None`` on unsupported platforms.
    """
    if psutil.WINDOWS:
        platform = 'windows'
    elif psutil.LINUX:
        platform = 'linux'
    elif psutil.MACOS:
        platform = 'macos'
    else:
        return None
    return _NEIGHBOR_DUMP_CMDS.get((want_v6, platform))


# ─── Neighbor-table output parsing ─────────────────────────────────

_IP4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
_IP6_RE = re.compile(r'([0-9a-fA-F:]{3,}(?:::[0-9a-fA-F]{1,4}|:[0-9a-fA-F]{1,4}){1,})')


def extract_ips_for_mac(output: str, mac: str, want_v6: bool) -> List[str]:
    """Parse neighbor-table output and return IPs associated with *mac*.

    Handles output from Linux ``ip neigh``, Windows ``arp``/``netsh``,
    and macOS ``arp``/``ndp``.  MAC comparisons are case-insensitive and
    normalise dash separators to colons.
    """
    results: list[str] = []
    mac_lower = mac.lower().replace('-', ':')

    for line in output.splitlines():
        line_lower = line.lower().replace('-', ':')
        if mac_lower not in line_lower:
            continue

        pattern = _IP6_RE if want_v6 else _IP4_RE
        match = pattern.search(line)
        if not match:
            continue

        candidate = match.group(1)
        try:
            addr = ipaddress.ip_address(candidate.split('%')[0])
        except ValueError:
            continue

        if want_v6 and addr.version != 6:
            continue
        if not want_v6 and addr.version != 4:
            continue
        if addr.is_loopback:
            continue

        results.append(str(addr))

    return results


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


def get_ndp_ping_command(target: str) -> str:
    """Return a shell command to ICMPv6-ping *target* (e.g. ``ff02::1%scope``)."""
    if psutil.WINDOWS:
        return f"ping -6 -n 2 -w 1000 {target}"
    if psutil.MACOS:
        return f"ping6 -c 2 -W 2 {target}"
    return f"ping -6 -c 2 -W 2 {target}"


# ─── MAC address extraction ────────────────────────────────────────

_MAC_RE = re.compile(r'..:..:..:..:..:..')


def extract_mac_from_output(output: str) -> List[str]:
    """Extract MAC addresses from command output (normalises ``-`` to ``:``).

    Returns all matches found in *output*.
    """
    return _MAC_RE.findall(output.replace('-', ':'))


# ─── ARP packet helpers (Scapy) ────────────────────────────────────

def send_arp_request(ip: str, timeout: float = 1.0) -> tuple:
    """Build and send a broadcast ARP request via Scapy.

    Returns the ``(answered, unanswered)`` tuple from ``srp``.
    Imports Scapy lazily so non-Scapy code paths never pay the cost.

    ARP is IPv4-only; calling with an IPv6 address returns ``([], [])``.
    """
    if is_ipv6(ip):
        return ([], [])

    from scapy.sendrecv import srp          # pylint: disable=import-outside-toplevel
    from scapy.layers.l2 import ARP, Ether  # pylint: disable=import-outside-toplevel

    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, unanswered = srp(packet, timeout=timeout, verbose=False)
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
