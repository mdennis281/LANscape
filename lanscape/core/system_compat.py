"""
System compatibility utilities.

Single source of truth for all platform-specific logic in LANscape.
All OS-branching code should live here so the rest of the codebase
can remain platform-agnostic.
"""

import logging
import re
import shutil
import socket
import struct
import subprocess
from typing import List, Optional, Tuple

import psutil

from lanscape.core.decorators import run_once


log = logging.getLogger(__name__)


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
    """Get a shell-string ARP command for resolving a single IP's MAC address."""
    if psutil.WINDOWS:
        return f"arp -a {ip}"
    if psutil.LINUX:
        _, cmd_str = get_linux_arp_command()
        return f"{cmd_str} {ip}"
    return f"arp {ip}"


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
    """
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
    """
    if psutil.WINDOWS:
        return ['ping', '-n', str(count), '-w', str(timeout_ms), ip]
    # Linux, macOS, and other Unix-like systems (-W takes seconds)
    return ['ping', '-c', str(count), '-W', str(max(1, timeout_ms // 1000)), ip]


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
    """Return non-virtual, IPv4-capable, up interfaces."""
    candidates = []
    for interface, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(interface)
        if not stats or not stats.isup:
            continue

        ipv4_addrs = [a for a in addrs if a.family == socket.AF_INET]
        if not ipv4_addrs:
            continue

        if any(a.address.startswith('127.') for a in ipv4_addrs):
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
    import os  # pylint: disable=import-outside-toplevel
    os.system('cls' if psutil.WINDOWS else 'clear')
