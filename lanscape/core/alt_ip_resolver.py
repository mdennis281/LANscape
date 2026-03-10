"""Cross-protocol IP address resolution.

Discovers alternate IP addresses for a device by correlating MAC addresses
across the IPv4 ARP cache and IPv6 NDP neighbor table, deriving EUI-64
link-local addresses from MACs, and performing DNS-based lookups.

All helpers are fail-safe — errors are logged and empty lists returned.
"""

import ipaddress
import logging
import re
import socket
import subprocess
from typing import List

import psutil

from lanscape.core.system_compat import is_ipv6

log = logging.getLogger('AltIPResolver')


# ─── Public API ─────────────────────────────────────────────────────

def resolve_alt_ips(ip: str, macs: List[str], hostname: str | None) -> List[str]:
    """Discover alternate-protocol IP addresses for a device.

    Given a device's primary *ip*, its known *macs*, and optional *hostname*,
    return a deduplicated list of cross-protocol IP addresses (IPv6 if the
    device was scanned via IPv4, and vice versa).

    Resolution strategies (order of precedence):
    1. **Neighbor-cache correlation** — look up the opposite-protocol
       neighbor table for entries sharing the same MAC.
    2. **EUI-64 derivation** — for IPv4 scans, derive the ``fe80::``
       link-local from the MAC using modified EUI-64.
    3. **DNS lookup** — query ``getaddrinfo`` for A or AAAA records
       using the resolved hostname.

    All methods are best-effort and fail silently.
    """
    alt: list[str] = []
    scanning_v6 = is_ipv6(ip)

    for mac in macs:
        alt.extend(_alt_ips_from_neighbor_cache(mac, scanning_v6))

    if not scanning_v6:
        for mac in macs:
            eui = _eui64_link_local(mac)
            if eui:
                alt.append(eui)

    if hostname:
        target_family = socket.AF_INET if scanning_v6 else socket.AF_INET6
        alt.extend(_alt_ips_from_dns(hostname, target_family))

    return _deduplicate(alt, exclude=ip)


# ─── Neighbor-cache correlation ─────────────────────────────────────

def _alt_ips_from_neighbor_cache(mac: str, scanning_v6: bool) -> List[str]:
    """Search the opposite-protocol neighbor table for *mac*.

    When scanning IPv4 we query the IPv6 neighbor table, and vice versa.
    """
    try:
        cmd = _neighbor_dump_command(want_v6=not scanning_v6)
        if not cmd:
            return []
        output = subprocess.check_output(
            cmd, shell=True, timeout=5, stderr=subprocess.DEVNULL,
        ).decode(errors='replace')
        return _extract_ips_for_mac(output, mac, want_v6=not scanning_v6)
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("Neighbor-cache lookup failed: %s", exc)
        return []


# Command lookup: (want_v6, platform) -> shell command
_NEIGHBOR_CMDS: dict[tuple[bool, str], str] = {
    (True, 'windows'): 'netsh interface ipv6 show neighbors',
    (True, 'linux'):   'ip -6 neigh show',
    (True, 'macos'):   'ndp -an',
    (False, 'windows'): 'arp -a',
    (False, 'linux'):   'ip -4 neigh show',
    (False, 'macos'):   'arp -an',
}


def _neighbor_dump_command(want_v6: bool) -> str | None:
    """Return a shell command that dumps the full neighbor table for the target protocol."""
    if psutil.WINDOWS:
        platform = 'windows'
    elif psutil.LINUX:
        platform = 'linux'
    elif psutil.MACOS:
        platform = 'macos'
    else:
        return None
    return _NEIGHBOR_CMDS.get((want_v6, platform))


_IP4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
_IP6_RE = re.compile(r'([0-9a-fA-F:]{3,}(?:::[0-9a-fA-F]{1,4}|:[0-9a-fA-F]{1,4}){1,})')


def _extract_ips_for_mac(
    output: str, mac: str, want_v6: bool
) -> List[str]:
    """Parse neighbor-table output and return IPs associated with *mac*."""
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


# ─── EUI-64 link-local derivation ──────────────────────────────────

def _eui64_link_local(mac: str) -> str | None:
    """Derive the IPv6 link-local address from *mac* via modified EUI-64.

    Returns ``None`` if the MAC is invalid or obviously a broadcast/multicast address.
    """
    try:
        octets = mac.replace('-', ':').split(':')
        if len(octets) != 6:
            return None

        bytes_list = [int(o, 16) for o in octets]

        # Skip multicast / broadcast MACs
        if bytes_list[0] & 0x01:
            return None

        # Flip the universal/local bit (7th bit of first octet)
        bytes_list[0] ^= 0x02

        # Insert 0xFF, 0xFE in the middle
        eui64 = bytes_list[:3] + [0xFF, 0xFE] + bytes_list[3:]

        # Build 16-bit groups
        groups = []
        for i in range(0, 8, 2):
            groups.append(f"{(eui64[i] << 8) | eui64[i + 1]:x}")

        return str(ipaddress.IPv6Address(f"fe80::{':'.join(groups)}"))

    except (ValueError, IndexError) as exc:
        log.debug("EUI-64 derivation failed for MAC %s: %s", mac, exc)
        return None


# ─── DNS-based lookup ───────────────────────────────────────────────

def _alt_ips_from_dns(hostname: str, family: int) -> List[str]:
    """Query DNS for *hostname* using *family* (AF_INET or AF_INET6).

    Returns resolved addresses, silently returning [] on failure.
    """
    try:
        results = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
        return [r[4][0].split('%')[0] for r in results if r[4][0]]
    except (socket.gaierror, OSError) as exc:
        log.debug("DNS alt-IP lookup for %s failed: %s", hostname, exc)
        return []


# ─── Deduplication helper ──────────────────────────────────────────

def _deduplicate(ips: List[str], exclude: str) -> List[str]:
    """Return unique IPs, excluding the device's primary address.

    Normalises addresses via ``ipaddress`` so ``::1`` and
    ``0000:0000:0000:0000:0000:0000:0000:0001`` are treated as equal.
    """
    seen: set[str] = set()
    result: list[str] = []

    try:
        exclude_norm = str(ipaddress.ip_address(exclude.split('%')[0]))
    except ValueError:
        exclude_norm = exclude

    for raw_ip in ips:
        try:
            norm = str(ipaddress.ip_address(raw_ip.split('%')[0]))
        except ValueError:
            continue
        if norm == exclude_norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        result.append(norm)

    return result
