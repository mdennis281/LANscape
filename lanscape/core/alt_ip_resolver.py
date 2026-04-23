"""Cross-protocol IP address resolution.

Discovers alternate IP addresses for a device by correlating MAC addresses
across the IPv4 ARP cache and IPv6 NDP neighbor table, deriving EUI-64
link-local addresses from MACs, and performing DNS-based lookups.

All helpers are fail-safe — errors are logged and empty lists returned.
"""

import ipaddress
import logging
import socket
import subprocess
import threading
import time
from typing import List

from lanscape.core.system_compat import (
    is_ipv6,
    get_ipv6_interface_scopes,
    get_ndp_ping_command,
)
from lanscape.core.neighbor_table import NeighborTableService

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


# ─── NDP cache priming ──────────────────────────────────────────────

_ndp_primed = False  # pylint: disable=invalid-name  # mutable flag, not a constant
_ndp_prime_lock = threading.Lock()


def _prime_ndp_cache() -> None:
    """Ping ``ff02::1`` on active interfaces to populate the IPv6 NDP cache.

    The NDP neighbor table is only populated for devices the host has
    recently communicated with over IPv6.  By sending an ICMPv6 echo to
    the link-local all-nodes multicast group, every IPv6-capable device on
    the segment replies, causing the OS to record their link-layer (MAC)
    addresses in the NDP cache.

    This function is idempotent — it runs once per process and is
    thread-safe.
    """
    global _ndp_primed  # pylint: disable=global-statement
    with _ndp_prime_lock:
        if _ndp_primed:
            return
        _ndp_primed = True

    scopes = get_ipv6_interface_scopes()
    if not scopes:
        log.debug("No active IPv6 interfaces found for NDP priming")
        return

    for scope in scopes:
        target = f"ff02::1%{scope}"
        try:
            cmd = get_ndp_ping_command(target)
            subprocess.run(   # pylint: disable=subprocess-run-check
                cmd, timeout=6,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:  # pylint: disable=broad-except
            pass  # Best-effort; failures are expected on some interfaces

    # Brief pause so the OS can finish recording NDP entries
    time.sleep(0.5)
    log.debug("NDP cache primed on %d interface(s)", len(scopes))


# ─── Neighbor-cache correlation ─────────────────────────────────────

def _alt_ips_from_neighbor_cache(mac: str, scanning_v6: bool) -> List[str]:
    """Search the opposite-protocol neighbor table for *mac*.

    When scanning IPv4 we query the IPv6 neighbor table, and vice versa.
    Uses the NeighborTableService for thread-safe, lock-free lookups.
    If looking for IPv6 entries, the NDP cache is primed first (once per
    process) to maximise coverage.
    """
    try:
        want_v6 = not scanning_v6
        if want_v6:
            _prime_ndp_cache()

        svc = NeighborTableService.instance()
        if svc.is_running:
            return svc.get_ips_for_mac(mac, want_v6)
        return []
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("Neighbor-cache lookup failed: %s", exc)
        return []


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
