"""Centralized, thread-safe ARP/NDP neighbor table service.

Replaces scattered per-thread subprocess calls with a single background
daemon that periodically refreshes the full IPv4 ARP and IPv6 NDP tables.
All consumers read from an in-memory Pydantic-modeled cache, making
MAC/IP lookups O(1) dict reads and eliminating subprocess deadlocks
under concurrent access.

Usage::

    from lanscape.core.neighbor_table import NeighborTableService

    svc = NeighborTableService.instance()
    svc.start(refresh_interval=2.0)

    mac = svc.get_mac("10.0.0.1")
    ips = svc.get_ips_for_mac("aa:bb:cc:dd:ee:ff", want_v6=True)

    svc.wait_for_refresh()  # block until next cycle completes
    svc.stop()
"""

import ipaddress
import logging
import re
import subprocess
import shutil
import threading
import time
from typing import ClassVar, Dict, List, Literal, Optional

import psutil
from pydantic import BaseModel, Field

from lanscape.core.decorators import job_tracker

log = logging.getLogger(__name__)

# MACs that represent incomplete/invalid neighbor table entries.
_INVALID_MACS = frozenset({
    '00:00:00:00:00:00',
    'ff:ff:ff:ff:ff:ff',
})


# ─── Pydantic models ───────────────────────────────────────────────

class NeighborEntry(BaseModel):
    """Single ARP/NDP neighbor table entry."""
    ip: str
    mac: str
    interface: Optional[str] = None
    state: str = ''
    ip_version: Literal[4, 6]


class NeighborTable(BaseModel):
    """Immutable snapshot of a neighbor table (IPv4 or IPv6).

    Built once per refresh cycle, then atomically swapped in.
    Readers never need locks.
    """
    entries: Dict[str, NeighborEntry] = Field(default_factory=dict)
    mac_index: Dict[str, List[str]] = Field(default_factory=dict)
    timestamp: float = 0.0

    def get_mac(self, ip: str) -> Optional[str]:
        """Return the MAC for *ip*, or ``None`` if not in the table."""
        entry = self.entries.get(_normalize_ip(ip))  # pylint: disable=no-member
        return entry.mac if entry else None

    def get_macs(self, ip: str) -> List[str]:
        """Return all MACs associated with *ip* (usually 0 or 1)."""
        entry = self.entries.get(_normalize_ip(ip))  # pylint: disable=no-member
        return [entry.mac] if entry else []

    def get_ips_for_mac(self, mac: str, want_v6: bool) -> List[str]:
        """Return IPs associated with *mac* for the requested protocol."""
        norm = _normalize_mac(mac)
        ips = self.mac_index.get(norm, [])  # pylint: disable=no-member
        target_version = 6 if want_v6 else 4
        return [ip for ip in ips
                if self.entries.get(ip, NeighborEntry(  # pylint: disable=no-member
                    ip='', mac='', ip_version=4
                )).ip_version == target_version]

    def has_entry(self, ip: str) -> bool:
        """Return ``True`` if *ip* is in the table."""
        return _normalize_ip(ip) in self.entries


# ─── Normalization helpers ──────────────────────────────────────────

def _normalize_ip(ip: str) -> str:
    """Normalize an IP address string (strips scope, canonicalizes)."""
    try:
        return str(ipaddress.ip_address(ip.split('%')[0]))
    except ValueError:
        return ip


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase, colon-separated."""
    return mac.lower().replace('-', ':')


def _is_valid_mac(mac: str) -> bool:
    """Return True if *mac* is a real unicast MAC (not null/broadcast)."""
    return mac not in _INVALID_MACS and bool(mac)


# ─── Table construction ────────────────────────────────────────────

@job_tracker
def build_table(entries: List[NeighborEntry]) -> NeighborTable:
    """Build an immutable :class:`NeighborTable` from a list of entries."""
    entry_map: dict[str, NeighborEntry] = {}
    mac_idx: dict[str, list[str]] = {}

    for e in entries:
        norm_ip = _normalize_ip(e.ip)
        norm_mac = _normalize_mac(e.mac)

        if not _is_valid_mac(norm_mac):
            continue

        entry = NeighborEntry(
            ip=norm_ip, mac=norm_mac,
            interface=e.interface, state=e.state,
            ip_version=e.ip_version,
        )

        # If we already have this IP, prefer the entry with a reachable state
        if norm_ip in entry_map:
            existing = entry_map[norm_ip]
            if existing.state.lower() in ('reachable', 'delay'):
                continue

        entry_map[norm_ip] = entry
        mac_idx.setdefault(norm_mac, [])
        if norm_ip not in mac_idx[norm_mac]:
            mac_idx[norm_mac].append(norm_ip)

    return NeighborTable(
        entries=entry_map,
        mac_index=mac_idx,
        timestamp=time.monotonic(),
    )


# ═══════════════════════════════════════════════════════════════════
#  Platform-specific output parsers
# ═══════════════════════════════════════════════════════════════════

_MAC_PATTERN = re.compile(
    r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'
    r'[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})')


# ─── Linux: ip neigh show ──────────────────────────────────────────
# Format: "IP dev IFACE lladdr MAC STATE"
# Example: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
# May also: "192.168.1.2 dev eth0  FAILED" (no lladdr)

_LINUX_NEIGH_RE = re.compile(
    r'^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)',
    re.MULTILINE,
)


def parse_linux_neigh(output: str, ip_version: Literal[4, 6]) -> List[NeighborEntry]:
    """Parse ``ip -4 neigh show`` or ``ip -6 neigh show`` output."""
    entries: list[NeighborEntry] = []
    for m in _LINUX_NEIGH_RE.finditer(output):
        raw_ip, iface, raw_mac, state = m.group(1), m.group(2), m.group(3), m.group(4)
        mac = _normalize_mac(raw_mac)
        try:
            addr = ipaddress.ip_address(raw_ip.split('%')[0])
        except ValueError:
            continue
        if addr.is_loopback:
            continue
        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=iface,
            state=state, ip_version=ip_version,
        ))
    return entries


# ─── Windows: arp -a ───────────────────────────────────────────────
# Format:
#   Interface: 10.0.4.1 --- 0x8
#     Internet Address      Physical Address      Type
#     10.0.0.1              00-1b-21-38-a9-64     dynamic

_WIN_ARP_LINE_RE = re.compile(
    r'^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
    r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}'
    r'-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+'
    r'(\w+)',
    re.MULTILINE,
)

_WIN_ARP_IFACE_RE = re.compile(r'^Interface:\s+\S+\s+---\s+(\S+)', re.MULTILINE)


def parse_windows_arp(output: str) -> List[NeighborEntry]:
    """Parse ``arp -a`` output on Windows."""
    entries: list[NeighborEntry] = []
    current_iface: str | None = None

    for line in output.splitlines():
        iface_match = _WIN_ARP_IFACE_RE.match(line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue

        m = _WIN_ARP_LINE_RE.match(line)
        if not m:
            continue

        raw_ip, raw_mac, entry_type = m.group(1), m.group(2), m.group(3)
        mac = _normalize_mac(raw_mac)
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if addr.is_loopback:
            continue

        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=current_iface,
            state=entry_type, ip_version=4,
        ))
    return entries


# ─── Windows: Get-NetNeighbor (PowerShell) ─────────────────────────
# Parsed via ConvertTo-Csv for reliable machine parsing.
# When invoked with:
#   powershell -NoProfile -Command
#       "Get-NetNeighbor -AddressFamily IPv6
#        | ConvertTo-Csv -NoTypeInformation"
# Output format (CSV with header):
#   "ifIndex","IPAddress","LinkLayerAddress","State","PolicyStore","AddressFamily",...
#   "8","fe80::1","EC-71-DB-A0-DD-01","Stale","ActiveStore","IPv6",...
#
# Fallback: Format-Table output (if CSV parsing fails).
#   ifIndex IPAddress         LinkLayerAddress  State     PolicyStore
#   ------- ---------         ----------------  -----     -----------
#   8       fe80::1           EC-71-DB-A0-DD-01 Stale     ActiveStore

def parse_powershell_neighbor(output: str, ip_version: Literal[4, 6]) -> List[NeighborEntry]:
    """Parse ``Get-NetNeighbor | ConvertTo-Csv`` output."""
    entries: list[NeighborEntry] = []
    lines = output.strip().splitlines()
    if not lines:
        return entries

    # Try CSV parsing first (header has quoted fields)
    header = lines[0]
    if '"ifIndex"' in header:
        result = _parse_ps_csv(lines, ip_version)
        if result:
            return result

    # Fallback: table format (Format-Table or failed CSV)
    return _parse_ps_table(lines, ip_version)


def _parse_ps_csv(lines: list[str], ip_version: Literal[4, 6]) -> List[NeighborEntry]:
    """Parse CSV output from ``Get-NetNeighbor | ConvertTo-Csv``."""
    entries: list[NeighborEntry] = []
    if not lines:
        return entries

    # Parse header
    columns = [c.strip() for c in lines[0].replace('"', '').split(',')]
    col_names = ('IPAddress', 'LinkLayerAddress', 'State', 'ifIndex')
    try:
        col_idx = {name: columns.index(name) for name in col_names}
    except ValueError:
        log.debug("PowerShell CSV header missing expected columns: %s", columns)
        return entries

    min_fields = max(col_idx.values()) + 1
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = [f.strip().strip('"') for f in line.split(',')]
        if len(fields) < min_fields:
            continue

        raw_ip = fields[col_idx['IPAddress']]
        mac = _normalize_mac(fields[col_idx['LinkLayerAddress']])
        try:
            addr = ipaddress.ip_address(raw_ip.split('%')[0])
        except ValueError:
            continue
        if addr.is_loopback:
            continue

        entries.append(NeighborEntry(
            ip=str(addr), mac=mac,
            interface=fields[col_idx['ifIndex']],
            state=fields[col_idx['State']],
            ip_version=ip_version,
        ))
    return entries


_PS_TABLE_LINE_RE = re.compile(
    r'^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}'
    r'-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+(\S+)',
    re.MULTILINE,
)


def _parse_ps_table(lines: list[str], ip_version: Literal[4, 6]) -> List[NeighborEntry]:
    """Fallback: parse ``Get-NetNeighbor | Format-Table`` output."""
    entries: list[NeighborEntry] = []
    for line in lines:
        m = _PS_TABLE_LINE_RE.match(line)
        if not m:
            continue
        iface, raw_ip, raw_mac, state = m.group(1), m.group(2), m.group(3), m.group(4)
        mac = _normalize_mac(raw_mac)
        try:
            addr = ipaddress.ip_address(raw_ip.split('%')[0])
        except ValueError:
            continue
        if addr.is_loopback:
            continue
        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=iface,
            state=state, ip_version=ip_version,
        ))
    return entries


# ─── Windows: netsh interface ipv6 show neighbors ──────────────────
# Format:
#   Interface 8: Ethernet
#
#   Internet Address                     Physical Address   Type
#   ----------------------------------------  -----------------  -----------
#   fe80::1                              EC-71-DB-A0-DD-01  Stale
#   2601:2c5:4000:20e9::1115             00-00-00-00-00-00  Unreachable

_NETSH_IFACE_RE = re.compile(r'^Interface\s+(\d+):\s+(.+)', re.MULTILINE)

_NETSH_ENTRY_RE = re.compile(
    r'^\s*(\S+)\s+'
    r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}'
    r'-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+'
    r'(\S+)',
    re.MULTILINE,
)


def parse_netsh_neighbors(output: str) -> List[NeighborEntry]:
    """Parse ``netsh interface ipv6 show neighbors`` output."""
    entries: list[NeighborEntry] = []
    current_iface: str | None = None

    for line in output.splitlines():
        iface_match = _NETSH_IFACE_RE.match(line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue

        m = _NETSH_ENTRY_RE.match(line)
        if not m:
            continue

        raw_ip, raw_mac, state = m.group(1), m.group(2), m.group(3)
        mac = _normalize_mac(raw_mac)

        try:
            addr = ipaddress.ip_address(raw_ip.split('%')[0])
        except ValueError:
            continue
        if addr.is_loopback:
            continue

        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=current_iface,
            state=state, ip_version=6,
        ))
    return entries


# ─── macOS: arp -an ────────────────────────────────────────────────
# Format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
#     or: "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]"

_MACOS_ARP_RE = re.compile(
    r'\?\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+'
    r'([0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}'
    r':[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2})\s+'
    r'on\s+(\S+)',
)


def parse_macos_arp(output: str) -> List[NeighborEntry]:
    """Parse ``arp -an`` output on macOS."""
    entries: list[NeighborEntry] = []
    for m in _MACOS_ARP_RE.finditer(output):
        raw_ip, raw_mac, iface = m.group(1), m.group(2), m.group(3)
        # macOS may produce single-digit hex octets (e.g. "0:1b:...")
        # Normalize to two-digit zero-padded
        mac = ':'.join(f'{int(o, 16):02x}' for o in raw_mac.split(':'))
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if addr.is_loopback:
            continue
        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=iface,
            state='', ip_version=4,
        ))
    return entries


# ─── macOS: ndp -an ────────────────────────────────────────────────
# Format:
#   Neighbor                        Linklayer Address  Netif Expire    S Flags
#   fe80::1%en0                     aa:bb:cc:dd:ee:ff  en0   23h59m57s S R
#   fe80::aede:48ff:fe00:1122%en0   ac:de:48:00:11:22  en0   permanent R

_MACOS_NDP_RE = re.compile(
    r'^(\S+)\s+'
    r'([0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}'
    r':[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2})\s+'
    r'(\S+)\s+'
    r'(\S+)',
    re.MULTILINE,
)


def parse_macos_ndp(output: str) -> List[NeighborEntry]:
    """Parse ``ndp -an`` output on macOS."""
    entries: list[NeighborEntry] = []
    for m in _MACOS_NDP_RE.finditer(output):
        raw_ip, raw_mac, iface, expire_or_state = (
            m.group(1), m.group(2), m.group(3), m.group(4))

        # Strip scope ID (e.g. "%en0")
        clean_ip = raw_ip.split('%')[0]
        # Normalize single-digit hex octets
        mac = ':'.join(f'{int(o, 16):02x}' for o in raw_mac.split(':'))

        try:
            addr = ipaddress.ip_address(clean_ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.version != 6:
            continue

        entries.append(NeighborEntry(
            ip=str(addr), mac=mac, interface=iface,
            state=expire_or_state, ip_version=6,
        ))
    return entries


# ═══════════════════════════════════════════════════════════════════
#  Command resolution with fallback
# ═══════════════════════════════════════════════════════════════════

def _get_platform() -> str:
    """Return 'windows', 'linux', 'macos', or 'unknown'."""
    if psutil.WINDOWS:
        return 'windows'
    if psutil.LINUX:
        return 'linux'
    if psutil.MACOS:
        return 'macos'
    return 'unknown'


def get_table_commands(want_v6: bool) -> List[List[str]]:
    """Return an ordered list of commands to try for dumping the neighbor table.

    First successful execution wins. Each entry is a (command_list, parser_key)
    encoded as a plain list — the caller uses :func:`get_parser_for_command` to
    pick the right parser.
    """
    platform = _get_platform()

    if platform == 'windows':
        if want_v6:
            cmds = [
                ['powershell', '-NoProfile', '-Command',
                 'Get-NetNeighbor -AddressFamily IPv6 | ConvertTo-Csv -NoTypeInformation'],
                ['netsh', 'interface', 'ipv6', 'show', 'neighbors'],
            ]
        else:
            cmds = [['arp', '-a']]
        return cmds

    if platform == 'linux':
        flag = '-6' if want_v6 else '-4'
        cmds: list[list[str]] = []
        if shutil.which('ip'):
            cmds.append(['ip', flag, 'neigh', 'show'])
        if not want_v6 and shutil.which('arp'):
            cmds.append(['arp', '-an'])
        return cmds

    if platform == 'macos':
        if want_v6:
            return [['ndp', '-an']]
        return [['arp', '-an']]

    return []


def parse_command_output(
    command: List[str], output: str, want_v6: bool
) -> List[NeighborEntry]:
    """Route *output* from *command* to the appropriate parser."""
    cmd_name = command[0] if command else ''
    ip_ver: Literal[4, 6] = 6 if want_v6 else 4

    parsers = {
        'powershell': lambda: parse_powershell_neighbor(output, ip_ver),
        'netsh': lambda: parse_netsh_neighbors(output),
        'ip': lambda: parse_linux_neigh(output, ip_ver),
        'ndp': lambda: parse_macos_ndp(output),
    }

    if cmd_name in parsers:
        return parsers[cmd_name]()
    if cmd_name == 'arp':
        if _get_platform() == 'macos':
            return parse_macos_arp(output)
        return parse_windows_arp(output)

    log.warning("No parser for command: %s", command)
    return []


# ═══════════════════════════════════════════════════════════════════
#  Background refresh service (process-level singleton)
# ═══════════════════════════════════════════════════════════════════

_EMPTY_TABLE = NeighborTable()


class NeighborTableService:
    """Thread-safe, periodically-refreshing ARP/NDP neighbor table cache.

    Singleton — use :meth:`instance` to obtain the global instance.

    The background daemon thread fetches the full IPv4 + IPv6 neighbor
    tables on a configurable interval and atomically swaps in new
    :class:`NeighborTable` snapshots.  Readers never block.
    """

    _instance: ClassVar[Optional['NeighborTableService']] = None
    _instance_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self) -> None:
        self._ipv4_table: NeighborTable = _EMPTY_TABLE
        self._ipv6_table: NeighborTable = _EMPTY_TABLE
        self._refresh_interval: float = 2.0
        self._command_timeout: float = 5.0
        self._daemon_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._refresh_event = threading.Event()
        self._refresh_start_cond = threading.Condition()
        self._refresh_start_count: int = 0
        self._refresh_cond = threading.Condition()
        self._refresh_count: int = 0
        self._running = False

    # ── Singleton accessor ──────────────────────────────────────────

    @classmethod
    def instance(cls) -> 'NeighborTableService':
        """Return the global singleton, creating it on first call."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset the singleton — **for testing only**."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance.stop()
            cls._instance = None

    # ── Lifecycle ───────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Whether the background refresh thread is active."""
        return self._running

    def start(
        self,
        refresh_interval: float = 2.0,
        command_timeout: float = 5.0,
    ) -> None:
        """Start the background refresh daemon.

        Performs one synchronous refresh before returning so callers
        can immediately query the table.
        """
        if self._running:
            if (refresh_interval != self._refresh_interval
                    or command_timeout != self._command_timeout):
                self._refresh_interval = refresh_interval
                self._command_timeout = command_timeout
                self._wake_event.set()  # interrupt current sleep
                log.info(
                    "NeighborTableService config updated (interval=%.1fs, timeout=%.1fs)",
                    refresh_interval, command_timeout,
                )
            return

        self._refresh_interval = refresh_interval
        self._command_timeout = command_timeout
        self._stop_event.clear()
        self._running = True

        # Synchronous initial refresh
        self._do_refresh()

        self._daemon_thread = threading.Thread(
            target=self._refresh_loop,
            name="NeighborTableDaemon",
            daemon=True,
        )
        self._daemon_thread.start()
        log.info(
            "NeighborTableService started (interval=%.1fs, timeout=%.1fs)",
            refresh_interval, command_timeout,
        )

    def stop(self) -> None:
        """Stop the background refresh daemon and wait for it to exit."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        self._wake_event.set()
        # Unblock any threads waiting in get_macs_wait
        with self._refresh_start_cond:
            self._refresh_start_count += 1
            self._refresh_start_cond.notify_all()
        with self._refresh_cond:
            self._refresh_count += 1
            self._refresh_cond.notify_all()
        if self._daemon_thread is not None:
            self._daemon_thread.join(timeout=self._command_timeout + 2)
            self._daemon_thread = None
        log.info("NeighborTableService stopped")

    # ── Query API ───────────────────────────────────────────────────

    def get_mac(self, ip: str) -> Optional[str]:
        """Return the MAC for *ip*, or ``None`` if not in any table."""
        table = self._ipv6_table if ':' in ip else self._ipv4_table
        return table.get_mac(ip)

    def get_macs(self, ip: str) -> List[str]:
        """Return all MACs associated with *ip* from the current cache."""
        table = self._ipv6_table if ':' in ip else self._ipv4_table
        return table.get_macs(ip)

    def get_macs_wait(self, ip: str) -> List[str]:
        """Return MACs for *ip*, waiting for one fresh refresh if not cached.

        1. Checks the current cache — returns immediately if found.
        2. Otherwise waits for a **new** refresh cycle to **start**
           (so we don't trust one already in-flight that may have
           begun before the OS cache was populated) and then **finish**.
        3. Checks the cache once more and returns the result (may be empty).
        """
        macs = self.get_macs(ip)
        if macs:
            return macs

        if not self._running:
            return []

        # Wait for a NEW refresh to start
        start_baseline = self._refresh_start_count
        with self._refresh_start_cond:
            self._refresh_start_cond.wait_for(
                lambda: self._refresh_start_count > start_baseline,
            )

        # Now wait for that refresh to finish
        finish_baseline = self._refresh_count
        with self._refresh_cond:
            self._refresh_cond.wait_for(
                lambda: self._refresh_count > finish_baseline,
            )

        return self.get_macs(ip)

    def get_ips_for_mac(self, mac: str, want_v6: bool) -> List[str]:
        """Return IPs associated with *mac* for the requested protocol."""
        table = self._ipv6_table if want_v6 else self._ipv4_table
        return table.get_ips_for_mac(mac, want_v6)

    def get_table(self, want_v6: bool) -> NeighborTable:
        """Return the current snapshot for the requested protocol."""
        return self._ipv6_table if want_v6 else self._ipv4_table

    def wait_for_refresh(self, timeout: float = 5.0) -> bool:
        """Block until the next refresh cycle completes.

        Returns ``True`` if a refresh happened, ``False`` on timeout.
        Use this after a poke/ICMP to wait for the OS neighbor cache
        to be picked up by the next background refresh.
        """
        if not self._running:
            return False
        self._refresh_event.clear()
        return self._refresh_event.wait(timeout=timeout)

    # ── Internal refresh logic ──────────────────────────────────────

    def _refresh_loop(self) -> None:
        """Daemon thread main loop."""
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self._refresh_interval)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            self._do_refresh()
    @job_tracker
    def _do_refresh(self) -> None:
        """Fetch both tables and atomically swap them in."""
        self._refresh_event.clear()

        with self._refresh_start_cond:
            self._refresh_start_count += 1
            self._refresh_start_cond.notify_all()

        v4_entries = self._fetch_entries(want_v6=False)
        v6_entries = self._fetch_entries(want_v6=True)

        self._ipv4_table = build_table(v4_entries)
        self._ipv6_table = build_table(v6_entries)

        with self._refresh_cond:
            self._refresh_count += 1
            self._refresh_cond.notify_all()

        self._refresh_event.set()

    def _fetch_entries(self, want_v6: bool) -> List[NeighborEntry]:
        """Try each command in order for the given protocol. First success wins."""
        commands = get_table_commands(want_v6)
        for cmd in commands:
            try:
                output = subprocess.check_output(
                    cmd, shell=False, timeout=self._command_timeout,
                    stderr=subprocess.DEVNULL,
                ).decode(errors='replace')
                entries = parse_command_output(cmd, output, want_v6)
                if entries:
                    log.debug(
                        "Fetched %d %s entries via: %s",
                        len(entries), 'IPv6' if want_v6 else 'IPv4',
                        ' '.join(cmd[:2]),
                    )
                    return entries
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    FileNotFoundError, OSError) as exc:
                log.debug("Command %s failed: %s", cmd[:2], exc)
                continue
        return []
