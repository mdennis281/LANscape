"""DHCP lease request listener for LAN monitoring and troubleshooting.

Captures all DHCP traffic on the local network and surfaces it as structured,
correlated :class:`DhcpEvent` objects. Events sharing the same transaction ID
(``xid``) are automatically grouped into :class:`DhcpLeaseTransaction` records
that track the full DORA lifecycle (Discover → Offer → Request → ACK).

Requires scapy and elevated privileges (root on Linux/macOS, or Npcap on Windows).

Basic usage::

    from lanscape.core.dhcp_listener import DhcpListener, DhcpFilter

    # Context-manager — starts/stops automatically
    with DhcpListener() as listener:
        for event in listener:
            print(event.summary())

    # Subnet filter + callbacks
    listener = DhcpListener(
        dhcp_filter=DhcpFilter(subnets=["192.168.1.0/24"]),
        on_event=lambda e: print(e.summary()),
        on_transaction_complete=lambda t: print(t.summary()),
    )
    listener.start()

    # Access the correlated transaction table at any time
    for xid, tx in listener.transactions.items():
        print(tx.summary())

    listener.stop()
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import threading
import time
from enum import IntEnum
from typing import Callable, Dict, Iterator, List, Optional, Union

from pydantic import BaseModel, Field, computed_field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DHCP message type
# ---------------------------------------------------------------------------

class DhcpMessageType(IntEnum):
    """DHCP message type (option 53). Values follow RFC 2132."""
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8

    @property
    def direction(self) -> str:
        """``'client'`` for client-originated messages, ``'server'`` for replies."""
        _client = {
            DhcpMessageType.DISCOVER,
            DhcpMessageType.REQUEST,
            DhcpMessageType.DECLINE,
            DhcpMessageType.RELEASE,
            DhcpMessageType.INFORM,
        }
        return 'client' if self in _client else 'server'


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

class DhcpEvent(BaseModel):
    """A single decoded DHCP packet captured from the wire.

    All BOOTP/DHCP fields are surfaced as first-class attributes.  Raw scapy
    option data is also preserved in ``raw_options`` for fields not explicitly
    modeled here.
    """

    # ── Core identifiers ───────────────────────────────────────────
    xid: int = Field(
        description="Transaction ID — correlates Discover / Offer / Request / ACK"
    )
    message_type: DhcpMessageType = Field(description="DHCP message type (option 53)")
    timestamp: float = Field(description="Unix timestamp when the packet was captured")
    interface: Optional[str] = Field(
        default=None, description="Network interface where the packet was captured"
    )

    # ── Layer-2 / Layer-3 ──────────────────────────────────────────
    src_mac: str = Field(description="Ethernet source MAC address")
    dst_mac: str = Field(description="Ethernet destination MAC address")
    src_ip: str  = Field(description="IP source address")
    dst_ip: str  = Field(description="IP destination address")

    # ── BOOTP fields ───────────────────────────────────────────────
    client_mac: str = Field(description="Client hardware address (chaddr field)")
    client_ip: str  = Field(
        default='0.0.0.0',
        description="Client's current IP (ciaddr) — non-zero during renews"
    )
    offered_ip: str = Field(
        default='0.0.0.0',
        description="IP offered or assigned by the server (yiaddr)"
    )
    server_ip: str  = Field(
        default='0.0.0.0',
        description="Next-server IP (siaddr — e.g. TFTP boot server)"
    )
    relay_ip: str   = Field(
        default='0.0.0.0',
        description="Relay agent IP (giaddr) — non-zero when routed through a relay"
    )

    # ── DHCP options ───────────────────────────────────────────────
    server_identifier: Optional[str] = Field(
        default=None, description="DHCP server IP (option 54)"
    )
    requested_ip: Optional[str] = Field(
        default=None,
        description="IP the client is explicitly requesting (option 50)"
    )
    lease_time: Optional[int] = Field(
        default=None, description="Offered lease duration in seconds (option 51)"
    )
    renewal_time: Optional[int] = Field(
        default=None, description="T1 renewal time in seconds (option 58)"
    )
    rebinding_time: Optional[int] = Field(
        default=None, description="T2 rebinding time in seconds (option 59)"
    )
    subnet_mask: Optional[str] = Field(
        default=None, description="Offered subnet mask (option 1)"
    )
    routers: List[str] = Field(
        default_factory=list, description="Offered default gateway IPs (option 3)"
    )
    dns_servers: List[str] = Field(
        default_factory=list, description="Offered DNS server IPs (option 6)"
    )
    domain_name: Optional[str] = Field(
        default=None, description="Offered domain name (option 15)"
    )
    hostname: Optional[str] = Field(
        default=None, description="Client hostname (option 12)"
    )
    vendor_class_id: Optional[str] = Field(
        default=None, description="Vendor class identifier (option 60)"
    )
    client_id: Optional[str] = Field(
        default=None, description="Client identifier bytes as hex string (option 61)"
    )
    broadcast_address: Optional[str] = Field(
        default=None, description="Offered broadcast address (option 28)"
    )
    ntp_servers: List[str] = Field(
        default_factory=list, description="Offered NTP server IPs (option 42)"
    )
    param_request_list: List[int] = Field(
        default_factory=list,
        description="Option codes the client is requesting (option 55)"
    )
    error_message: Optional[str] = Field(
        default=None, description="NAK / error message from the server (option 56)"
    )
    max_message_size: Optional[int] = Field(
        default=None, description="Maximum DHCP message size the client accepts (option 57)"
    )
    raw_options: Dict[str, object] = Field(
        default_factory=dict,
        description="All decoded DHCP options as a name → value dict"
    )

    # ── Computed helpers ───────────────────────────────────────────

    @computed_field
    @property
    def effective_ip(self) -> str:
        """Best available IP for this event: offered → requested → client."""
        if self.offered_ip and self.offered_ip != '0.0.0.0':
            return self.offered_ip
        if self.requested_ip:
            return self.requested_ip
        return self.client_ip

    @computed_field
    @property
    def direction(self) -> str:
        """``'client'`` or ``'server'``."""
        return self.message_type.direction

    def summary(self) -> str:
        """One-line human-readable description of this event."""
        parts = [
            f"[{self.message_type.name:8s}]",
            f"xid={self.xid:#010x}",
            f"mac={self.client_mac}",
        ]
        if self.hostname:
            parts.append(f"host={self.hostname!r}")
        if (ip := self.effective_ip) and ip != '0.0.0.0':
            parts.append(f"ip={ip}")
        if self.server_identifier:
            parts.append(f"server={self.server_identifier}")
        if self.lease_time is not None:
            parts.append(f"lease={self.lease_time}s")
        if self.vendor_class_id:
            parts.append(f"vendor={self.vendor_class_id!r}")
        return ' '.join(parts)


# ---------------------------------------------------------------------------
# Transaction model
# ---------------------------------------------------------------------------

class DhcpLeaseTransaction(BaseModel):
    """Correlated view of all DHCP messages sharing the same ``xid``.

    Tracks the full DORA (Discover → Offer → Request → ACK) lifecycle plus
    Decline / Release / NAK events.  Useful for diagnosing lease failures,
    rogue servers, and client misconfiguration.
    """

    xid: int = Field(description="Transaction ID")
    client_mac: str = Field(description="Client MAC address")
    events: List[DhcpEvent] = Field(
        default_factory=list, description="All events in chronological order"
    )
    started_at: float = Field(description="Timestamp of the first event")
    last_seen: float = Field(description="Timestamp of the most recent event")

    # ── Computed helpers ───────────────────────────────────────────

    @computed_field
    @property
    def is_complete(self) -> bool:
        """``True`` once an ACK or NAK has been received."""
        return any(
            e.message_type in {DhcpMessageType.ACK, DhcpMessageType.NAK}
            for e in self.events
        )

    @computed_field
    @property
    def assigned_ip(self) -> Optional[str]:
        """IP address confirmed in an ACK, or ``None`` if not yet assigned."""
        for event in reversed(self.events):
            if event.message_type == DhcpMessageType.ACK and event.offered_ip != '0.0.0.0':
                return event.offered_ip
        return None

    @computed_field
    @property
    def hostname(self) -> Optional[str]:
        """Hostname from any event in this transaction."""
        return next((e.hostname for e in self.events if e.hostname), None)

    @computed_field
    @property
    def message_flow(self) -> str:
        """Sequence of message types, e.g. ``'DISCOVER → OFFER → REQUEST → ACK'``."""
        return ' → '.join(e.message_type.name for e in self.events)

    def add_event(self, event: DhcpEvent) -> None:
        """Append *event* to this transaction and update ``last_seen``."""
        self.events.append(event)
        self.last_seen = event.timestamp

    def summary(self) -> str:
        """One-line description of the full transaction."""
        ip   = self.assigned_ip or '?'
        host = self.hostname or 'unknown'
        return (
            f"Transaction {self.xid:#010x} | mac={self.client_mac} "
            f"host={host!r} ip={ip} | {self.message_flow}"
        )


# ---------------------------------------------------------------------------
# Filter model
# ---------------------------------------------------------------------------

class DhcpFilter(BaseModel):
    """Declarative filter applied to each captured :class:`DhcpEvent`.

    All active filter criteria must pass for an event to be delivered.
    An empty list for any criterion means *no filter on that dimension*.
    """

    subnets: List[str] = Field(
        default_factory=list,
        description=(
            "Only emit events whose effective IP falls within one of these subnets. "
            "Zero-IP events (Discovers before an IP is known) are passed through "
            "unless ``drop_zero_ip`` is True."
        ),
    )
    mac_addresses: List[str] = Field(
        default_factory=list,
        description="Only emit events from these client MAC addresses.",
    )
    message_types: List[DhcpMessageType] = Field(
        default_factory=list,
        description="Only emit these DHCP message types.",
    )
    drop_zero_ip: bool = Field(
        default=False,
        description="Drop events where the effective IP is 0.0.0.0.",
    )

    # Cached parsed networks — rebuilt lazily
    _networks: Optional[List[ipaddress.IPv4Network]] = None

    def _get_networks(self) -> List[ipaddress.IPv4Network]:
        if self._networks is None:
            self._networks = [
                ipaddress.ip_network(s, strict=False)  # type: ignore[assignment]
                for s in self.subnets
            ]
        return self._networks  # type: ignore[return-value]

    def matches(self, event: DhcpEvent) -> bool:
        """Return ``True`` if *event* passes all active filter criteria."""
        if self.message_types and event.message_type not in self.message_types:
            return False

        if self.mac_addresses:
            norm = event.client_mac.lower()
            if not any(m.lower() == norm for m in self.mac_addresses):
                return False

        effective = event.effective_ip
        is_zero = not effective or effective == '0.0.0.0'

        if self.drop_zero_ip and is_zero:
            return False

        if self.subnets and not is_zero:
            try:
                ip_obj = ipaddress.ip_address(effective)
                if not any(ip_obj in net for net in self._get_networks()):
                    return False
            except ValueError:
                return False

        return True


# ---------------------------------------------------------------------------
# Internal packet decoder
# ---------------------------------------------------------------------------

def _normalize_ip(addr: object) -> str:
    """Coerce a scapy IP field to a dotted-decimal string."""
    if addr is None:
        return '0.0.0.0'
    s = str(addr)
    return s if s else '0.0.0.0'


def _normalize_mac(raw: bytes) -> str:
    """Format the first 6 bytes of a BOOTP ``chaddr`` field as a MAC string."""
    if isinstance(raw, bytes):
        return ':'.join(f'{b:02x}' for b in raw[:6])
    return str(raw)


def _ip_list(value: object) -> List[str]:
    """Convert a scapy repeated-IP option value to a list of strings."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(v) for v in value]  # type: ignore[union-attr]
    except TypeError:
        return [str(value)]


def _decode_client_id(raw: object) -> Optional[str]:
    """Render client-id bytes as a colon-separated hex string."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return ':'.join(f'{b:02x}' for b in raw)
    return str(raw)


def _options_to_dict(options: list) -> Dict[str, object]:
    """Flatten scapy's option list into a plain dict, dropping ``'end'``/``'pad'`` markers."""
    result: Dict[str, object] = {}
    for item in options:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            key, value = item[0], item[1]
            if key not in ('end', 'pad'):
                result[str(key)] = value
        elif isinstance(item, str) and item not in ('end', 'pad'):
            result[item] = None
    return result


def decode_packet(pkt) -> Optional[DhcpEvent]:  # noqa: C901 – intentionally wide
    """Decode a scapy packet into a :class:`DhcpEvent`, or return ``None`` if invalid."""
    try:
        from scapy.layers.dhcp import BOOTP, DHCP  # pylint: disable=import-outside-toplevel
        from scapy.layers.inet import IP              # pylint: disable=import-outside-toplevel
        from scapy.layers.l2 import Ether           # pylint: disable=import-outside-toplevel
    except ImportError:
        log.error("scapy is required for DHCP sniffing: pip install scapy")
        return None

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return None

    bootp = pkt[BOOTP]
    dhcp  = pkt[DHCP]

    opts = _options_to_dict(dhcp.options)

    raw_msg_type = opts.get('message-type')
    try:
        msg_type = DhcpMessageType(int(raw_msg_type))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        log.debug("Ignoring DHCP packet with unknown message-type: %r", raw_msg_type)
        return None

    src_mac = pkt[Ether].src  if pkt.haslayer(Ether) else ''
    dst_mac = pkt[Ether].dst  if pkt.haslayer(Ether) else ''
    src_ip  = pkt[IP].src     if pkt.haslayer(IP)    else '0.0.0.0'
    dst_ip  = pkt[IP].dst     if pkt.haslayer(IP)    else '0.0.0.0'

    # Capture interface name when scapy attaches it
    interface = getattr(pkt, 'sniffed_on', None)

    def _opt_str(key: str) -> Optional[str]:
        v = opts.get(key)
        if v is None:
            return None
        if isinstance(v, bytes):
            return v.decode('utf-8', errors='replace')
        return str(v) if v else None

    def _opt_int(key: str) -> Optional[int]:
        v = opts.get(key)
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    return DhcpEvent(
        xid              = int(bootp.xid),
        message_type     = msg_type,
        timestamp        = time.time(),
        interface        = interface,
        src_mac          = src_mac,
        dst_mac          = dst_mac,
        src_ip           = src_ip,
        dst_ip           = dst_ip,
        client_mac       = _normalize_mac(bootp.chaddr),
        client_ip        = _normalize_ip(bootp.ciaddr),
        offered_ip       = _normalize_ip(bootp.yiaddr),
        server_ip        = _normalize_ip(bootp.siaddr),
        relay_ip         = _normalize_ip(bootp.giaddr),
        server_identifier= _opt_str('server_id'),
        requested_ip     = _opt_str('requested_addr'),
        lease_time       = _opt_int('lease_time'),
        renewal_time     = _opt_int('renewal_time'),
        rebinding_time   = _opt_int('rebinding_time'),
        subnet_mask      = _opt_str('subnet_mask'),
        routers          = _ip_list(opts.get('router')),
        dns_servers      = _ip_list(opts.get('name_server')),
        domain_name      = _opt_str('domain'),
        hostname         = _opt_str('hostname'),
        vendor_class_id  = _opt_str('vendor_class_id'),
        client_id        = _decode_client_id(opts.get('client_id')),
        broadcast_address= _opt_str('broadcast_address'),
        ntp_servers      = _ip_list(opts.get('NTP_server')),
        param_request_list = list(opts.get('param_req_list') or []),
        error_message    = _opt_str('error_message'),
        max_message_size = _opt_int('max_dhcp_size'),
        raw_options      = opts,
    )


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

class DhcpListener:
    """Sniffs DHCP traffic on the LAN and delivers structured :class:`DhcpEvent` objects.

    Features
    --------
    * Subnet / MAC / message-type filtering via :class:`DhcpFilter`.
    * Optional callback hooks (``on_event``, ``on_transaction_complete``).
    * Iterator interface — ``for event in listener`` blocks until the listener stops.
    * Context-manager support — ``with DhcpListener() as l: ...`` auto-starts/stops.
    * Transaction correlation — all messages sharing the same ``xid`` are grouped into a
      :class:`DhcpLeaseTransaction` accessible via :attr:`transactions`.

    Requires
    --------
    * `scapy` (``pip install scapy``)
    * Elevated privileges: ``sudo`` on Linux/macOS; Npcap on Windows.

    Parameters
    ----------
    dhcp_filter:
        Optional :class:`DhcpFilter` to restrict which events are delivered.
    interface:
        One or more interface names to sniff on (e.g. ``"eth0"``).
        ``None`` sniffs on all interfaces.
    on_event:
        Callback fired for every event that passes the filter.
    on_transaction_complete:
        Callback fired when a transaction receives an ACK or NAK.
    track_transactions:
        When ``True`` (default), group events by ``xid`` into
        :attr:`transactions`.
    queue_maxsize:
        Maximum size of the internal event queue (for the iterator interface).
        Older events are dropped when the queue is full.
    """

    def __init__(
        self,
        dhcp_filter: Optional[DhcpFilter] = None,
        interface: Optional[Union[str, List[str]]] = None,
        on_event: Optional[Callable[[DhcpEvent], None]] = None,
        on_transaction_complete: Optional[Callable[[DhcpLeaseTransaction], None]] = None,
        track_transactions: bool = True,
        queue_maxsize: int = 1_000,
    ) -> None:
        self.dhcp_filter             = dhcp_filter or DhcpFilter()
        self.interface               = interface
        self.on_event                = on_event
        self.on_transaction_complete = on_transaction_complete
        self.track_transactions      = track_transactions

        self._queue: queue.Queue[DhcpEvent] = queue.Queue(maxsize=queue_maxsize)
        self._transactions: Dict[int, DhcpLeaseTransaction] = {}
        self._tx_lock = threading.Lock()

        self._sniffer = None
        self._running = False

    # ── Public API ──────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        """``True`` while the sniffer is active."""
        return self._running

    @property
    def transactions(self) -> Dict[int, DhcpLeaseTransaction]:
        """Live transaction table: ``{xid: DhcpLeaseTransaction}``."""
        return self._transactions

    def start(self) -> 'DhcpListener':
        """Start the sniffer in a background thread.  Returns ``self`` for chaining."""
        if self._running:
            log.warning("DhcpListener is already running")
            return self

        try:
            from scapy.sendrecv import AsyncSniffer  # pylint: disable=import-outside-toplevel
        except ImportError as exc:
            raise RuntimeError(
                "scapy is required for DHCP sniffing.  Install it with: pip install scapy"
            ) from exc

        kwargs: dict = dict(
            filter='udp and (port 67 or port 68)',
            prn=self._on_packet,
            store=False,
        )
        if self.interface:
            kwargs['iface'] = self.interface

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        self._running = True
        log.info(
            "DhcpListener started on interface=%s",
            self.interface or 'all',
        )
        return self

    def stop(self) -> None:
        """Stop the sniffer and drain remaining queued events."""
        if not self._running:
            return
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop(join=True)
            except Exception:  # noqa: BLE001
                log.debug("Exception while stopping sniffer", exc_info=True)
            self._sniffer = None
        log.info("DhcpListener stopped")

    def clear_transactions(self) -> None:
        """Purge the transaction table."""
        with self._tx_lock:
            self._transactions.clear()

    def prune_transactions(self, max_age_seconds: float = 300.0) -> int:
        """Remove completed or stale transactions older than *max_age_seconds*.

        Returns the number of transactions removed.
        """
        cutoff = time.time() - max_age_seconds
        with self._tx_lock:
            stale = [
                xid for xid, tx in self._transactions.items()
                if tx.last_seen < cutoff
            ]
            for xid in stale:
                del self._transactions[xid]
        return len(stale)

    # ── Iteration ──────────────────────────────────────────────────

    def __iter__(self) -> Iterator[DhcpEvent]:
        """Block-iterate over captured events.

        Yields events as they arrive.  Iteration ends naturally once
        :meth:`stop` is called and the queue is drained.
        """
        while self._running or not self._queue.empty():
            try:
                yield self._queue.get(timeout=0.1)
            except queue.Empty:
                continue

    def events(self, timeout: Optional[float] = None) -> Iterator[DhcpEvent]:
        """Iterate over events with an optional wall-clock *timeout* (seconds).

        Stops when the timeout elapses, when :meth:`stop` is called, or when
        the queue is drained — whichever comes first.
        """
        deadline = (time.monotonic() + timeout) if timeout is not None else None
        while self._running or not self._queue.empty():
            if deadline is not None and time.monotonic() >= deadline:
                break
            remaining = (
                min(0.1, deadline - time.monotonic())
                if deadline is not None
                else 0.1
            )
            try:
                yield self._queue.get(timeout=max(remaining, 0.0))
            except queue.Empty:
                continue

    # ── Context-manager ────────────────────────────────────────────

    def __enter__(self) -> 'DhcpListener':
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── Internal ───────────────────────────────────────────────────

    def _on_packet(self, pkt) -> None:
        """scapy callback — decode, filter, dispatch."""
        event = decode_packet(pkt)
        if event is None:
            return
        if not self.dhcp_filter.matches(event):
            return

        log.debug(event.summary())

        if self.track_transactions:
            self._update_transaction(event)

        if self.on_event:
            try:
                self.on_event(event)
            except Exception:  # noqa: BLE001
                log.exception("on_event callback raised an exception")

        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Drop the oldest event to make room
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                log.warning("DhcpListener event queue is full — dropping event")

    def _update_transaction(self, event: DhcpEvent) -> None:
        """Insert or update the :class:`DhcpLeaseTransaction` for *event*."""
        xid = event.xid
        with self._tx_lock:
            tx = self._transactions.get(xid)
            if tx is None:
                tx = DhcpLeaseTransaction(
                    xid        = xid,
                    client_mac = event.client_mac,
                    started_at = event.timestamp,
                    last_seen  = event.timestamp,
                )
                self._transactions[xid] = tx
            tx.add_event(event)
            just_completed = tx.is_complete and len(tx.events) > 0

        if just_completed and self.on_transaction_complete:
            try:
                self.on_transaction_complete(tx)
            except Exception:  # noqa: BLE001
                log.exception("on_transaction_complete callback raised an exception")
