"""DHCP lease request listener.

Passively captures DHCP traffic on the LAN and surfaces fully-parsed
lease events — DISCOVERs, REQUESTs, OFFERs, ACKs, and more — via a
simple callback interface.

Useful for:
    - Watching new devices join the network in real time
    - Troubleshooting DHCP failures (DISCOVER with no ACK, etc.)
    - Auditing vendor class / hostname data sent by clients

Usage::

    from lanscape.core.dhcp_listener import DhcpListener, DhcpListenerConfig

    config = DhcpListenerConfig(
        subnet_filter=["192.168.1.0/24"],
        message_types=[DhcpMessageType.DISCOVER, DhcpMessageType.REQUEST],
    )

    def on_event(event: DhcpLeaseEvent) -> None:
        print(event.model_dump_json(indent=2))

    listener = DhcpListener(config, on_event=on_event)
    listener.start()
    # ... later ...
    listener.stop()
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from datetime import datetime, timezone
from enum import IntEnum
from typing import Callable, List, Optional

from pydantic import BaseModel, Field
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
from scapy.sendrecv import AsyncSniffer

log = logging.getLogger(__name__)


# ─── Enums ────────────────────────────────────────────────────────

class DhcpMessageType(IntEnum):
    """DHCP message-type option values (RFC 2131)."""
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8

    @classmethod
    def from_int(cls, value: int) -> Optional["DhcpMessageType"]:
        """Return the enum member for *value*, or ``None`` if unknown."""
        try:
            return cls(value)
        except ValueError:
            return None


# ─── Pydantic models ──────────────────────────────────────────────

class DhcpLeaseEvent(BaseModel):
    """Fully-parsed snapshot of a single DHCP packet.

    All optional fields are ``None`` when absent from the packet.
    """

    # ── DHCP message classification ──
    message_type: Optional[DhcpMessageType] = Field(
        default=None,
        description="DHCP message type (option 53)"
    )

    # ── Client identification ──
    client_mac: str = Field(
        description="Client hardware (MAC) address from BOOTP chaddr"
    )
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address (ciaddr — non-zero only when client already has a lease)"
    )
    client_identifier: Optional[str] = Field(
        default=None,
        description="Client identifier from option 61 (often MAC or UUID)"
    )

    # ── IP negotiation ──
    requested_ip: Optional[str] = Field(
        default=None,
        description="IP the client is requesting (option 50)"
    )
    offered_ip: Optional[str] = Field(
        default=None,
        description="IP offered or assigned by the server (yiaddr)"
    )
    server_ip: Optional[str] = Field(
        default=None,
        description="Next-server IP from BOOTP siaddr"
    )
    server_identifier: Optional[str] = Field(
        default=None,
        description="DHCP server identifier from option 54"
    )

    # ── Client-supplied options ──
    hostname: Optional[str] = Field(
        default=None,
        description="Client-supplied hostname (option 12)"
    )
    fqdn: Optional[str] = Field(
        default=None,
        description="Fully-qualified domain name from option 81"
    )
    vendor_class: Optional[str] = Field(
        default=None,
        description="Vendor class identifier (option 60) — e.g. 'MSFT 5.0', 'android-dhcp-13'"
    )
    user_class: Optional[str] = Field(
        default=None,
        description="User class information (option 77)"
    )
    requested_options: Optional[List[int]] = Field(
        default=None,
        description="Parameter request list (option 55) — options the client wants in the response"
    )

    # ── Server-supplied lease parameters ──
    subnet_mask: Optional[str] = Field(
        default=None,
        description="Offered subnet mask (option 1)"
    )
    router: Optional[str] = Field(
        default=None,
        description="Default gateway from option 3"
    )
    dns_servers: Optional[List[str]] = Field(
        default=None,
        description="DNS server list from option 6"
    )
    lease_time: Optional[int] = Field(
        default=None,
        description="Lease duration in seconds (option 51)"
    )
    renewal_time: Optional[int] = Field(
        default=None,
        description="T1 renewal time in seconds (option 58)"
    )
    rebinding_time: Optional[int] = Field(
        default=None,
        description="T2 rebinding time in seconds (option 59)"
    )

    # ── Raw extras ──
    unknown_options: dict = Field(
        default_factory=dict,
        description="Option code → raw value for any options not explicitly decoded"
    )

    # ── Transport metadata ──
    src_ip: Optional[str] = Field(
        default=None,
        description="IP-layer source address of the captured packet"
    )
    dst_ip: Optional[str] = Field(
        default=None,
        description="IP-layer destination address of the captured packet"
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface the packet was captured on"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of capture"
    )

    @property
    def effective_ip(self) -> Optional[str]:
        """Best available client IP: requested → offered → ciaddr."""
        return self.requested_ip or self.offered_ip or self.client_ip

    @property
    def is_client_message(self) -> bool:
        """True for messages initiated by the client.

        Covers: DISCOVER, REQUEST, DECLINE, RELEASE, and INFORM.
        """
        client_types = {
            DhcpMessageType.DISCOVER,
            DhcpMessageType.REQUEST,
            DhcpMessageType.DECLINE,
            DhcpMessageType.RELEASE,
            DhcpMessageType.INFORM,
        }
        return self.message_type in client_types

    @property
    def is_server_message(self) -> bool:
        """True for messages initiated by the server (OFFER / ACK / NAK)."""
        server_types = {DhcpMessageType.OFFER, DhcpMessageType.ACK, DhcpMessageType.NAK}
        return self.message_type in server_types


class DhcpListenerConfig(BaseModel):
    """Configuration for :class:`DhcpListener`."""

    subnet_filter: Optional[List[str]] = Field(
        default=None,
        description=(
            "Only emit events where the effective client IP falls within one of these subnets. "
            "Accepts any notation accepted by ipaddress.ip_network (e.g. '192.168.1.0/24'). "
            "``None`` means no filtering — all events are emitted."
        )
    )
    message_types: Optional[List[DhcpMessageType]] = Field(
        default=None,
        description=(
            "Restrict captured events to these message types. "
            "``None`` captures all message types."
        )
    )
    include_server_messages: bool = Field(
        default=True,
        description="When True, OFFER / ACK / NAK from DHCP servers are also emitted"
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface to listen on. ``None`` listens on all interfaces"
    )


# ─── Option parser helpers ────────────────────────────────────────

# Scapy DHCP option tuples use string keys for known options and
# integer keys for unknown ones. This map translates known names
# back to the canonical option number so we can handle them uniformly.

_OPTION_NAME_TO_CODE: dict[str, int] = {
    "subnet_mask": 1,
    "router": 3,
    "name_server": 6,
    "hostname": 12,
    "requested_addr": 50,
    "lease_time": 51,
    "message-type": 53,
    "server_id": 54,
    "param_req_list": 55,
    "vendor_class_id": 60,
    "client_id": 61,
    "renewal_time": 58,
    "rebinding_time": 59,
    "FQDN": 81,
    "user_class": 77,
}


def _decode_bytes(value: object) -> Optional[str]:
    """Best-effort bytes → str; returns None for non-byte values."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace").strip("\x00")
    if isinstance(value, str):
        return value
    return None


def _mac_from_bytes(raw: bytes) -> str:
    """Format a 6-byte (or longer) bytes object as a MAC address string."""
    return ":".join(f"{b:02x}" for b in raw[:6])


def _parse_dhcp_options(options: list) -> dict:
    """Flatten a scapy DHCP options list into a {code: value} dict."""
    result: dict = {}
    for item in options:
        if not isinstance(item, (tuple, list)) or len(item) < 2:
            continue
        key, value = item[0], item[1]
        if key in ("end", "pad"):
            continue
        code = _OPTION_NAME_TO_CODE.get(key, key) if isinstance(key, str) else key
        result[code] = value
    return result


def _first_ip(value: object) -> Optional[str]:
    """Return the first IP string from a single value or a list."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else None
    return str(value)


def _ip_list(value: object) -> Optional[List[str]]:
    """Return a list of IP strings from a single value or a list."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


# ─── Subnet filter ────────────────────────────────────────────────

def _build_subnet_networks(
    subnet_filter: Optional[List[str]],
) -> Optional[List[ipaddress.IPv4Network]]:
    """Parse subnet strings into network objects. Returns None for no filter."""
    if not subnet_filter:
        return None
    networks = []
    for s in subnet_filter:
        try:
            networks.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            log.warning("DhcpListener: ignoring invalid subnet filter %r", s)
    return networks or None


def _ip_in_networks(ip: Optional[str], networks: Optional[List[ipaddress.IPv4Network]]) -> bool:
    """Return True if *ip* is contained within any of *networks*, or if no filter is set."""
    if networks is None:
        return True
    if ip is None:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


# ─── Core listener ────────────────────────────────────────────────

class DhcpListener:
    """Passive DHCP listener.

    Captures DHCP packets on UDP ports 67/68 and calls *on_event* for
    every packet that passes the configured filters.

    The sniffer runs in a daemon thread — it will not prevent the
    process from exiting.  Call :meth:`stop` to release resources cleanly.

    Args:
        config: Listener configuration (subnet filter, message-type filter, etc.)
        on_event: Callable invoked with a :class:`DhcpLeaseEvent` for each
            matching packet.  Invoked from the sniffer thread; keep it fast
            or dispatch to a queue.
    """

    def __init__(
        self,
        config: DhcpListenerConfig,
        on_event: Callable[[DhcpLeaseEvent], None],
    ) -> None:
        self._config = config
        self._on_event = on_event
        self._sniffer = None
        self._thread: Optional[threading.Thread] = None
        self._networks = _build_subnet_networks(config.subnet_filter)
        self._running = False

    # ── Public API ────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """True while the sniffer thread is active."""
        return self._running

    def start(self) -> None:
        """Start the background sniffer thread.

        Raises:
            RuntimeError: If the listener is already running.
            ImportError: If scapy is not installed.
        """
        if self._running:
            raise RuntimeError("DhcpListener is already running")

        bpf_filter = "udp and (port 67 or port 68)"
        kwargs: dict = {
            "filter": bpf_filter,
            "prn": self._handle_packet,
            "store": False,
        }
        if self._config.interface:
            kwargs["iface"] = self._config.interface

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        self._running = True
        log.info("DhcpListener started (interface=%s)", self._config.interface or "all")

    def stop(self) -> None:
        """Stop the sniffer and join the background thread."""
        if not self._running or self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Exception:  # pylint: disable=broad-except
            log.debug("DhcpListener: error stopping sniffer", exc_info=True)
        self._running = False
        log.info("DhcpListener stopped")

    def __enter__(self) -> "DhcpListener":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── Internal ──────────────────────────────────────────────────

    def _handle_packet(self, pkt) -> None:
        """Scapy packet callback — parse, filter, and dispatch."""
        try:
            event = _parse_packet(pkt)
            if event is None:
                return
            if self._passes_filters(event):
                self._on_event(event)
        except Exception:  # pylint: disable=broad-except
            log.debug("DhcpListener: error parsing packet", exc_info=True)

    def _passes_filters(self, event: DhcpLeaseEvent) -> bool:
        """Return True if *event* matches all configured filters."""
        # ── Server message opt-out ──
        if not self._config.include_server_messages and event.is_server_message:
            return False

        # ── Message-type filter ──
        if self._config.message_types is not None:
            if event.message_type not in self._config.message_types:
                return False

        # ── Subnet filter ──
        if self._networks is not None:
            # For client messages, check requested or ciaddr.
            # For server messages (OFFER/ACK), check offered_ip or server_id.
            candidate_ips = [
                event.requested_ip,
                event.offered_ip,
                event.client_ip,
            ]
            if not any(_ip_in_networks(ip, self._networks) for ip in candidate_ips):
                return False

        return True


# ─── Option sub-decoders ─────────────────────────────────────────

def _decode_client_identifier(opts: dict) -> Optional[str]:
    """Decode DHCP option 61 (client identifier) to a string.

    Type byte 0x01 → format remaining bytes as MAC address.
    Otherwise decode the payload as UTF-8.
    """
    raw = opts.get(61)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)) and len(raw) > 1:
        id_type, payload = raw[0], raw[1:]
        if id_type == 1 and len(payload) >= 6:
            return _mac_from_bytes(payload)
        return payload.decode("utf-8", errors="replace")
    return _decode_bytes(raw)


def _decode_fqdn(opts: dict) -> Optional[str]:
    """Decode DHCP option 81 (FQDN, RFC 4702).

    The first 3 bytes are flags/RCODE/RCODE2 — the name starts at byte 4.
    """
    raw = opts.get(81)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)) and len(raw) > 3:
        return raw[3:].decode("utf-8", errors="replace").strip("\x00.")
    return _decode_bytes(raw)


def _decode_requested_options(opts: dict) -> Optional[List[int]]:
    """Decode DHCP option 55 (parameter request list) to a list of ints."""
    param_req = opts.get(55)
    if param_req is None:
        return None
    if isinstance(param_req, (list, tuple)):
        return [int(x) for x in param_req]
    if isinstance(param_req, (bytes, bytearray)):
        return list(param_req)
    return None


def _extract_unknown_options(opts: dict) -> dict:
    """Return option code → repr(value) for all unrecognised option codes."""
    known = set(_OPTION_NAME_TO_CODE.values())
    return {
        code: repr(val)
        for code, val in opts.items()
        if isinstance(code, int) and code not in known
    }


# ─── Packet parser (module-level, testable standalone) ───────────

def _parse_packet(pkt) -> Optional[DhcpLeaseEvent]:
    """Parse a scapy packet into a :class:`DhcpLeaseEvent`.

    Returns ``None`` if the packet does not contain a DHCP layer.
    """
    if DHCP not in pkt or BOOTP not in pkt:
        return None

    bootp = pkt[BOOTP]
    opts = _parse_dhcp_options(getattr(pkt[DHCP], "options", []))

    # ── Client MAC ──
    client_mac = _mac_from_bytes(bytes(bootp.chaddr))

    # ── IP fields from BOOTP fixed header ──
    client_ip  = str(bootp.ciaddr) if bootp.ciaddr and str(bootp.ciaddr) != "0.0.0.0" else None
    offered_ip = str(bootp.yiaddr) if bootp.yiaddr and str(bootp.yiaddr) != "0.0.0.0" else None
    server_ip  = str(bootp.siaddr) if bootp.siaddr and str(bootp.siaddr) != "0.0.0.0" else None

    # ── IP transport ──
    src_ip = str(pkt[IP].src) if IP in pkt else None
    dst_ip = str(pkt[IP].dst) if IP in pkt else None

    # ── Decode DHCP message type ──
    msg_type_raw = opts.get(53)
    message_type = DhcpMessageType.from_int(int(msg_type_raw)) if msg_type_raw is not None else None

    return DhcpLeaseEvent(
        message_type=message_type,
        client_mac=client_mac,
        client_ip=client_ip,
        client_identifier=_decode_client_identifier(opts),
        requested_ip=_first_ip(opts.get(50)),
        offered_ip=offered_ip,
        server_ip=server_ip,
        server_identifier=_first_ip(opts.get(54)),
        hostname=_decode_bytes(opts.get(12)),
        fqdn=_decode_fqdn(opts),
        vendor_class=_decode_bytes(opts.get(60)),
        user_class=_decode_bytes(opts.get(77)),
        requested_options=_decode_requested_options(opts),
        subnet_mask=_first_ip(opts.get(1)),
        router=_first_ip(opts.get(3)),
        dns_servers=_ip_list(opts.get(6)),
        lease_time=int(opts[51]) if opts.get(51) is not None else None,
        renewal_time=int(opts[58]) if opts.get(58) is not None else None,
        rebinding_time=int(opts[59]) if opts.get(59) is not None else None,
        unknown_options=_extract_unknown_options(opts),
        src_ip=src_ip,
        dst_ip=dst_ip,
        interface=getattr(pkt, "sniffed_on", None),
        timestamp=datetime.now(timezone.utc),
    )
