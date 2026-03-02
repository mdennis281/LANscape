"""
mDNS service discovery for LANscape.

Advertises this LANscape instance on the local network using mDNS/DNS-SD
and browses for other instances. The discovered list is served by the
HTTP proxy so the frontend can offer a server picker.

Service type: ``_lanscape._tcp.local.``
"""

import errno
import ipaddress
import json
import logging
import socket
import threading
from typing import Optional

import psutil
from pydantic import BaseModel
from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
)

from lanscape.core.version_manager import get_installed_version

log = logging.getLogger('Discovery')

# Suppress zeroconf library logs — binding failures and async socket errors
# are expected on macOS/BSD (mDNSResponder owns port 5353) and handled gracefully.
# We emit our own warning when falling back to unicast mode.
logging.getLogger('zeroconf').setLevel(logging.CRITICAL)

SERVICE_TYPE = '_lanscape._tcp.local.'


# Interface name substrings that indicate non-LAN adapters.
# Covers: loopback, VMware, VirtualBox, Docker, Hyper-V/WSL,
# ZeroTier, Tailscale, WireGuard, TUN/TAP, Cisco VPN.
_VIRTUAL_IFACE_NAMES = (
    'loop', 'vmnet', 'vbox', 'docker', 'virtual', 'veth',
    'vethernet', 'zerotier', 'tailscale', 'tun', 'tap',
    'wg', 'utun', 'virbr', 'br-', 'ham',
)

# Subnet prefixes that are almost never a real LAN:
# 192.168.137.0/24 = Windows ICS (Internet Connection Sharing).
_ICS_NETWORK = ipaddress.ip_network('192.168.137.0/24')


def _get_local_addresses() -> list[bytes]:
    """
    Collect all private-LAN IPv4 addresses from up, non-virtual interfaces.

    Returns the addresses as packed 4-byte ``bytes`` suitable for passing
    to ``ServiceInfo(addresses=...)``.
    """
    result: list[bytes] = []
    stats = psutil.net_if_stats()

    for iface, addrs in psutil.net_if_addrs().items():
        # Skip down interfaces
        iface_stats = stats.get(iface)
        if not iface_stats or not iface_stats.isup:
            continue
        # Skip common virtual / overlay interfaces
        if any(v in iface.lower() for v in _VIRTUAL_IFACE_NAMES):
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            try:
                ip = ipaddress.ip_address(addr.address)
                if (ip.is_private and not ip.is_loopback
                        and not ip.is_link_local
                        and ip not in _ICS_NETWORK):
                    result.append(socket.inet_aton(str(ip)))
            except (ValueError, OSError):
                continue

    return result


def get_local_address_strings() -> list[str]:
    """
    Return human-readable private-LAN IPv4 addresses from up, non-virtual
    interfaces.  Suitable for display in log messages.
    """
    return [socket.inet_ntoa(addr) for addr in _get_local_addresses()]


def _get_local_subnets() -> list[ipaddress.IPv4Network]:
    """
    Return the subnets of every address that ``_get_local_addresses`` would
    include.  Used by ``_best_lan_address`` to prefer same-subnet peers.
    """
    subnets: list[ipaddress.IPv4Network] = []
    stats = psutil.net_if_stats()

    for iface, addrs in psutil.net_if_addrs().items():
        iface_stats = stats.get(iface)
        if not iface_stats or not iface_stats.isup:
            continue
        if any(v in iface.lower() for v in _VIRTUAL_IFACE_NAMES):
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            try:
                ip = ipaddress.ip_address(addr.address)
                if (ip.is_private and not ip.is_loopback
                        and not ip.is_link_local
                        and ip not in _ICS_NETWORK):
                    net = ipaddress.ip_network(
                        f'{addr.address}/{addr.netmask}', strict=False
                    )
                    subnets.append(net)
            except (ValueError, OSError):
                continue

    return subnets


def _best_lan_address(
    addresses: list[str],
    local_subnets: list[ipaddress.IPv4Network] | None = None,
) -> str | None:
    """
    Pick the most suitable address from a list returned by
    ``ServiceInfo.parsed_addresses()``.

    mDNS records can contain addresses from every interface on the host
    (LAN, VPN, Docker bridges, Hyper-V adapters, etc.).  Selection order:

    1. Private IPv4 on the **same subnet** as one of our own LAN interfaces
    2. Any private IPv4 (not loopback, not link-local, not ICS)
    3. Any non-loopback IPv4
    4. First address as a last resort
    """
    if local_subnets is None:
        local_subnets = _get_local_subnets()

    # Pass 1 — same subnet as one of our own LAN interfaces
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            if ip.version != 4:
                continue
            if any(ip in subnet for subnet in local_subnets):
                return str(ip)
        except ValueError:
            continue

    # Pass 2 — any private, non-overlay IPv4
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            if (ip.version == 4 and ip.is_private
                    and not ip.is_loopback and not ip.is_link_local
                    and ip not in _ICS_NETWORK):
                return str(ip)
        except ValueError:
            continue

    # Pass 3 — any non-loopback IPv4
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            if ip.version == 4 and not ip.is_loopback:
                return str(ip)
        except ValueError:
            continue

    return addresses[0] if addresses else None


class DiscoveredInstance(BaseModel):
    """A LANscape backend discovered on the local network."""
    host: str
    ws_port: int
    http_port: int
    version: str
    hostname: str


class DiscoverResponse(BaseModel):
    """Response payload for the /api/discover endpoint."""
    mdns_enabled: bool
    default_route: str
    instances: list[DiscoveredInstance]


def build_default_route(http_port: int) -> str:
    """Build the default connection URL for this server.

    Prefers a private LAN address so remote browsers on the same network
    can reach the server.  Falls back to ``localhost``.
    """
    addrs = get_local_address_strings()
    host = addrs[0] if addrs else 'localhost'
    return f'http://{host}:{http_port}'


class DiscoveryService:
    """
    Manages mDNS advertisement of *this* instance and browsing for others.

    Thread-safe: the browser callback mutates ``_instances`` under a lock;
    :meth:`get_instances` copies the list under the same lock.
    """

    def __init__(
        self,
        ws_port: int,
        http_port: int,
        service_name: Optional[str] = None,
    ):
        self._ws_port = ws_port
        self._http_port = http_port
        self._zeroconf: Optional[Zeroconf] = None
        self._browser: Optional[ServiceBrowser] = None
        self._service_info: Optional[ServiceInfo] = None

        self._local_subnets: list[ipaddress.IPv4Network] = []
        self._lock = threading.Lock()
        self._instances: dict[str, DiscoveredInstance] = {}

        # Build a unique, human-friendly service name.
        hostname = socket.gethostname()
        self._service_name = service_name or f'LANscape ({hostname})'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register this instance and start browsing for others.

        On macOS (and some BSDs) the system mDNS daemon (``mDNSResponder``)
        holds port 5353 exclusively, preventing Zeroconf from binding its
        multicast listen socket.  When that happens we fall back to
        **unicast mode** — service browsing and registration still work but
        responses arrive as unicast rather than multicast.
        """
        self._zeroconf = self._create_zeroconf()

        # Cache our own subnets so _best_lan_address can prefer same-subnet
        # peers without re-scanning interfaces on every callback.
        self._local_subnets = _get_local_subnets()

        # Advertise ourselves
        self._register_service()

        # Browse for peers
        self._browser = ServiceBrowser(
            self._zeroconf,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )
        log.debug('mDNS discovery started (service=%s)', self._service_name)

    def _create_zeroconf(self) -> Zeroconf:
        """Create a Zeroconf instance, falling back to unicast mode.

        Returns a ``Zeroconf`` instance.  First tries the default multicast
        mode (binds port 5353).  If that fails with ``EADDRINUSE`` — common
        on macOS where ``mDNSResponder`` already owns the port — retries in
        unicast mode which uses an ephemeral port instead.
        """
        try:
            return Zeroconf(ip_version=IPVersion.V4Only)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            log.warning(
                'mDNS port 5353 in use (system mDNS daemon); '
                'falling back to unicast mode — discovery may be limited'
            )
            return Zeroconf(ip_version=IPVersion.V4Only, unicast=True)

    def stop(self) -> None:
        """Unregister and close mDNS resources."""
        if self._zeroconf and self._service_info:
            try:
                self._zeroconf.unregister_service(self._service_info)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log.debug('Error un-registering mDNS service: %s', exc)

        if self._zeroconf:
            try:
                self._zeroconf.close()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log.debug('Error closing zeroconf: %s', exc)

        self._zeroconf = None
        self._browser = None
        self._service_info = None
        log.debug('mDNS discovery stopped')

    def get_instances(self) -> list[dict]:
        """Return a snapshot of discovered instances as plain dicts."""
        with self._lock:
            return [inst.model_dump() for inst in self._instances.values()]

    def get_instances_json(self) -> str:
        """Return discovered instances as a JSON string."""
        return json.dumps(self.get_instances())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _register_service(self) -> None:
        """Register this LANscape instance via mDNS."""
        hostname = socket.gethostname()
        version = get_installed_version()

        properties = {
            'ws_port': str(self._ws_port),
            'http_port': str(self._http_port),
            'version': version,
            'hostname': hostname,
        }

        # Gather all private-LAN addresses so the mDNS response includes
        # A records. Without this, remote browsers see the SRV record but
        # can never resolve the host address.
        local_addrs = _get_local_addresses()
        if not local_addrs:
            log.warning('No private LAN addresses found; mDNS may not work')

        self._service_info = ServiceInfo(
            SERVICE_TYPE,
            name=f'{self._service_name}.{SERVICE_TYPE}',
            port=self._ws_port,
            properties=properties,
            server=f'{hostname}.local.',
            addresses=local_addrs or None,
        )

        assert self._zeroconf is not None
        self._zeroconf.register_service(self._service_info)
        log.debug(
            'Registered mDNS service: %s (ws=%d, http=%d)',
            self._service_name, self._ws_port, self._http_port,
        )

    def _on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        """Callback for ServiceBrowser events."""
        if state_change == ServiceStateChange.Removed:
            with self._lock:
                if name in self._instances:
                    log.debug('mDNS service removed: %s', name)
                    del self._instances[name]
            return

        # Added or Updated — resolve with retries.  Remote hosts sometimes
        # need more than one attempt (especially across subnets or on busy
        # networks where the first mDNS response is lost).
        info: Optional[ServiceInfo] = None
        for attempt in range(3):
            info = zeroconf.get_service_info(
                service_type, name, timeout=4000,
            )
            if info is not None:
                break
            log.debug(
                'get_service_info attempt %d/3 timed out for %s',
                attempt + 1, name,
            )

        if info is None:
            log.debug('Could not resolve mDNS record: %s', name)
            return

        props = {
            k.decode() if isinstance(k, bytes) else k:
            v.decode() if isinstance(v, bytes) else v
            for k, v in (info.properties or {}).items()
        }

        # Resolve host address — prefer an IP on the same subnet as one of
        # our own LAN interfaces, then fall back to any private IPv4.
        addresses = info.parsed_addresses()
        if not addresses:
            return
        host = _best_lan_address(addresses, self._local_subnets)
        if host is None:
            return

        try:
            instance = DiscoveredInstance(
                host=host,
                ws_port=int(props.get('ws_port', info.port)),
                http_port=int(props.get('http_port', 0)),
                version=props.get('version', 'unknown'),
                hostname=props.get('hostname', 'unknown'),
            )
        except (ValueError, TypeError) as exc:
            log.debug('Ignoring malformed mDNS record %s: %s', name, exc)
            return

        with self._lock:
            self._instances[name] = instance

        log.debug(
            'mDNS service %s: %s (%s:%d, from %s)',
            'updated' if state_change == ServiceStateChange.Updated else 'discovered',
            name, host, instance.ws_port, addresses,
        )
