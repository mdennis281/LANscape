"""
mDNS service discovery for LANscape.

Advertises this LANscape instance on the local network using mDNS/DNS-SD
and browses for other instances. The discovered list is served by the
HTTP proxy so the frontend can offer a server picker.

Service type: ``_lanscape._tcp.local.``
"""

import ipaddress
import json
import logging
import socket
import threading
from typing import Optional

from pydantic import BaseModel
from zeroconf import (
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
)

from lanscape.core.version_manager import get_installed_version

log = logging.getLogger('Discovery')

SERVICE_TYPE = '_lanscape._tcp.local.'


def _best_lan_address(addresses: list[str]) -> str | None:
    """
    Pick the most suitable address from a list returned by
    ``ServiceInfo.parsed_addresses()``.

    mDNS records can contain addresses from every interface on the host
    (LAN, VPN, Docker bridges, Hyper-V adapters, etc.).  This function
    picks the most useful one for a LAN app:

    1. Private IPv4 (10/172.16-31/192.168), not loopback, not link-local
    2. Any non-loopback IPv4
    3. First address as a last resort
    """
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            if (ip.version == 4 and ip.is_private
                    and not ip.is_loopback and not ip.is_link_local):
                return str(ip)
        except ValueError:
            continue

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

        self._lock = threading.Lock()
        self._instances: dict[str, DiscoveredInstance] = {}

        # Build a unique, human-friendly service name.
        hostname = socket.gethostname()
        self._service_name = service_name or f'LANscape ({hostname})'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register this instance and start browsing for others."""
        # Bind to all interfaces — this is standard mDNS behaviour (RFC 6762).
        # Restricting to one interface breaks discovery when the OS picks the
        # wrong primary interface (VPN up, multiple NICs, etc.).
        # Address selection is handled in _best_lan_address(); unreachable
        # entries are filtered by the frontend's WebSocket probe.
        self._zeroconf = Zeroconf()

        # Advertise ourselves
        self._register_service()

        # Browse for peers
        self._browser = ServiceBrowser(
            self._zeroconf,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )
        log.info('mDNS discovery started (service=%s)', self._service_name)

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
        log.info('mDNS discovery stopped')

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

        self._service_info = ServiceInfo(
            SERVICE_TYPE,
            name=f'{self._service_name}.{SERVICE_TYPE}',
            port=self._ws_port,
            properties=properties,
            server=f'{hostname}.local.',
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

        # Added or Updated
        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            return

        props = {
            k.decode() if isinstance(k, bytes) else k:
            v.decode() if isinstance(v, bytes) else v
            for k, v in (info.properties or {}).items()
        }

        # Resolve host address — prefer a private LAN IP over VPN / virtual
        # adapter addresses that mDNS may also include in the record.
        addresses = info.parsed_addresses()
        if not addresses:
            return
        host = _best_lan_address(addresses)
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
            'mDNS service %s: %s (%s:%d)',
            'updated' if state_change == ServiceStateChange.Updated else 'discovered',
            name, host, instance.ws_port,
        )
