"""IPv6 device discovery stages (NDP and mDNS)."""

import ipaddress
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.models.enums import StageType
from lanscape.core.scan_config import IPv6NDPDiscoveryStageConfig, IPv6MDNSDiscoveryStageConfig
from lanscape.core.net_tools.device import Device
from lanscape.core.ip_parser import get_address_count
from lanscape.core.neighbor_table import NeighborTableService, NeighborEntry
from lanscape.core.system_compat import (
    get_ipv6_interface_scopes,
    get_ndp_ping_command,
    is_ipv6,
)


# ═══════════════════════════════════════════════════════════════════
#  IPv6 NDP Neighbor Discovery
# ═══════════════════════════════════════════════════════════════════


class IPv6NDPDiscoveryStage(ScanStageMixin):
    """Discover IPv6 devices via multicast NDP (ping ff02::1).

    Lifecycle of :class:`NeighborTableService` is scoped entirely to
    this stage — it is started on entry and stopped on completion or
    termination.
    """

    stage_type = StageType.IPV6_NDP_DISCOVERY
    stage_name = "IPv6 NDP Discovery"
    counter_label = "devices discovered"

    def __init__(
        self,
        cfg: IPv6NDPDiscoveryStageConfig,
        *,
        subnet_hint: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self._subnet_hint = subnet_hint
        self._neighbor_svc: Optional[NeighborTableService] = None

    def execute(self, context: ScanContext) -> None:
        subnet_str = self._subnet_hint or context.subnet
        self.total = get_address_count(subnet_str) if subnet_str else 0

        scopes = self._detect_scopes()

        # Start neighbor table service scoped to this stage
        self._neighbor_svc = NeighborTableService.instance()
        ntc = self.cfg.neighbor_table_config
        self._neighbor_svc.start(
            refresh_interval=ntc.refresh_interval,
            command_timeout=ntc.command_timeout,
        )

        for scope in scopes:
            if not self.running:
                break
            self._ping_multicast(scope)

        # Wait for the neighbor table to refresh after pings
        if self.running and self._neighbor_svc.is_running:
            self._neighbor_svc.wait_for_refresh()

        # Harvest NDP entries and add devices
        if self.running:
            self._harvest_ndp_devices(context)

    def _detect_scopes(self):
        """Determine which interface scopes to probe."""
        if self.cfg.interface:
            return [self.cfg.interface]
        return get_ipv6_interface_scopes()

    def _ping_multicast(self, scope: str) -> None:
        """Send ICMPv6 multicast ping to ff02::1 on the given scope."""
        target = f"ff02::1%{scope}"
        cmd = get_ndp_ping_command(target)
        self.log.debug("NDP multicast ping: %s", ' '.join(cmd))
        try:
            subprocess.run(
                cmd, capture_output=True, timeout=10, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            self.log.debug("NDP ping failed on scope %s: %s", scope, exc)

    def _harvest_ndp_devices(self, context: ScanContext) -> None:
        """Read IPv6 entries from the neighbor table and add as devices.

        Filters out non-unicast addresses (multicast, loopback, link-local)
        and restricts to the target subnet when available.  Device metadata
        resolution is threaded for performance.
        """
        if not self._neighbor_svc:
            return

        candidates = self._filter_neighbor_entries(context)
        if not candidates:
            self.log.debug("No IPv6 unicast neighbors to harvest")
            return

        self.log.debug("Harvesting %d IPv6 neighbor entries", len(candidates))

        def _resolve_device(dev: Device) -> Device:
            dev.get_metadata(hostname_config=self.cfg.hostname_config)
            dev.stage = 'found'
            return dev

        workers = min(self.cfg.t_cnt, len(candidates))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="NDP") as pool:
            futures = {}
            for ip, entry in candidates:
                if not self.running:
                    break
                device = Device(ip=ip)
                device.alive = True
                device.macs = [entry.mac]
                device.stage = 'resolving'
                if context.add_device(device):
                    futures[pool.submit(_resolve_device, device)] = ip

            for future in as_completed(futures):
                if not self.running:
                    break
                try:
                    future.result()
                except Exception as exc:  # pylint: disable=broad-except
                    self.log.debug("Error resolving %s: %s", futures[future], exc)
                self.increment()

    def _filter_neighbor_entries(
        self, context: ScanContext,
    ) -> List[tuple[str, NeighborEntry]]:
        """Return (ip, entry) pairs from the neighbor table, filtered to
        unicast addresses on the target subnet."""
        if not self._neighbor_svc:
            return []

        # Build subnet filter from hint or context
        subnet_net: Optional[ipaddress.IPv6Network] = None
        subnet_str = self._subnet_hint or context.subnet
        if subnet_str:
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                if net.version == 6:
                    subnet_net = net
            except ValueError:
                pass

        candidates: list[tuple[str, NeighborEntry]] = []
        table = self._neighbor_svc.get_table(want_v6=True)
        for ip, entry in table.entries.items():
            if not is_ipv6(ip):
                continue
            try:
                addr = ipaddress.ip_address(ip.split('%')[0])
            except ValueError:
                continue

            # Skip non-unicast: multicast (ff00::/8), loopback, link-local (fe80::/10)
            if addr.is_multicast or addr.is_loopback or addr.is_link_local:
                continue

            # Filter to target subnet if known
            if subnet_net and addr not in subnet_net:
                continue

            candidates.append((ip, entry))

        return candidates


# ═══════════════════════════════════════════════════════════════════
#  IPv6 mDNS Service Discovery
# ═══════════════════════════════════════════════════════════════════


class IPv6MDNSDiscoveryStage(ScanStageMixin):
    """Discover IPv6 devices via mDNS service browsing (zeroconf)."""

    stage_type = StageType.IPV6_MDNS_DISCOVERY
    stage_name = "IPv6 mDNS Discovery"
    counter_label = "devices discovered"

    _BASE_SERVICE_TYPES = {
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ssh._tcp.local.",
        "_smb._tcp.local.",
        "_ftp._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_googlecast._tcp.local.",
        "_workstation._tcp.local.",
        "_device-info._tcp.local.",
        "_companion-link._tcp.local.",
        "_homekit._tcp.local.",
        "_hap._tcp.local.",
        "_rdp._tcp.local.",
        "_rfb._tcp.local.",
        "_nfs._tcp.local.",
        "_afpovertcp._tcp.local.",
    }

    def __init__(
        self,
        cfg: IPv6MDNSDiscoveryStageConfig,
    ) -> None:
        super().__init__()
        self.cfg = cfg

    def execute(self, context: ScanContext) -> None:
        # Progress tracks elapsed time in half-second ticks
        self.total = max(int(self.cfg.timeout / 0.5), 1)

        # Ensure neighbor table service is running for MAC resolution
        if not NeighborTableService.instance().is_running:
            NeighborTableService.instance().start()

        try:
            from zeroconf import Zeroconf, ServiceBrowser  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.log.warning("zeroconf not installed — skipping mDNS discovery")
            self._completed = self.total
            return

        discovered: dict[str, Device] = {}

        class _Listener:
            """Zeroconf service listener for mDNS discovery."""

            def add_service(self, zc, svc_type, name):
                """Handle a newly discovered mDNS service."""
                info = zc.get_service_info(svc_type, name)
                if info is None:
                    return
                for addr in info.parsed_addresses():
                    if not is_ipv6(addr) or addr in discovered:
                        continue
                    try:
                        v6 = ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if v6.is_multicast or v6.is_loopback or v6.is_link_local:
                        continue
                    dev = Device(ip=addr)
                    dev.alive = True
                    if info.server:
                        hostname = info.server.rstrip('.')
                        if hostname.endswith('.local'):
                            hostname = hostname[:-6]
                        dev.hostname = hostname
                    discovered[addr] = dev

            def remove_service(self, zc, svc_type, name):
                """Handle removal of an mDNS service (no-op)."""

            def update_service(self, zc, svc_type, name):
                """Handle update of an mDNS service (no-op)."""

        zc = Zeroconf()
        listener = _Listener()

        # Dynamic type discovery via meta-query
        discovered_types: list[str] = []

        class _TypeListener:
            """Listener for mDNS service-type meta-query."""

            def add_service(self, _zc, _svc_type, name):
                """Record a newly discovered service type."""
                discovered_types.append(name)

            def remove_service(self, _zc, _svc_type, _name):
                """Handle removal (no-op)."""

            def update_service(self, _zc, _svc_type, _name):
                """Handle update (no-op)."""

        ServiceBrowser(zc, "_services._dns-sd._udp.local.", _TypeListener())

        # Start browsing base types
        active_types: set[str] = set(self._BASE_SERVICE_TYPES)
        for svc_type in self._BASE_SERVICE_TYPES:
            ServiceBrowser(zc, svc_type, listener)

        # Wait for timeout, periodically adding newly-discovered types
        deadline = time.monotonic() + self.cfg.timeout
        while time.monotonic() < deadline and self.running:
            time.sleep(0.5)
            self.increment()
            new_types = set(discovered_types) - active_types
            for svc_type in new_types:
                self.log.debug("mDNS: browsing discovered type %s", svc_type)
                ServiceBrowser(zc, svc_type, listener)
            active_types.update(new_types)

        zc.close()
        # Ensure we reach 100% even if loop timing is slightly off
        self._completed = self.total

        for dev in discovered.values():
            dev.stage = 'resolving'
            context.add_device(dev)

        for dev in discovered.values():
            dev.get_metadata(hostname_config=self.cfg.hostname_config)
            dev.stage = 'found'
