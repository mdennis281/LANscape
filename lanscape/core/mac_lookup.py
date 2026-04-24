"""MAC address lookup and resolution service."""

import logging
from typing import List, Optional

from lanscape.core.app_scope import ResourceManager
from lanscape.core.decorators import job_tracker, JobStatsMixin
from lanscape.core.errors import DeviceError
from lanscape.core.system_compat import (
    send_arp_request,
    is_ipv6,
)
from lanscape.core.neighbor_table import NeighborTableService
log = logging.getLogger('MacLookup')


class MacLookup:
    """High-level MAC address lookup service."""

    def __init__(self):
        self._db = ResourceManager('mac_addresses').get_json('mac_db.json')
        self._resolver = MacResolver()

    def lookup_vendor(self, mac: str) -> Optional[str]:
        """
        Lookup a MAC address in the database and return the vendor name.
        """
        if mac:
            for m in self._db:
                if mac.upper().startswith(str(m).upper()):
                    return self._db[m]
        return None

    def resolve_mac_addresses(self, ip: str) -> List[str]:
        """
        Get MAC addresses for an IP address using available methods.
        """
        return self._resolver.get_macs(ip)


class MacResolver(JobStatsMixin):
    """Handles MAC address resolution using various methods."""

    def __init__(self):
        super().__init__()
        self.caught_errors: List[DeviceError] = []

    def get_macs(self, ip: str) -> List[str]:
        """Resolve MAC address via neighbor cache, or Scapy if cache is unhealthy."""
        if self._neighbor_cache_healthy():
            return self._get_mac_by_neighbor_cache(ip)
        if not is_ipv6(ip):
            if macs := self._get_mac_by_scapy(ip):
                log.debug("Used Scapy to resolve ip %s to mac %s", ip, macs)
                return macs
        return []

    def _neighbor_cache_healthy(self) -> bool:
        """Return True if the NeighborTableService is running and has entries."""
        try:
            svc = NeighborTableService.instance()
            if not svc.is_running:
                return False
            return len(svc.get_table(want_v6=False).entries) > 0 \
                or len(svc.get_table(want_v6=True).entries) > 0
        except Exception:  # pylint: disable=broad-except
            return False

    @job_tracker
    def _get_mac_by_neighbor_cache(self, ip: str) -> List[str]:
        """Retrieve MAC addresses from the NeighborTableService."""
        try:
            svc = NeighborTableService.instance()
            return svc.get_macs(ip)
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
            return []

    @job_tracker
    def _get_mac_by_scapy(self, ip: str) -> List[str]:
        """Retrieve MAC addresses using Scapy ARP."""
        try:
            answered, _ = send_arp_request(ip, timeout=1.0)
            return [res[1].hwsrc for res in answered]
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
            return []
