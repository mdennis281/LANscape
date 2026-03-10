"""MAC address lookup and resolution service."""

import logging
import subprocess
from typing import List, Optional

from .app_scope import ResourceManager
from .decorators import job_tracker, JobStatsMixin
from .errors import DeviceError
from .system_compat import (
    get_arp_lookup_command,
    extract_mac_from_output,
    send_arp_request,
    is_ipv6,
)


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
        """Try to get the MAC address using Scapy, fallback to ARP/NDP if it fails."""
        if not is_ipv6(ip):
            if mac := self._get_mac_by_scapy(ip):
                log.debug(f"Used Scapy to resolve ip {ip} to mac {mac}")
                return mac
        neighbor = self._get_mac_by_neighbor_cache(ip)
        log.debug(f"Used neighbor cache to resolve ip {ip} to mac {neighbor}")
        return neighbor

    @job_tracker
    def _get_mac_by_neighbor_cache(self, ip: str) -> List[str]:
        """Retrieve MAC addresses using the system ARP/NDP command."""
        try:
            cmd = get_arp_lookup_command(ip)
            output = subprocess.check_output(cmd, shell=True).decode()
            return extract_mac_from_output(output)
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


# Backward compatibility functions
def lookup_mac(mac: str) -> Optional[str]:
    """Backward compatibility function for MAC vendor lookup."""
    return MacLookup().lookup_vendor(mac)


def get_macs(ip: str) -> List[str]:
    """Backward compatibility function for MAC resolution."""
    return MacResolver().get_macs(ip)
