import re
import logging
import platform
import subprocess
from typing import List, Optional
from scapy.sendrecv import srp
from scapy.layers.l2 import ARP, Ether
from .app_scope import ResourceManager
from .decorators import job_tracker, JobStatsMixin
from .errors import DeviceError


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
        """Try to get the MAC address using Scapy, fallback to ARP if it fails."""
        if mac := self._get_mac_by_scapy(ip):
            log.debug(f"Used Scapy to resolve ip {ip} to mac {mac}")
            return mac
        arp = self._get_mac_by_arp(ip)
        log.debug(f"Used ARP to resolve ip {ip} to mac {arp}")
        return arp

    @job_tracker
    def _get_mac_by_arp(self, ip: str) -> List[str]:
        """Retrieve the last MAC address instance using the ARP command."""
        try:
            # Use the appropriate ARP command based on the platform
            cmd = f"arp -a {ip}" if platform.system() == "Windows" else f"arp {ip}"

            # Execute the ARP command and decode the output
            output = subprocess.check_output(
                cmd, shell=True
            ).decode().replace('-', ':')

            macs = re.findall(r'..:..:..:..:..:..', output)
            # found that typically last mac is the correct one
            return macs
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
            return []

    @job_tracker
    def _get_mac_by_scapy(self, ip: str) -> List[str]:
        """Retrieve the MAC address using the Scapy library."""
        try:
            # Construct and send an ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            # Send the packet and wait for a response
            answered, _ = srp(packet, timeout=1, verbose=False)[0]

            # Extract the MAC addresses from the response
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
