import re
import json
import logging
import platform
import subprocess
from typing import List

from .app_scope import ResourceManager

DB = json.loads(ResourceManager('mac_addresses').get('mac_db.json'))

log = logging.getLogger('MacLookup')


def lookup_mac(mac: str) -> str:
    """
    Lookup a MAC address in the database and return the vendor name.
    """
    if mac:
        for m in DB:
            if mac.upper().startswith(str(m).upper()):
                return DB[m]
    return None
        
def get_macs(ip: str) -> List[str]:
    """Try to get the MAC address using Scapy, fallback to ARP if it fails."""
    if mac := get_mac_by_scapy(ip):
        log.debug(f"Used Scapy to resolve ip {ip} to mac {mac}")
        return mac
    arp = get_mac_by_arp(ip)
    log.debug(f"Used ARP to resolve ip {ip} to mac {arp}")
    return arp


def get_mac_by_arp(ip: str) -> List[str]:
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
    except:
        return []

def get_mac_by_scapy(ip: str) -> List[str]:
    """Retrieve the MAC address using the Scapy library."""
    try:
        from scapy.all import ARP, Ether, srp

        # Construct and send an ARP request
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send the packet and wait for a response
        result = srp(packet, timeout=1, verbose=0)[0]

        # Extract the MAC addresses from the response
        return [res[1].hwsrc for res in result]
        # return result[0][1].hwsrc if result else None
    except:
        return None

