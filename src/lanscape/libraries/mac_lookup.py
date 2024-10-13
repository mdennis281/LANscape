import re
import json
import platform
import subprocess
from typing import Optional

from .resource_manager import ResourceManager

DB = json.loads(ResourceManager('mac_addresses').get('mac_db.json'))


def lookup_mac(mac: str) -> str:
    """
    Lookup a MAC address in the database and return the vendor name.
    """
    if mac:
        for m in DB:
            if mac.upper().startswith(str(m).upper()):
                return DB[m]
    return None
        
def get_mac(ip: str) -> Optional[str]:
    """Try to get the MAC address using Scapy, fallback to ARP if it fails."""
    if mac := get_mac_by_scapy(ip):
        return mac
    return get_mac_by_arp(ip)

def get_mac_by_arp(ip: str) -> Optional[str]:
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
        return macs[-1] if macs else None
    except:
        return None

def get_mac_by_scapy(ip: str) -> Optional[str]:
    """Retrieve the MAC address using the Scapy library."""
    try:
        from scapy.all import ARP, Ether, srp

        # Construct and send an ARP request
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send the packet and wait for a response
        result = srp(packet, timeout=1, verbose=0)[0]

        # Extract the MAC address from the response
        return result[0][1].hwsrc if result else None
    except:
        return None

