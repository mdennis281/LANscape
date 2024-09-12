import json
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
        