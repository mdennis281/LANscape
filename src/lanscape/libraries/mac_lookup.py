import json
import importlib.resources as pkg_resources

DB = json.load(pkg_resources.open_text('lanscape.resources.mac_addresses', 'mac_db.json'))


def lookup_mac(mac: str) -> str:
    """
    Lookup a MAC address in the database and return the vendor name.
    """
    if mac:
        for m in DB:
            if mac.upper().startswith(str(m).upper()):
                return DB[m]
    return None
        