import json

DB = json.load(open('./resources/mac_addresses/mac_db.json', 'r'))

def lookup_mac(mac: str) -> str:
    """
    Lookup a MAC address in the database and return the vendor name.
    """
    if mac:
        for m in DB:
            if mac.upper().startswith(m.upper()):
                return DB[m]
    return None
        