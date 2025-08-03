
from lanscape.libraries.ip_parser import get_address_count


def right_size_subnet(subnet: str):
    """
    Used to improve speed of test time
    """
    if get_address_count(subnet) > 500:
        parts = subnet.split('/')
        ip = parts[0]
        mask = int(parts[1])
        mask += 1
        return right_size_subnet(f"{ip}/{mask}")
    return subnet
