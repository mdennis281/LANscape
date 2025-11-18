"""Helper functions for tests in the lanscape project."""
from lanscape.core.ip_parser import get_address_count
from lanscape.core.net_tools import smart_select_primary_subnet


def right_size_subnet(subnet: str = '') -> str:
    """
    Used to improve speed of test time by increasing the prefix length until
    the subnet contains no more than 25 addresses. Protect against malformed
    input and infinite loops by validating the mask and applying a max-iteration
    safety limit.
    """
    if not subnet:
        subnet = smart_select_primary_subnet()

    max_mask = 32
    max_iterations = 10
    max_ips = 25
    iterations = 0

    while get_address_count(subnet) > max_ips:
        parts = subnet.split('/')
        if len(parts) != 2:
            raise ValueError(f"Invalid subnet format: {subnet}")
        ip = parts[0]
        try:
            mask = int(parts[1])
        except ValueError as exc:
            raise ValueError(f"Invalid mask in subnet: {subnet}") from exc

        if mask >= max_mask:
            # Cannot increase the mask further; abort to avoid infinite loop.
            raise RuntimeError(f"Cannot reduce subnet {subnet} further (mask={mask}).")

        mask += 1
        subnet = f"{ip}/{mask}"

        iterations += 1
        if iterations > max_iterations:
            raise RuntimeError(f"Exceeded maximum iterations while resizing subnet: {subnet}")

    return subnet
