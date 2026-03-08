"""Network tools for scanning and managing devices on a network."""

# Re-export everything for backward compatibility with
# ``from lanscape.core.net_tools import <name>``

from lanscape.core.net_tools.device import (  # noqa: F401
    Device,
    MacSelector,
    mac_selector,
    _dns_name_decode,
    _parse_mdns_ptr_response,
    _parse_nbstat_response,
)
from lanscape.core.net_tools.subnet_utils import (  # noqa: F401
    get_cidr_from_netmask,
    get_host_ip_mask,
    get_network_subnet,
    get_all_network_subnets,
    network_from_snicaddr,
    smart_select_primary_subnet,
    _is_deprioritized_subnet,
    is_internal_block,
    scan_config_uses_arp,
    is_arp_supported,
)

# Previously imported here; keep re-export for callers that expect it
from lanscape.core.errors import DeviceError  # noqa: F401
