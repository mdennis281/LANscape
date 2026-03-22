"""Local network scanner"""
# Scanner core functionality
from lanscape.core.subnet_scan import (
    SubnetScanner,
    ScannerResults,
    ScanManager
)

# Configuration models for scans
from lanscape.core.scan_config import (
    ScanConfig,
    ArpConfig,
    PingConfig,
    PokeConfig,
    ArpCacheConfig,
    PortScanConfig,
    ServiceScanConfig,
    ServiceScanStrategy,
    ScanType,
    NeighborTableConfig,
    HostnameConfig,
)

from lanscape.core.port_manager import PortManager

# Neighbor table service (centralized ARP/NDP cache)
from lanscape.core.neighbor_table import (
    NeighborTableService,
    NeighborEntry,
    NeighborTable,
)

# Network utilities and device model
from lanscape.core import net_tools  # noqa: F401 – namespace import for `lanscape.net_tools`
from lanscape.core.net_tools import (
    Device,
    get_network_subnet,
    get_all_network_subnets,
    smart_select_primary_subnet,
    is_internal_block,
    is_arp_supported,
    scan_config_uses_arp,
)

from lanscape.core.errors import DeviceError

# Alt-IP resolution (cross-protocol: IPv4 <-> IPv6)
from lanscape.core.alt_ip_resolver import resolve_alt_ips

# Threadpool retry utilities
from lanscape.core.threadpool_retry import (
    ThreadPoolRetryManager,
    RetryJob,
    RetryConfig,
    MultiplierController
)

# Models for structured data
from lanscape.core.models import (
    DeviceStage,
    ScanStage,
    DeviceErrorInfo,
    DeviceResult,
    ProbeResponseInfo,
    ServiceInfo,
    ScanErrorInfo,
    ScanWarningInfo,
    ScanMetadata,
    ScanResults,
    ScanDelta,
    ScanSummary,
    ScanListItem
)

# Webapp server for serving bundled React UI
from lanscape.ui.react_proxy import (
    start_webapp_server,
    REACT_BUILD_DIR,
    DiscoveryService,
    DiscoveredInstance,
    DiscoverResponse,
    build_default_route,
    get_local_address_strings,
)

# Version management
from lanscape.core.version_manager import (
    get_installed_version,
    get_latest_version,
    is_update_available,
    lookup_latest_version
)
