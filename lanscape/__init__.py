"""
Local network scanner
"""
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
    ScanType
)

from lanscape.core.port_manager import PortManager

from lanscape.core import net_tools

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
    get_local_address_strings,
)

# Version management
from lanscape.core.version_manager import (
    get_installed_version,
    get_latest_version,
    is_update_available,
    lookup_latest_version
)
