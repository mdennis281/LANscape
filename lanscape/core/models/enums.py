"""
Enumeration types for scanner models.
"""

from enum import Enum


class DeviceStage(str, Enum):
    """Stage of device discovery/scanning."""
    RESOLVING = "resolving"
    FOUND = "found"
    SCANNING = "scanning"
    COMPLETE = "complete"


class ScanStage(str, Enum):
    """Overall scan stage."""
    INSTANTIATED = "instantiated"
    SCANNING_DEVICES = "scanning devices"
    TESTING_PORTS = "testing ports"
    COMPLETE = "complete"
    TERMINATING = "terminating"
    TERMINATED = "terminated"


class WarningCategory(str, Enum):
    """Category grouping for scan warnings."""
    CONCURRENCY = "concurrency"
    STAGE_SKIP = "stage_skip"
    CAPABILITY = "capability"
    RESILIENCE = "resilience"


class StageType(str, Enum):
    """Type identifier for each composable scan stage."""
    ICMP_DISCOVERY = "icmp_discovery"
    ARP_DISCOVERY = "arp_discovery"
    POKE_ARP_DISCOVERY = "poke_arp_discovery"
    ICMP_ARP_DISCOVERY = "icmp_arp_discovery"
    IPV6_NDP_DISCOVERY = "ipv6_ndp_discovery"
    IPV6_MDNS_DISCOVERY = "ipv6_mdns_discovery"
    PORT_SCAN = "port_scan"
