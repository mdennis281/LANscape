"""
Stage configuration presets — predefined tuning profiles for scan stages.

Each stage type has three presets:

- **fast**: Minimize scan time at the cost of accuracy.
- **balanced**: The default configuration — good trade-off.
- **accurate**: Maximize detection reliability at the cost of speed.

Usage from the library::

    from lanscape import StagePreset, get_stage_presets

    # Get all presets for all stages
    presets = get_stage_presets()

    # Get a specific stage's preset config dict
    fast_icmp = presets["icmp_discovery"]["fast"]

    # Or use with StageConfig directly
    from lanscape import StageConfig, StageType
    stage = StageConfig(
        stage_type=StageType.ICMP_DISCOVERY,
        config=get_stage_presets()["icmp_discovery"]["fast"],
    )
"""

from enum import Enum
from typing import Dict

from lanscape.core.models.enums import StageType
from lanscape.core.scan_config import (
    STAGE_CONFIG_REGISTRY,
    PingConfig,
    ArpConfig,
    ArpCacheConfig,
    PokeConfig,
    HostnameConfig,
    NeighborTableConfig,
    PortScanConfig,
    ServiceScanConfig,
    ServiceScanStrategy,
    ICMPDiscoveryStageConfig,
    ARPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
    ICMPARPDiscoveryStageConfig,
    IPv6NDPDiscoveryStageConfig,
    IPv6MDNSDiscoveryStageConfig,
    PortScanStageConfig,
)


class StagePreset(str, Enum):
    """Predefined tuning profiles for scan stages."""
    FAST = "fast"
    BALANCED = "balanced"
    ACCURATE = "accurate"


# ── Preset definitions ──────────────────────────────────────────────
#
# Each entry maps StageType -> {preset_name -> config_instance}.
# "balanced" always matches the Pydantic defaults (i.e. a plain constructor).

_PRESETS: Dict[StageType, Dict[StagePreset, object]] = {

    StageType.ICMP_DISCOVERY: {
        StagePreset.FAST: ICMPDiscoveryStageConfig(
            ping_config=PingConfig(attempts=1, ping_count=1, timeout=0.5, retry_delay=0.1),
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: ICMPDiscoveryStageConfig(),
        StagePreset.ACCURATE: ICMPDiscoveryStageConfig(
            ping_config=PingConfig(attempts=3, ping_count=2, timeout=2.0, retry_delay=0.5),
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.ARP_DISCOVERY: {
        StagePreset.FAST: ARPDiscoveryStageConfig(
            arp_config=ArpConfig(attempts=1, timeout=1.0),
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: ARPDiscoveryStageConfig(),
        StagePreset.ACCURATE: ARPDiscoveryStageConfig(
            arp_config=ArpConfig(attempts=3, timeout=3.0),
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.POKE_ARP_DISCOVERY: {
        StagePreset.FAST: PokeARPDiscoveryStageConfig(
            poke_config=PokeConfig(attempts=1, timeout=1.0),
            arp_cache_config=ArpCacheConfig(attempts=1, wait_before=0.1),
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: PokeARPDiscoveryStageConfig(),
        StagePreset.ACCURATE: PokeARPDiscoveryStageConfig(
            poke_config=PokeConfig(attempts=2, timeout=3.0),
            arp_cache_config=ArpCacheConfig(attempts=2, wait_before=0.5),
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.ICMP_ARP_DISCOVERY: {
        StagePreset.FAST: ICMPARPDiscoveryStageConfig(
            ping_config=PingConfig(attempts=1, ping_count=1, timeout=0.5, retry_delay=0.1),
            arp_cache_config=ArpCacheConfig(attempts=1, wait_before=0.1),
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: ICMPARPDiscoveryStageConfig(),
        StagePreset.ACCURATE: ICMPARPDiscoveryStageConfig(
            ping_config=PingConfig(attempts=3, ping_count=2, timeout=2.0, retry_delay=0.5),
            arp_cache_config=ArpCacheConfig(attempts=2, wait_before=0.5),
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.IPV6_NDP_DISCOVERY: {
        StagePreset.FAST: IPv6NDPDiscoveryStageConfig(
            neighbor_table_config=NeighborTableConfig(refresh_interval=1.0, command_timeout=3.0),
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: IPv6NDPDiscoveryStageConfig(),
        StagePreset.ACCURATE: IPv6NDPDiscoveryStageConfig(
            neighbor_table_config=NeighborTableConfig(refresh_interval=3.0, command_timeout=8.0),
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.IPV6_MDNS_DISCOVERY: {
        StagePreset.FAST: IPv6MDNSDiscoveryStageConfig(
            timeout=2.0,
            hostname_config=HostnameConfig(retries=0, retry_delay=0),
        ),
        StagePreset.BALANCED: IPv6MDNSDiscoveryStageConfig(),
        StagePreset.ACCURATE: IPv6MDNSDiscoveryStageConfig(
            timeout=10.0,
            hostname_config=HostnameConfig(retries=2, retry_delay=2.0),
        ),
    },

    StageType.PORT_SCAN: {
        StagePreset.FAST: PortScanStageConfig(
            port_list="small",
            port_scan_config=PortScanConfig(timeout=0.5, retries=0, retry_delay=0),
            service_scan_config=ServiceScanConfig(
                timeout=3.0,
                lookup_type=ServiceScanStrategy.LAZY,
            ),
        ),
        StagePreset.BALANCED: PortScanStageConfig(),
        StagePreset.ACCURATE: PortScanStageConfig(
            port_list="large",
            port_scan_config=PortScanConfig(timeout=2.0, retries=1, retry_delay=0.3),
            service_scan_config=ServiceScanConfig(
                timeout=8.0,
                lookup_type=ServiceScanStrategy.AGGRESSIVE,
                max_concurrent_probes=15,
            ),
        ),
    },
}


def get_stage_presets() -> Dict[str, Dict[str, dict]]:
    """Return all presets for every stage type as serialized dicts.

    Returns:
        ``{stage_type_value: {preset_name: config_dict, ...}, ...}``

    Example::

        >>> presets = get_stage_presets()
        >>> presets["icmp_discovery"]["fast"]
        {'ping_config': {'attempts': 1, ...}, ...}
    """
    result: Dict[str, Dict[str, dict]] = {}
    for stage_type, preset_map in _PRESETS.items():
        result[stage_type.value] = {
            preset.value: cfg.to_dict()
            for preset, cfg in preset_map.items()
        }
    return result
