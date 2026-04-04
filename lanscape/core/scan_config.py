"""Configuration module for network scanning operations."""

import os
from typing import List, Dict, Optional, Any
from enum import Enum

from pydantic import BaseModel, Field

from lanscape.core.port_manager import PortManager
from lanscape.core.ip_parser import parse_ip_input, IPAddress
from lanscape.core.models.enums import StageType


class ConfigBase(BaseModel):
    """Base class for all scan configuration models.

    Provides ``from_dict`` / ``to_dict`` so subclasses don't need to
    repeat the same one-liner wrappers around Pydantic.
    """

    @classmethod
    def from_dict(cls, data: dict):
        """Create an instance from a dictionary."""
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        """Serialise to a plain dictionary."""
        return self.model_dump()


class PingConfig(ConfigBase):
    """Configuration for ICMP ping scanning."""
    attempts: int = 2
    ping_count: int = 1
    timeout: float = 1.0
    retry_delay: float = 0.25

    def __str__(self):
        return (
            f"PingCfg(attempts={self.attempts}, "
            f"ping_count={self.ping_count}, "
            f"timeout={self.timeout}, "
            f"retry_delay={self.retry_delay})"
        )


class ArpConfig(ConfigBase):
    """Configuration for ARP scanning."""
    attempts: int = 1
    timeout: float = 2.0

    def __str__(self):
        return f'ArpCfg(timeout={self.timeout}, attempts={self.attempts})'


class ArpCacheConfig(ConfigBase):
    """Configuration for ARP cache lookups."""
    attempts: int = 1
    wait_before: float = 0.2

    def __str__(self):
        return f'ArpCacheCfg(wait_before={self.wait_before}, attempts={self.attempts})'


class PokeConfig(ConfigBase):
    """Configuration for TCP poke (triggers ARP cache population)."""
    attempts: int = 1
    timeout: float = 2.0


class HostnameConfig(ConfigBase):
    """Configuration for hostname resolution retries."""
    retries: int = Field(default=1, ge=0)
    retry_delay: float = Field(default=1.5, ge=0)

    def __str__(self):
        return f'HostnameCfg(retries={self.retries}, retry_delay={self.retry_delay})'


class NeighborTableConfig(ConfigBase):
    """Configuration for the background neighbor table refresh service."""
    refresh_interval: float = 2.0
    command_timeout: float = 5.0


class ServiceScanStrategy(Enum):
    """
    Enumeration of strategies for service scanning on open ports.

    LAZY: Several common probes to see if we can identify the service.
    BASIC: Common probes plus probes correlated to the port number.
    AGGRESSIVE: All known probes in parallel to try to elicit a response.
    """
    LAZY = 'LAZY'
    BASIC = 'BASIC'
    AGGRESSIVE = 'AGGRESSIVE'


class ServiceScanConfig(ConfigBase):
    """Configuration for service scanning on open ports."""
    timeout: float = 5.0
    lookup_type: ServiceScanStrategy = ServiceScanStrategy.BASIC
    max_concurrent_probes: int = 10

    def __str__(self):
        return f'ServiceScanCfg(timeout={self.timeout})'


class PortScanConfig(ConfigBase):
    """Configuration for port scanning."""
    timeout: float = 1.0
    retries: int = 0
    retry_delay: float = 0.1

    def __str__(self):
        return f'PortScanCfg(timeout={self.timeout}, retry_delay={self.retry_delay})'


class ScanType(Enum):
    """
    Enumeration of supported network scan types.

    PING: Uses ICMP echo requests to determine if hosts are alive
    ARP: Uses Address Resolution Protocol to discover hosts on the local network

    """
    ICMP = 'ICMP'
    ARP_LOOKUP = 'ARP_LOOKUP'
    POKE_THEN_ARP = 'POKE_THEN_ARP'
    ICMP_THEN_ARP = 'ICMP_THEN_ARP'


class ScanConfig(ConfigBase):
    """Main configuration for a network scan operation."""
    subnet: str
    port_list: str
    t_multiplier: float = 1.0
    t_cnt_port_scan: int = os.cpu_count() or 4
    t_cnt_port_test: int = (os.cpu_count() or 4) * 4
    t_cnt_isalive: int = (os.cpu_count() or 4) * 6

    task_scan_ports: bool = True
    # below wont run if above false
    task_scan_port_services: bool = True

    lookup_type: List[ScanType] = [ScanType.ICMP_THEN_ARP]

    # Retry and resilience settings
    failure_retry_cnt: int = 2
    failure_multiplier_decrease: float = 0.25
    failure_debounce_sec: float = 5.0

    ping_config: PingConfig = Field(default_factory=PingConfig)
    arp_config: ArpConfig = Field(default_factory=ArpConfig)
    poke_config: PokeConfig = Field(default_factory=PokeConfig)
    arp_cache_config: ArpCacheConfig = Field(default_factory=ArpCacheConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    neighbor_table_config: 'NeighborTableConfig' = Field(default_factory=NeighborTableConfig)
    port_scan_config: PortScanConfig = Field(default_factory=PortScanConfig)
    service_scan_config: ServiceScanConfig = Field(default_factory=ServiceScanConfig)

    def t_cnt(self, thread_id: str) -> int:
        """
        Calculate thread count for a specific operation based on multiplier.

        Args:
            thread_id: String identifier for the thread type (e.g., 'port_scan')

        Returns:
            Calculated thread count for the specified operation
        """
        return int(int(getattr(self, f't_cnt_{thread_id}')) * float(self.t_multiplier))

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanConfig':
        """Create a ScanConfig from a dictionary."""
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary."""
        return self.model_dump(mode="json")

    def get_ports(self) -> List[int]:
        """
        Get the list of ports to scan based on the configured port list name.

        Returns:
            List of port numbers to scan
        """
        return [int(p) for p in PortManager().get_port_list(self.port_list).keys()]

    def parse_subnet(self) -> List['IPAddress']:
        """
        Parse the configured subnet string into IP address objects.

        Returns:
            List of IPv4Address / IPv6Address objects representing the target IPs
        """
        return parse_ip_input(self.subnet)

    def __str__(self):
        a = f'subnet={self.subnet}'
        b = f'ports={self.port_list}'
        c = f'scan_type={[st.value for st in self.lookup_type]}'
        return f'ScanConfig({a}, {b}, {c})'

    def to_pipeline_config(self) -> 'PipelineConfig':
        """Convert this legacy ScanConfig into a PipelineConfig.

        Maps each ``lookup_type`` entry to a discovery stage, then optionally
        appends a port-scan stage.
        """
        stages: List[StageConfig] = []

        scan_type_map = {
            ScanType.ICMP: StageType.ICMP_DISCOVERY,
            ScanType.ARP_LOOKUP: StageType.ARP_DISCOVERY,
            ScanType.POKE_THEN_ARP: StageType.POKE_ARP_DISCOVERY,
            ScanType.ICMP_THEN_ARP: StageType.ICMP_ARP_DISCOVERY,
        }

        for lt in self.lookup_type:
            stage_type = scan_type_map.get(lt)
            if stage_type is None:
                continue

            if stage_type == StageType.ICMP_DISCOVERY:
                cfg = ICMPDiscoveryStageConfig(
                    ping_config=self.ping_config,
                    hostname_config=self.hostname_config,
                    t_cnt=self.t_cnt_isalive,
                )
            elif stage_type == StageType.ARP_DISCOVERY:
                cfg = ARPDiscoveryStageConfig(
                    arp_config=self.arp_config,
                    hostname_config=self.hostname_config,
                    t_cnt=self.t_cnt_isalive,
                )
            elif stage_type == StageType.POKE_ARP_DISCOVERY:
                cfg = PokeARPDiscoveryStageConfig(
                    poke_config=self.poke_config,
                    arp_cache_config=self.arp_cache_config,
                    hostname_config=self.hostname_config,
                    t_cnt=self.t_cnt_isalive,
                )
            elif stage_type == StageType.ICMP_ARP_DISCOVERY:
                cfg = ICMPARPDiscoveryStageConfig(
                    ping_config=self.ping_config,
                    arp_cache_config=self.arp_cache_config,
                    hostname_config=self.hostname_config,
                    t_cnt=self.t_cnt_isalive,
                )
            else:
                continue

            stages.append(StageConfig(
                stage_type=stage_type,
                config=cfg.to_dict(),
            ))

        if self.task_scan_ports:
            port_cfg = PortScanStageConfig(
                port_list=self.port_list,
                port_scan_config=self.port_scan_config,
                service_scan_config=self.service_scan_config,
                scan_services=self.task_scan_port_services,
                t_cnt_device=self.t_cnt_port_scan,
                t_cnt_port=self.t_cnt_port_test,
            )
            stages.append(StageConfig(
                stage_type=StageType.PORT_SCAN,
                config=port_cfg.to_dict(),
            ))

        return PipelineConfig(
            subnet=self.subnet,
            stages=stages,
            resilience=ResilienceConfig(
                t_multiplier=self.t_multiplier,
                failure_retry_cnt=self.failure_retry_cnt,
                failure_multiplier_decrease=self.failure_multiplier_decrease,
                failure_debounce_sec=self.failure_debounce_sec,
            ),
            hostname_config=self.hostname_config,
        )


# ─── Per-stage configuration models ────────────────────────────────


class ICMPDiscoveryStageConfig(ConfigBase):
    """Config for the ICMP discovery stage."""
    ping_config: PingConfig = Field(default_factory=PingConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    t_cnt: int = (os.cpu_count() or 4) * 6


class ARPDiscoveryStageConfig(ConfigBase):
    """Config for the ARP broadcast discovery stage."""
    arp_config: ArpConfig = Field(default_factory=ArpConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    t_cnt: int = (os.cpu_count() or 4) * 6


class PokeARPDiscoveryStageConfig(ConfigBase):
    """Config for the Poke→ARP cache discovery stage."""
    poke_config: PokeConfig = Field(default_factory=PokeConfig)
    arp_cache_config: ArpCacheConfig = Field(default_factory=ArpCacheConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    t_cnt: int = (os.cpu_count() or 4) * 6


class ICMPARPDiscoveryStageConfig(ConfigBase):
    """Config for the ICMP→ARP cache discovery stage."""
    ping_config: PingConfig = Field(default_factory=PingConfig)
    arp_cache_config: ArpCacheConfig = Field(default_factory=ArpCacheConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    t_cnt: int = (os.cpu_count() or 4) * 6


class IPv6NDPDiscoveryStageConfig(ConfigBase):
    """Config for the IPv6 NDP neighbor discovery stage."""
    neighbor_table_config: NeighborTableConfig = Field(default_factory=NeighborTableConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    t_cnt: int = (os.cpu_count() or 4) * 4
    interface: Optional[str] = None


class IPv6MDNSDiscoveryStageConfig(ConfigBase):
    """Config for the IPv6 mDNS discovery stage."""
    timeout: float = 5.0
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)
    interface: Optional[str] = None


class PortScanStageConfig(ConfigBase):
    """Config for the port scanning stage."""
    port_list: str = "medium"
    port_scan_config: PortScanConfig = Field(default_factory=PortScanConfig)
    service_scan_config: ServiceScanConfig = Field(default_factory=ServiceScanConfig)
    scan_services: bool = True
    t_cnt_device: int = os.cpu_count() or 4
    t_cnt_port: int = (os.cpu_count() or 4) * 4


# ─── Stage config registry ─────────────────────────────────────────

STAGE_CONFIG_REGISTRY: Dict[StageType, type] = {
    StageType.ICMP_DISCOVERY: ICMPDiscoveryStageConfig,
    StageType.ARP_DISCOVERY: ARPDiscoveryStageConfig,
    StageType.POKE_ARP_DISCOVERY: PokeARPDiscoveryStageConfig,
    StageType.ICMP_ARP_DISCOVERY: ICMPARPDiscoveryStageConfig,
    StageType.IPV6_NDP_DISCOVERY: IPv6NDPDiscoveryStageConfig,
    StageType.IPV6_MDNS_DISCOVERY: IPv6MDNSDiscoveryStageConfig,
    StageType.PORT_SCAN: PortScanStageConfig,
}


def parse_stage_config(stage_type: StageType, data: dict) -> ConfigBase:
    """Deserialize a stage config dict to the correct model class."""
    cls = STAGE_CONFIG_REGISTRY.get(stage_type)
    if cls is None:
        raise ValueError(f"Unknown stage type: {stage_type}")
    return cls.model_validate(data)


# ─── Pipeline configuration ────────────────────────────────────────


class ResilienceConfig(ConfigBase):
    """Thread-pool resilience and retry settings shared across stages."""
    t_multiplier: float = 1.0
    failure_retry_cnt: int = 2
    failure_multiplier_decrease: float = 0.25
    failure_debounce_sec: float = 5.0


class StageConfig(ConfigBase):
    """A single stage entry in a pipeline configuration."""
    stage_type: StageType
    config: Dict[str, Any] = Field(default_factory=dict)

    def get_typed_config(self) -> ConfigBase:
        """Return the config dict parsed into its stage-specific model."""
        return parse_stage_config(self.stage_type, self.config)


class PipelineConfig(ConfigBase):
    """Top-level config for a multi-stage scan pipeline.

    Power users can construct this directly to build custom stage
    sequences (e.g. ``[ICMP_DISCOVERY, PORT_SCAN, ARP_DISCOVERY, PORT_SCAN]``).
    Simple users keep using :class:`ScanConfig`, which auto-converts via
    :meth:`ScanConfig.to_pipeline_config`.
    """
    subnet: str
    stages: List[StageConfig] = Field(default_factory=list)
    resilience: ResilienceConfig = Field(default_factory=ResilienceConfig)
    hostname_config: HostnameConfig = Field(default_factory=HostnameConfig)


DEFAULT_CONFIGS: Dict[str, ScanConfig] = {
    'balanced': ScanConfig(subnet='', port_list='medium'),
    'accurate': ScanConfig(
        subnet='',
        port_list='large',
        t_cnt_port_scan=5,
        t_cnt_port_test=64,
        t_cnt_isalive=64,
        task_scan_ports=True,
        task_scan_port_services=True,
        lookup_type=[ScanType.ICMP_THEN_ARP, ScanType.ARP_LOOKUP],
        arp_config=ArpConfig(
            attempts=3,
            timeout=2.5
        ),
        ping_config=PingConfig(
            attempts=3,
            ping_count=2,
            timeout=1.5,
            retry_delay=0.5
        ),
        arp_cache_config=ArpCacheConfig(
            attempts=2,
            wait_before=0.3
        ),
        port_scan_config=PortScanConfig(
            timeout=2.5,
            retries=1,
            retry_delay=0.2
        ),
        service_scan_config=ServiceScanConfig(
            timeout=8.0,
            lookup_type=ServiceScanStrategy.AGGRESSIVE,
            max_concurrent_probes=5
        ),
        hostname_config=HostnameConfig(
            retries=2,
            retry_delay=2.0
        )
    ),
    'fast': ScanConfig(
        subnet='',
        port_list='small',
        t_cnt_port_scan=20,
        t_cnt_port_test=256,
        t_cnt_isalive=512,
        task_scan_ports=True,
        task_scan_port_services=True,
        lookup_type=[ScanType.POKE_THEN_ARP],
        arp_config=ArpConfig(
            attempts=1,
            timeout=1.0
        ),
        ping_config=PingConfig(
            attempts=1,
            ping_count=1,
            timeout=0.5,
            retry_delay=0.25
        ),
        service_scan_config=ServiceScanConfig(
            timeout=2.0,
            lookup_type=ServiceScanStrategy.LAZY,
            max_concurrent_probes=15
        ),
        hostname_config=HostnameConfig(
            retries=0
        )
    )
}


def get_default_configs_with_arp_fallback(arp_supported: bool) -> Dict[str, dict]:
    """
    Get default scan configurations, adjusting for ARP support.

    When ARP lookups are not supported on the host system, adjust any
    presets that rely on ARP_LOOKUP to use the POKE_THEN_ARP fallback.

    Args:
        arp_supported: Whether active ARP scanning is available

    Returns:
        Dict of preset name -> ScanConfig dict
    """
    configs = {}
    for key, config in DEFAULT_CONFIGS.items():
        config_dict = config.to_dict()

        if not arp_supported:
            lookup_types = list(config_dict.get('lookup_type') or [])
            if 'ARP_LOOKUP' in lookup_types:
                lookup_types = [lt for lt in lookup_types if lt != 'ARP_LOOKUP']
                if 'POKE_THEN_ARP' not in lookup_types:
                    lookup_types.append('POKE_THEN_ARP')
                config_dict['lookup_type'] = lookup_types

        configs[key] = config_dict

    return configs


def get_stage_config_defaults() -> Dict[str, dict]:
    """
    Get the default configuration for each stage type.

    Instantiates each stage config class with its Pydantic defaults
    and returns the serialized dict keyed by stage type value.

    Returns:
        Dict of stage_type string -> default config dict
    """
    return {
        stage_type.value: cls().to_dict()
        for stage_type, cls in STAGE_CONFIG_REGISTRY.items()
    }
