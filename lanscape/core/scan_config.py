"""Configuration module for network scanning operations."""

import os
from typing import List, Dict
from enum import Enum

from pydantic import BaseModel, Field

from lanscape.core.port_manager import PortManager
from lanscape.core.ip_parser import parse_ip_input


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
        return PortManager().get_port_list(self.port_list).keys()

    def parse_subnet(self) -> list:
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
