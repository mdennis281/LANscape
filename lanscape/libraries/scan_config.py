"""
Configuration module for network scanning operations.
Provides classes and utilities to configure different types of network scans
including ping scans, ARP scans, and port scanning.
"""

from typing import List, Dict
import ipaddress
from enum import Enum

from pydantic import BaseModel, Field

from lanscape.libraries.port_manager import PortManager
from lanscape.libraries.ip_parser import parse_ip_input


class PingConfig(BaseModel):
    """
    Configuration settings for ICMP ping-based network scanning.

    Controls parameters such as the number of ping attempts, count per ping,
    timeout values, and retry delays to optimize ping scanning behavior.
    """
    attempts: int = 2
    ping_count: int = 1
    timeout: float = 1.0
    retry_delay: float = 0.25

    @classmethod
    def from_dict(cls, data: dict) -> 'PingConfig':
        """
        Create a PingConfig instance from a dictionary.

        Args:
            data: Dictionary containing PingConfig parameters

        Returns:
            A new PingConfig instance with the provided settings
        """
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        """
        Convert the PingConfig instance to a dictionary.

        Returns:
            Dictionary representation of the PingConfig
        """
        return self.model_dump()

    def __str__(self):
        return (
            f"PingCfg(attempts={self.attempts}, "
            f"ping_count={self.ping_count}, "
            f"timeout={self.timeout}, "
            f"retry_delay={self.retry_delay})"
        )


class ArpConfig(BaseModel):
    """
    Configuration for ARP scanning.
    """
    attempts: int = 1
    timeout: float = 2.0

    @classmethod
    def from_dict(cls, data: dict) -> 'ArpConfig':
        """
        Create an ArpConfig instance from a dictionary.

        Args:
            data: Dictionary containing ArpConfig parameters

        Returns:
            A new ArpConfig instance with the provided settings
        """
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        """
        Convert the ArpConfig instance to a dictionary.

        Returns:
            Dictionary representation of the ArpConfig
        """
        return self.model_dump()

    def __str__(self):
        return f'ArpCfg(timeout={self.timeout}, attempts={self.attempts})'


class ScanType(Enum):
    """
    Enumeration of supported network scan types.

    PING: Uses ICMP echo requests to determine if hosts are alive
    ARP: Uses Address Resolution Protocol to discover hosts on the local network
    BOTH: Uses both PING and ARP methods for maximum coverage
    """
    PING = 'ping'
    ARP = 'arp'
    BOTH = 'both'


class ScanConfig(BaseModel):
    """
    Main configuration class for network scanning operations.

    Contains settings for subnet targets, port ranges, thread counts,
    scan tasks to perform, and configurations for different scan methods.
    """
    subnet: str
    port_list: str
    t_multiplier: float = 1.0
    t_cnt_port_scan: int = 10
    t_cnt_port_test: int = 128
    t_cnt_isalive: int = 256

    task_scan_ports: bool = True
    # below wont run if above false
    task_scan_port_services: bool = False  # disabling until more stable

    lookup_type: ScanType = ScanType.BOTH

    ping_config: PingConfig = Field(default_factory=PingConfig)
    arp_config: ArpConfig = Field(default_factory=ArpConfig)

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
        """
        Create a ScanConfig instance from a dictionary.

        Handles special cases like converting string enum values to proper Enum types.

        Args:
            data: Dictionary containing ScanConfig parameters

        Returns:
            A new ScanConfig instance with the provided settings
        """
        # Handle special cases before validation
        if isinstance(data.get('lookup_type'), str):
            data['lookup_type'] = ScanType[data['lookup_type'].upper()]

        return cls.model_validate(data)

    def to_dict(self) -> dict:
        """
        Convert the ScanConfig instance to a dictionary.

        Handles special cases like converting Enum values to strings.

        Returns:
            Dictionary representation of the ScanConfig
        """
        dump = self.model_dump()
        dump['lookup_type'] = self.lookup_type.value
        return dump

    def get_ports(self) -> List[int]:
        """
        Get the list of ports to scan based on the configured port list name.

        Returns:
            List of port numbers to scan
        """
        return PortManager().get_port_list(self.port_list).keys()

    def parse_subnet(self) -> List[ipaddress.IPv4Network]:
        """
        Parse the configured subnet string into IPv4Network objects.

        Returns:
            List of IPv4Network objects representing the target networks
        """
        return parse_ip_input(self.subnet)

    def __str__(self):
        a = f'subnet={self.subnet}'
        b = f'ports={self.port_list}'
        c = f'scan_type={self.lookup_type.value}'
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
        task_scan_port_services=False,
        lookup_type=ScanType.BOTH,
        arp_config=ArpConfig(
            attempts=3,
            timeout=2.5
        ),
        ping_config=PingConfig(
            attempts=3,
            ping_count=2,
            timeout=1.5,
            retry_delay=0.5
        )
    ),
    'fast': ScanConfig(
        subnet='',
        port_list='small',
        t_cnt_port_scan=20,
        t_cnt_port_test=256,
        t_cnt_isalive=512,
        task_scan_ports=True,
        task_scan_port_services=False,
        lookup_type=ScanType.BOTH,
        arp_config=ArpConfig(
            attempts=1,
            timeout=1.0
        ),
        ping_config=PingConfig(
            attempts=1,
            ping_count=1,
            timeout=0.5,
            retry_delay=0.25
        )
    )
}
