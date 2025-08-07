from typing import List, Dict
import ipaddress
from pydantic import BaseModel, Field
from enum import Enum


from lanscape.libraries.port_manager import PortManager
from lanscape.libraries.ip_parser import parse_ip_input


class PingConfig(BaseModel):
    attempts: int = 2
    ping_count: int = 1
    timeout: float = 1.0
    retry_delay: float = 0.25

    @classmethod
    def from_dict(cls, data: dict) -> 'PingConfig':
        return cls.model_validate(data)

    def to_dict(self) -> dict:
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
        return cls.model_validate(data)

    def to_dict(self) -> dict:
        return self.model_dump()

    def __str__(self):
        return f'ArpCfg(timeout={self.timeout}, attempts={self.attempts})'


class ScanType(Enum):
    PING = 'ping'
    ARP = 'arp'
    BOTH = 'both'


class ScanConfig(BaseModel):
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

    def t_cnt(self, id: str) -> int:
        return int(int(getattr(self, f't_cnt_{id}')) * float(self.t_multiplier))

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanConfig':
        # Handle special cases before validation
        if isinstance(data.get('lookup_type'), str):
            data['lookup_type'] = ScanType[data['lookup_type'].upper()]

        return cls.model_validate(data)

    def to_dict(self) -> dict:
        dump = self.model_dump()
        dump['lookup_type'] = self.lookup_type.value
        return dump

    def get_ports(self) -> List[int]:
        return PortManager().get_port_list(self.port_list).keys()

    def parse_subnet(self) -> List[ipaddress.IPv4Network]:
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
