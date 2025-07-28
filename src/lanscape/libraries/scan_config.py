from dataclasses import dataclass, field
from typing import List
import ipaddress
from .port_manager import PortManager
from .ip_parser import parse_ip_input
from dataclasses import dataclass, fields
from enum import Enum


@dataclass
class PingConfig:
    attempts: int = 1
    ping_count: int = 2
    timeout: float = 1.0
    retry_delay: float = 0.5

    @staticmethod
    def from_dict(data: dict) -> 'PingConfig':
        # Only use keys that are fields of PingConfig
        init_args = {f.name: data.get(f.name, getattr(PingConfig, f.name)) for f in fields(PingConfig)}
        return PingConfig(**init_args)
    
    def __str__(self):
        return f'PingCfg(attempts={self.attempts}, ping_count={self.ping_count}, timeout={self.timeout}, retry_delay={self.retry_delay})'
    
@dataclass
class ArpConfig:
    """
    Configuration for ARP scanning.
    """
    attempts: int = 1
    timeout: float = 1.0

    @staticmethod
    def from_dict(data: dict) -> 'ArpConfig':
        # Only use keys that are fields of ArpConfig
        init_args = {f.name: data.get(f.name, getattr(ArpConfig, f.name)) for f in fields(ArpConfig)}
        return ArpConfig(**init_args)

    def __str__(self):
        return f'ArpCfg(timeout={self.timeout}, attempts={self.attempts})'
    
class ScanType(Enum):
    PING = 'ping'
    ARP = 'arp'
    BOTH = 'both'

@dataclass
class ScanConfig:
    subnet: str
    port_list: str
    t_multiplier: float = 1.0
    t_cnt_port_scan: int = 10
    t_cnt_port_test: int = 128
    t_cnt_isalive: int = 256

    task_scan_ports: bool = True
    # below wont run if above false
    task_scan_port_services: bool = False # disabling until more stable

    lookup_type: ScanType = ScanType.BOTH

    ping_config: 'PingConfig' = field(default_factory=PingConfig)
    arp_config: 'ArpConfig' = field(default_factory=ArpConfig)

    def t_cnt(self, id: str) -> int:
        return int(int(getattr(self, f't_cnt_{id}')) * float(self.t_multiplier))
    
    @staticmethod
    def from_dict(data: dict) -> 'ScanConfig':
        # Only use keys that are fields of ScanConfig
        init_args = {f.name: data.get(f.name, getattr(ScanConfig, f.name)) for f in fields(ScanConfig)}
        # Convert ping_config and arp_config if they are dicts
        if isinstance(init_args.get('ping_config'), dict):
            init_args['ping_config'] = PingConfig.from_dict(init_args['ping_config'])
        if isinstance(init_args.get('arp_config'), dict):
            init_args['arp_config'] = ArpConfig.from_dict(init_args['arp_config'])
        # Convert lookup_type to ScanType enum
        if isinstance(init_args.get('lookup_type'), str):
            init_args['lookup_type'] = ScanType[init_args['lookup_type'].lower()]
        
        return ScanConfig(**init_args)

    def get_ports(self) -> List[int]:
        return PortManager().get_port_list(self.port_list).keys()
    
    def parse_subnet(self) -> List[ipaddress.IPv4Network]:
        return parse_ip_input(self.subnet)
    
    def __str__(self):
        return f'ScanCfg(subnet={self.subnet}, ports={self.port_list}, multiplier={self.t_multiplier})'


