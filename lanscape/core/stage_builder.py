"""Factory for building stage instances from pipeline configuration."""

from typing import List

from lanscape.core.scan_config import PipelineConfig
from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.models.enums import StageType
from lanscape.core.ip_parser import parse_ip_input, get_address_count
from lanscape.core.stages.discovery import (
    ICMPDiscoveryStage,
    ARPDiscoveryStage,
    PokeARPDiscoveryStage,
    ICMPARPDiscoveryStage,
)
from lanscape.core.stages.ipv6_discovery import (
    IPv6NDPDiscoveryStage,
    IPv6MDNSDiscoveryStage,
)
from lanscape.core.stages.port_scan import PortScanStage

# Stage types that enumerate the subnet IP list (IPv4 only)
_IPV4_ENUM_STAGES = {
    StageType.ICMP_DISCOVERY,
    StageType.ARP_DISCOVERY,
    StageType.POKE_ARP_DISCOVERY,
    StageType.ICMP_ARP_DISCOVERY,
}


def build_stages(pipeline_cfg: PipelineConfig) -> List[ScanStageMixin]:
    """Instantiate concrete stage objects from a :class:`PipelineConfig`.

    Discovery stages receive the parsed subnet IPs; port scan and IPv6
    stages are constructed from their typed config alone.

    Raises:
        ValueError: If a stage's MAX_SUBNET_SIZE constraint is exceeded.
    """
    needs_enum = any(s.stage_type in _IPV4_ENUM_STAGES for s in pipeline_cfg.stages)

    subnet_ips: List = []
    if needs_enum:
        address_cnt = get_address_count(pipeline_cfg.subnet)
        # Validate per-stage size constraints before allocating the IP list
        for stage_cfg in pipeline_cfg.stages:
            if stage_cfg.stage_type not in _IPV4_ENUM_STAGES:
                continue
            typed_cfg = stage_cfg.get_typed_config()
            max_size = getattr(type(typed_cfg), 'MAX_SUBNET_SIZE', None)
            if max_size is not None and address_cnt > max_size:
                raise ValueError(
                    f"Stage '{stage_cfg.stage_type.value}' supports a maximum of "
                    f"{max_size:,} IPs, but subnet has {address_cnt:,} IPs."
                )
        subnet_ips = parse_ip_input(pipeline_cfg.subnet)

    resilience = pipeline_cfg.resilience

    stages: List[ScanStageMixin] = []

    for stage_cfg in pipeline_cfg.stages:
        typed_cfg = stage_cfg.get_typed_config()
        st = stage_cfg.stage_type

        if st == StageType.ICMP_DISCOVERY:
            stages.append(ICMPDiscoveryStage(typed_cfg, subnet_ips, resilience=resilience))
        elif st == StageType.ARP_DISCOVERY:
            stages.append(ARPDiscoveryStage(typed_cfg, subnet_ips, resilience=resilience))
        elif st == StageType.POKE_ARP_DISCOVERY:
            stages.append(PokeARPDiscoveryStage(typed_cfg, subnet_ips, resilience=resilience))
        elif st == StageType.ICMP_ARP_DISCOVERY:
            stages.append(ICMPARPDiscoveryStage(typed_cfg, subnet_ips, resilience=resilience))
        elif st == StageType.IPV6_NDP_DISCOVERY:
            stages.append(IPv6NDPDiscoveryStage(
                typed_cfg, subnet_hint=pipeline_cfg.subnet,
            ))
        elif st == StageType.IPV6_MDNS_DISCOVERY:
            stages.append(IPv6MDNSDiscoveryStage(typed_cfg))
        elif st == StageType.PORT_SCAN:
            stages.append(PortScanStage(typed_cfg, resilience=resilience))

        # Propagate auto-stage metadata to the stage instance
        if stages:
            stages[-1].auto = stage_cfg.auto
            stages[-1].reason = stage_cfg.reason

    return stages
