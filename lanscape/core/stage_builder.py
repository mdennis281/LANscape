"""Factory for building stage instances from pipeline configuration."""

from typing import List

from lanscape.core.scan_config import PipelineConfig
from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.models.enums import StageType
from lanscape.core.ip_parser import parse_ip_input


def build_stages(pipeline_cfg: PipelineConfig) -> List[ScanStageMixin]:
    """Instantiate concrete stage objects from a :class:`PipelineConfig`.

    Discovery stages receive the parsed subnet IPs; port scan and IPv6
    stages are constructed from their typed config alone.
    """
    from lanscape.core.stages.discovery import (  # pylint: disable=import-outside-toplevel
        ICMPDiscoveryStage,
        ARPDiscoveryStage,
        PokeARPDiscoveryStage,
        ICMPARPDiscoveryStage,
    )
    from lanscape.core.stages.ipv6_discovery import (  # pylint: disable=import-outside-toplevel
        IPv6NDPDiscoveryStage,
        IPv6MDNSDiscoveryStage,
    )
    from lanscape.core.stages.port_scan import PortScanStage  # pylint: disable=import-outside-toplevel

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

    return stages
