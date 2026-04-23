"""Per-stage time estimation for a single unit of work.

Each discovery stage returns the worst-case seconds to probe **one IP**
(without hostname resolution, since ~90 % of IPs won't be alive).

The port-scan stage returns the worst-case seconds to scan **one device**
given the configured port list, thread count, and service-scan settings.

The frontend multiplies these values by subnet size / thread count to
derive the total estimated scan time.
"""

import math
from typing import Dict

from lanscape.core.models.enums import StageType
from lanscape.core.port_manager import PortManager
from lanscape.core.scan_config import (
    STAGE_CONFIG_REGISTRY,
    ICMPDiscoveryStageConfig,
    ARPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
    ICMPARPDiscoveryStageConfig,
    IPv6NDPDiscoveryStageConfig,
    IPv6MDNSDiscoveryStageConfig,
    PortScanStageConfig,
)


def _icmp_estimate(cfg: ICMPDiscoveryStageConfig) -> float:
    """Worst-case per-IP: all attempts timeout with retry delays."""
    pc = cfg.ping_config
    return pc.attempts * (pc.timeout + pc.retry_delay)


def _arp_estimate(cfg: ARPDiscoveryStageConfig) -> float:
    """Worst-case per-IP: all ARP attempts timeout."""
    ac = cfg.arp_config
    return ac.attempts * ac.timeout


def _poke_arp_estimate(cfg: PokeARPDiscoveryStageConfig) -> float:
    """Worst-case per-IP: poke timeout + ARP cache wait."""
    pc = cfg.poke_config
    cc = cfg.arp_cache_config
    return (pc.attempts * pc.timeout) + cc.wait_before


def _icmp_arp_estimate(cfg: ICMPARPDiscoveryStageConfig) -> float:
    """Worst-case per-IP: ICMP timeout + ARP cache lookup is negligible."""
    pc = cfg.ping_config
    return pc.attempts * (pc.timeout + pc.retry_delay)


def _ipv6_ndp_estimate(cfg: IPv6NDPDiscoveryStageConfig) -> float:
    """Fixed cost: multicast ping (~10 s) + neighbor table refresh."""
    return 10.0 + cfg.neighbor_table_config.refresh_interval


def _ipv6_mdns_estimate(cfg: IPv6MDNSDiscoveryStageConfig) -> float:
    """Fixed cost: mDNS browse runs for exactly `timeout` seconds."""
    return cfg.timeout


def _port_scan_estimate(cfg: PortScanStageConfig) -> float:
    """Worst-case per-device: all ports timeout, batched by thread count."""
    try:
        port_count = len(PortManager().get_port_list(cfg.port_list))
    except Exception:  # pylint: disable=broad-except
        port_count = 148  # fallback to medium list size

    psc = cfg.port_scan_config
    per_port = psc.timeout * (1 + psc.retries) + psc.retry_delay * psc.retries

    if cfg.scan_services:
        ssc = cfg.service_scan_config
        per_port += ssc.timeout

    batches = math.ceil(port_count / max(1, cfg.t_cnt_port))
    return batches * per_port


_ESTIMATORS = {
    StageType.ICMP_DISCOVERY: _icmp_estimate,
    StageType.ARP_DISCOVERY: _arp_estimate,
    StageType.POKE_ARP_DISCOVERY: _poke_arp_estimate,
    StageType.ICMP_ARP_DISCOVERY: _icmp_arp_estimate,
    StageType.IPV6_NDP_DISCOVERY: _ipv6_ndp_estimate,
    StageType.IPV6_MDNS_DISCOVERY: _ipv6_mdns_estimate,
    StageType.PORT_SCAN: _port_scan_estimate,
}


def estimate_stage_time(stage_type: StageType, config: dict) -> float:
    """Return estimated seconds for one unit of work.

    For IPv4 discovery stages this is one IP.
    For IPv6 stages this is the fixed overhead.
    For port scan this is one device.

    Parameters
    ----------
    stage_type:
        The stage to estimate.
    config:
        The stage config dict (will be parsed to the matching Pydantic model).

    Returns
    -------
    float
        Estimated seconds (worst-case).
    """
    cfg_cls = STAGE_CONFIG_REGISTRY[stage_type]
    cfg = cfg_cls.model_validate(config)
    estimator = _ESTIMATORS[stage_type]
    return round(estimator(cfg), 2)


def get_all_estimates(
    stages: Dict[str, dict],
) -> Dict[str, float]:
    """Return estimates for multiple stages at once.

    Parameters
    ----------
    stages:
        Mapping of ``stage_type`` string → config dict.

    Returns
    -------
    dict
        ``stage_type`` string → estimated seconds.
    """
    result: Dict[str, float] = {}
    for stage_key, config in stages.items():
        st = StageType(stage_key)
        result[stage_key] = estimate_stage_time(st, config)
    return result
