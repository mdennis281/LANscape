"""
Auto-stage recommendation engine.

Recommends scan stages based on subnet characteristics (size, IPv4/IPv6,
local vs remote), system capabilities (ARP support, OS), and interface context.
"""

from typing import List, Optional

from lanscape.core.models.enums import StageType
from lanscape.core.stage_presets import StagePreset, get_stage_presets
from lanscape.core.net_tools.subnet_utils import (
    is_ipv6_subnet as _is_ipv6,
    is_local_subnet as _is_local_subnet,
    matching_interface as _matching_interface,
    get_os_platform as _get_os_platform,
)
from lanscape.core.ip_parser import get_address_count
from lanscape.core.scan_config import (
    ICMPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
)


# Threshold for "small" vs "large" preset selection
_LARGE_SUBNET_THRESHOLD = 1000
# Per-stage max subnet sizes (mirrors ClassVar constants on config classes)
_ICMP_MAX = ICMPDiscoveryStageConfig.MAX_SUBNET_SIZE    # 25_000
_POKE_ARP_MAX = PokeARPDiscoveryStageConfig.MAX_SUBNET_SIZE  # 64_000


class StageRecommendation:
    """A single recommended stage with its config and reasoning."""

    def __init__(
        self,
        stage_type: StageType,
        preset: StagePreset,
        reason: str,
    ):
        self.stage_type = stage_type
        self.preset = preset
        self.reason = reason

    def to_dict(self) -> dict:
        """Serialize to a dict suitable for JSON/WS responses."""
        presets = get_stage_presets()
        config = presets.get(self.stage_type.value, {}).get(self.preset.value, {})
        return {
            'stage_type': self.stage_type.value,
            'preset': self.preset.value,
            'config': config,
            'reason': self.reason,
        }


def recommend_stages(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    subnet: str,
    ip_count: Optional[int] = None,
    is_ipv6: Optional[bool] = None,
    is_local: Optional[bool] = None,
    arp_supported: bool = True,
    os_platform: Optional[str] = None,
) -> List[StageRecommendation]:
    """Return a list of recommended scan stages for the given subnet context.

    Args:
        subnet: The target subnet string (e.g. ``"192.168.1.0/24"``).
        ip_count: Number of IPs in the subnet.  Computed from *subnet* if ``None``.
        is_ipv6: Whether the subnet is IPv6.  Detected from *subnet* if ``None``.
        is_local: Whether the subnet overlaps a local interface.  Detected if ``None``.
        arp_supported: Whether the system supports ARP (from ``is_arp_supported``).
        os_platform: ``'windows'``, ``'linux'``, or ``'darwin'``.  Detected if ``None``.

    Returns:
        Ordered list of :class:`StageRecommendation` objects.
    """
    # ── Resolve optional parameters ──────────────────────────────────
    if is_ipv6 is None:
        is_ipv6 = _is_ipv6(subnet)

    if ip_count is None:
        try:
            ip_count = get_address_count(subnet)
        except Exception:  # noqa: BLE001
            ip_count = 0

    if is_local is None:
        is_local = _is_local_subnet(subnet)

    if os_platform is None:
        os_platform = _get_os_platform()

    os_platform = os_platform.lower()
    is_large = ip_count >= _LARGE_SUBNET_THRESHOLD

    stages: List[StageRecommendation] = []

    # ── IPv6 ─────────────────────────────────────────────────────────
    if is_ipv6:
        stages.append(StageRecommendation(
            StageType.IPV6_NDP_DISCOVERY,
            StagePreset.BALANCED,
            'IPv6 subnet — NDP discovers link-local neighbors',
        ))
        stages.append(StageRecommendation(
            StageType.IPV6_MDNS_DISCOVERY,
            StagePreset.BALANCED,
            'IPv6 subnet — mDNS finds service-announcing hosts',
        ))
        stages.append(StageRecommendation(
            StageType.PORT_SCAN,
            StagePreset.BALANCED,
            'Port scan on discovered IPv6 hosts',
        ))
        return stages

    # ── IPv4 — local + ARP supported ────────────────────────────────
    if is_local and arp_supported:
        if os_platform == 'windows':
            if ip_count > _POKE_ARP_MAX:
                # No IPv4 discovery stage supports subnets this large
                return []
            if ip_count > _ICMP_MAX:
                # Too large for ICMP, but poke+ARP can handle it on Windows
                stages.append(StageRecommendation(
                    StageType.POKE_ARP_DISCOVERY,
                    StagePreset.FAST,
                    f'Large local subnet on Windows ({ip_count:,} IPs) — Poke+ARP scales, exceeds ICMP limit',
                ))
            elif is_large:
                # Large but within ICMP range: poke+ARP still faster on Windows
                stages.append(StageRecommendation(
                    StageType.POKE_ARP_DISCOVERY,
                    StagePreset.FAST,
                    'Large local subnet on Windows — Poke+ARP scales, skips ICMP wait',
                ))
            else:
                # Small subnet: ICMP+ARP is reliable
                stages.append(StageRecommendation(
                    StageType.ICMP_ARP_DISCOVERY,
                    StagePreset.BALANCED,
                    'Small local subnet on Windows — ICMP+ARP is reliable',
                ))
        else:
            # Linux / macOS — poke+ARP is unreliable, ICMP only
            if ip_count > _ICMP_MAX:
                # No viable discovery stage for this subnet size on Linux/Mac
                return []
            if is_large:
                stages.append(StageRecommendation(
                    StageType.ICMP_DISCOVERY,
                    StagePreset.FAST,
                    'Large local subnet on Linux/Mac — lightweight ICMP (poke unreliable)',
                ))
            else:
                # ICMP+ARP works well for smaller subnets
                stages.append(StageRecommendation(
                    StageType.ICMP_ARP_DISCOVERY,
                    StagePreset.BALANCED,
                    'Small local subnet on Linux/Mac — ICMP+ARP is reliable',
                ))

        # Always add port scan after discovery
        preset = StagePreset.FAST if is_large else StagePreset.BALANCED
        stages.append(StageRecommendation(
            StageType.PORT_SCAN,
            preset,
            f'Port scan ({"fast" if is_large else "balanced"} — {ip_count} IPs)',
        ))
        return stages

    # ── IPv4 — non-local or ARP not supported ───────────────────────
    if ip_count > _ICMP_MAX:
        # No viable discovery stage for this subnet size
        return []

    preset = StagePreset.FAST if is_large else StagePreset.BALANCED
    reason = 'Non-local subnet — ARP not usable across L2 boundary' if not is_local \
        else 'ARP not supported on this system — falling back to ICMP'

    stages.append(StageRecommendation(
        StageType.ICMP_DISCOVERY,
        preset,
        reason,
    ))
    stages.append(StageRecommendation(
        StageType.PORT_SCAN,
        preset,
        f'Port scan ({"fast" if is_large else "balanced"} — {ip_count} IPs)',
    ))
    return stages
