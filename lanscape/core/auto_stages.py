"""
Auto-stage recommendation engine.

Recommends scan stages based on subnet characteristics (size, IPv4/IPv6,
local vs remote), system capabilities (ARP support, OS), and interface context.
"""

import ipaddress
from typing import List, Optional

import psutil

from lanscape.core.models.enums import StageType
from lanscape.core.stage_presets import StagePreset, get_stage_presets
from lanscape.core.net_tools.subnet_utils import get_all_network_subnets
from lanscape.core.ip_parser import get_address_count


# Threshold for "small" vs "large" subnets
_LARGE_SUBNET_THRESHOLD = 1000


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


def _is_ipv6(subnet: str) -> bool:
    """Return True if *subnet* is an IPv6 network."""
    try:
        return isinstance(
            ipaddress.ip_network(subnet, strict=False),
            ipaddress.IPv6Network,
        )
    except ValueError:
        return False


def _is_local_subnet(subnet: str) -> bool:
    """Return True if *subnet* overlaps with any interface on this machine."""
    try:
        target = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False

    for entry in get_all_network_subnets():
        try:
            iface_net = ipaddress.ip_network(entry['subnet'], strict=False)
            if target.overlaps(iface_net):
                return True
        except ValueError:
            continue
    return False


def _matching_interface(subnet: str) -> Optional[str]:
    """Return the name of the first interface whose subnet overlaps *subnet*."""
    try:
        target = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None

    for entry in get_all_network_subnets():
        try:
            iface_net = ipaddress.ip_network(entry['subnet'], strict=False)
            if target.overlaps(iface_net):
                return entry.get('interface')
        except ValueError:
            continue
    return None


def _get_os_platform() -> str:
    """Return a normalised OS identifier: 'windows', 'linux', or 'darwin'."""
    if psutil.WINDOWS:
        return 'windows'
    if psutil.LINUX:
        return 'linux'
    return 'darwin'


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
            if is_large:
                # Windows, large subnet: poke+ARP scales well
                stages.append(StageRecommendation(
                    StageType.POKE_ARP_DISCOVERY,
                    StagePreset.FAST,
                    'Large local subnet on Windows — Poke+ARP scales, skips ICMP wait',
                ))
            else:
                # Windows, small subnet: ICMP+ARP is reliable
                stages.append(StageRecommendation(
                    StageType.ICMP_ARP_DISCOVERY,
                    StagePreset.BALANCED,
                    'Small local subnet on Windows — ICMP+ARP is reliable',
                ))
        else:
            # Linux / macOS
            if is_large:
                # poke+ARP is unreliable on Linux/Mac — use plain ICMP
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
