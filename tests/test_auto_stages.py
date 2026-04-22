"""Tests for the auto-stage recommendation engine."""

from unittest.mock import patch

from lanscape.core.auto_stages import (
    recommend_stages,
    StageRecommendation,
    _is_ipv6,
    _LARGE_SUBNET_THRESHOLD,
)
from lanscape.core.models.enums import StageType
from lanscape.core.stage_presets import StagePreset, get_stage_presets


# ── Helper ───────────────────────────────────────────────────────────

def _stage_types(recs: list[StageRecommendation]) -> list[str]:
    """Extract stage_type values from a list of recommendations."""
    return [r.stage_type.value for r in recs]


def _presets(recs: list[StageRecommendation]) -> list[str]:
    """Extract preset values from a list of recommendations."""
    return [r.preset.value for r in recs]


# ── _is_ipv6 ─────────────────────────────────────────────────────────

class TestIsIpv6:
    """Tests for the _is_ipv6 helper."""

    def test_ipv4_cidr(self) -> None:
        """IPv4 CIDR is not IPv6."""
        assert _is_ipv6('192.168.1.0/24') is False

    def test_ipv6_cidr(self) -> None:
        """IPv6 CIDR is IPv6."""
        assert _is_ipv6('2001:db8::/32') is True

    def test_invalid(self) -> None:
        """Invalid input returns False."""
        assert _is_ipv6('not-a-subnet') is False

    def test_ipv6_range(self) -> None:
        """IPv6 range (not valid CIDR) is still detected as IPv6."""
        assert _is_ipv6('2601:2c5:4000:20e9::1000-2000') is True

    def test_ipv4_range(self) -> None:
        """IPv4 range is not IPv6."""
        assert _is_ipv6('192.168.1.1-192.168.1.10') is False


# ── IPv6 subnets ─────────────────────────────────────────────────────

class TestIPv6Recommendations:
    """IPv6 subnets should get NDP + mDNS + port_scan."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_ipv6_stages(self, _mock_subnets: object) -> None:
        """IPv6 → NDP + mDNS + port_scan."""
        recs = recommend_stages('2001:db8::/64', ip_count=100)
        types = _stage_types(recs)
        assert types == [
            'ipv6_ndp_discovery',
            'ipv6_mdns_discovery',
            'port_scan',
        ]

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_ipv6_presets_balanced(self, _mock_subnets: object) -> None:
        """All IPv6 stages use balanced preset."""
        recs = recommend_stages('2001:db8::/64', ip_count=100)
        assert all(r.preset == StagePreset.BALANCED for r in recs)

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_ipv6_range_gets_ipv6_stages(self, _mock_subnets: object) -> None:
        """IPv6 range (non-CIDR) should still get IPv6 stages, not ICMP."""
        recs = recommend_stages('2601:2c5:4000:20e9::1000-2000', ip_count=4096)
        types = _stage_types(recs)
        assert types == [
            'ipv6_ndp_discovery',
            'ipv6_mdns_discovery',
            'port_scan',
        ]


# ── IPv4 small local Windows ────────────────────────────────────────

class TestIPv4SmallLocalWindows:
    """Small local subnet on Windows → icmp_arp (balanced) + port_scan (accurate)."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'Ethernet'}])
    def test_stages(self, _mock_subnets: object) -> None:
        """Picks icmp_arp + port_scan."""
        recs = recommend_stages(
            '192.168.1.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='windows',
        )
        types = _stage_types(recs)
        assert types == ['icmp_arp_discovery', 'port_scan']

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'Ethernet'}])
    def test_discovery_balanced_port_scan_accurate(self, _mock_subnets: object) -> None:
        """Discovery uses balanced, port scan uses accurate for small subnet."""
        recs = recommend_stages(
            '192.168.1.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='windows',
        )
        presets_by_type = {r.stage_type.value: r.preset for r in recs}
        assert presets_by_type['icmp_arp_discovery'] == StagePreset.BALANCED
        assert presets_by_type['port_scan'] == StagePreset.ACCURATE


# ── IPv4 large local Windows ────────────────────────────────────────

class TestIPv4LargeLocalWindows:
    """Large local subnet on Windows → poke_arp + port_scan (balanced)."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/20', 'interface': 'Ethernet'}])
    def test_stages(self, _mock_subnets: object) -> None:
        """Picks poke_arp + port_scan."""
        recs = recommend_stages(
            '10.0.0.0/20',
            ip_count=4094,
            arp_supported=True,
            os_platform='windows',
        )
        types = _stage_types(recs)
        assert types == ['poke_arp_discovery', 'port_scan']

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/20', 'interface': 'Ethernet'}])
    def test_presets_balanced(self, _mock_subnets: object) -> None:
        """All stages use balanced preset."""
        recs = recommend_stages(
            '10.0.0.0/20',
            ip_count=4094,
            arp_supported=True,
            os_platform='windows',
        )
        assert all(r.preset == StagePreset.BALANCED for r in recs)


# ── IPv4 small local Linux ──────────────────────────────────────────

class TestIPv4SmallLocalLinux:
    """Small local subnet on Linux → icmp_arp (balanced) + port_scan (accurate)."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'eth0'}])
    def test_stages(self, _mock_subnets: object) -> None:
        """Picks icmp_arp + port_scan."""
        recs = recommend_stages(
            '192.168.1.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='linux',
        )
        types = _stage_types(recs)
        assert types == ['icmp_arp_discovery', 'port_scan']

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'eth0'}])
    def test_discovery_balanced_port_scan_accurate(self, _mock_subnets: object) -> None:
        """Discovery uses balanced, port scan uses accurate for small subnet."""
        recs = recommend_stages(
            '192.168.1.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='linux',
        )
        presets_by_type = {r.stage_type.value: r.preset for r in recs}
        assert presets_by_type['icmp_arp_discovery'] == StagePreset.BALANCED
        assert presets_by_type['port_scan'] == StagePreset.ACCURATE


# ── IPv4 large local Linux ──────────────────────────────────────────

class TestIPv4LargeLocalLinux:
    """Large local subnet on Linux → icmp_arp (balanced) + port_scan (balanced).
    NOT poke_arp — it's unreliable on Linux/Mac."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/20', 'interface': 'eth0'}])
    def test_stages_no_poke(self, _mock_subnets: object) -> None:
        """Uses icmp instead of poke_arp."""
        recs = recommend_stages(
            '10.0.0.0/20',
            ip_count=4094,
            arp_supported=True,
            os_platform='linux',
        )
        types = _stage_types(recs)
        assert types == ['icmp_arp_discovery', 'port_scan']
        assert 'poke_arp_discovery' not in types


# ── IPv4 large local macOS ──────────────────────────────────────────

class TestIPv4LargeLocalMac:
    """Large local subnet on macOS → same as Linux (no poke_arp)."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/20', 'interface': 'en0'}])
    def test_stages_no_poke(self, _mock_subnets: object) -> None:
        """Uses icmp instead of poke_arp on macOS."""
        recs = recommend_stages(
            '10.0.0.0/20',
            ip_count=4094,
            arp_supported=True,
            os_platform='darwin',
        )
        types = _stage_types(recs)
        assert types == ['icmp_arp_discovery', 'port_scan']


# ── Non-local subnet ────────────────────────────────────────────────

class TestNonLocalSubnet:
    """Non-local subnets should never use ARP stages."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_icmp_only(self, _mock_subnets: object) -> None:
        """Non-local gets only ICMP."""
        recs = recommend_stages(
            '8.8.8.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='windows',
        )
        types = _stage_types(recs)
        assert types == ['icmp_discovery', 'port_scan']

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_no_arp_stages(self, _mock_subnets: object) -> None:
        """No ARP-based stages on non-local subnets."""
        recs = recommend_stages(
            '8.8.8.0/24',
            ip_count=254,
            arp_supported=True,
            os_platform='windows',
        )
        types = _stage_types(recs)
        arp_types = {'arp_discovery', 'poke_arp_discovery', 'icmp_arp_discovery'}
        assert not arp_types.intersection(types)

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_small_non_local_balanced(self, _mock_subnets: object) -> None:
        """Small non-local uses balanced preset."""
        recs = recommend_stages('8.8.8.0/24', ip_count=254)
        assert all(r.preset == StagePreset.BALANCED for r in recs)

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    def test_large_non_local_discovery_balanced_port_fast(self, _mock_subnets: object) -> None:
        """Large non-local: discovery balanced, port scan fast."""
        recs = recommend_stages('10.1.0.0/20', ip_count=4094, is_local=False)
        presets_by_type = {r.stage_type.value: r.preset for r in recs}
        assert presets_by_type['icmp_discovery'] == StagePreset.BALANCED
        assert presets_by_type['port_scan'] == StagePreset.FAST


# ── ARP not supported ───────────────────────────────────────────────

class TestArpNotSupported:
    """When ARP is not supported, fall back to plain ICMP even on local subnet."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'eth0'}])
    def test_falls_back_to_icmp(self, _mock_subnets: object) -> None:
        """Falls back to plain ICMP when ARP unsupported."""
        recs = recommend_stages(
            '192.168.1.0/24',
            ip_count=254,
            arp_supported=False,
            os_platform='linux',
        )
        types = _stage_types(recs)
        assert types == ['icmp_discovery', 'port_scan']


# ── Threshold boundary ──────────────────────────────────────────────

class TestThresholdBoundary:
    """Test the exact boundary at _LARGE_SUBNET_THRESHOLD."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/22', 'interface': 'Ethernet'}])
    def test_at_threshold_is_large(self, _mock_subnets: object) -> None:
        """At threshold count is treated as large."""
        recs = recommend_stages(
            '10.0.0.0/22',
            ip_count=_LARGE_SUBNET_THRESHOLD,
            arp_supported=True,
            os_platform='windows',
        )
        # At threshold → treated as large → poke_arp on Windows
        assert recs[0].stage_type == StageType.POKE_ARP_DISCOVERY

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '10.0.0.0/22', 'interface': 'Ethernet'}])
    def test_below_threshold_is_small(self, _mock_subnets: object) -> None:
        """Below threshold count is treated as small."""
        recs = recommend_stages(
            '10.0.0.0/22',
            ip_count=_LARGE_SUBNET_THRESHOLD - 1,
            arp_supported=True,
            os_platform='windows',
        )
        # Below threshold → small → icmp_arp on Windows
        assert recs[0].stage_type == StageType.ICMP_ARP_DISCOVERY


# ── to_dict serialization ────────────────────────────────────────────

class TestToDictSerialization:
    """StageRecommendation.to_dict() should produce a serializable dict."""

    def test_to_dict_keys(self) -> None:
        """Dict has expected keys and values."""
        rec = StageRecommendation(
            StageType.ICMP_DISCOVERY,
            StagePreset.BALANCED,
            'test reason',
        )
        d = rec.to_dict()
        assert set(d.keys()) == {'stage_type', 'preset', 'config', 'reason'}
        assert d['stage_type'] == 'icmp_discovery'
        assert d['preset'] == 'balanced'
        assert d['reason'] == 'test reason'
        assert isinstance(d['config'], dict)

    def test_to_dict_config_matches_preset(self) -> None:
        """Config in dict matches the preset from stage_presets."""
        rec = StageRecommendation(
            StageType.PORT_SCAN,
            StagePreset.FAST,
            'fast port scan',
        )
        d = rec.to_dict()
        expected_config = get_stage_presets()['port_scan']['fast']
        assert d['config'] == expected_config


# ── Auto-detection of parameters ─────────────────────────────────────

class TestAutoDetection:
    """When optional params are None, the engine should auto-detect them."""

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    @patch('lanscape.core.auto_stages._get_os_platform', return_value='windows')
    def test_auto_detects_ipv6(self, _mock_os: object, _mock_subnets: object) -> None:
        """Auto-detects IPv6 from subnet string."""
        recs = recommend_stages('2001:db8::/64')
        types = _stage_types(recs)
        assert 'ipv6_ndp_discovery' in types

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets',
           return_value=[{'subnet': '192.168.1.0/24', 'interface': 'eth0'}])
    @patch('lanscape.core.auto_stages._get_os_platform', return_value='linux')
    def test_auto_detects_local(self, _mock_os: object, _mock_subnets: object) -> None:
        """Auto-detects local subnet via interface overlap."""
        recs = recommend_stages('192.168.1.0/24', ip_count=254, arp_supported=True)
        types = _stage_types(recs)
        # Local + Linux + small → icmp_arp
        assert 'icmp_arp_discovery' in types

    @patch('lanscape.core.net_tools.subnet_utils.get_all_network_subnets', return_value=[])
    @patch('lanscape.core.auto_stages._get_os_platform', return_value='windows')
    def test_auto_detects_non_local(self, _mock_os: object, _mock_subnets: object) -> None:
        """Auto-detects non-local when no interface overlap."""
        recs = recommend_stages('8.8.8.0/24', ip_count=254, arp_supported=True)
        types = _stage_types(recs)
        # Non-local → only icmp
        assert types == ['icmp_discovery', 'port_scan']
