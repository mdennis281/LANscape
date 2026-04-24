"""
Tests for lanscape.core.stage_builder — stage construction and size validation.
"""

import pytest

from lanscape.core.scan_config import (
    PipelineConfig,
    StageConfig,
    ResilienceConfig,
    ICMPDiscoveryStageConfig,
    PokeARPDiscoveryStageConfig,
)
from lanscape.core.models.enums import StageType
from lanscape.core.stage_builder import build_stages


def _make_pipeline(stage_type: StageType, subnet: str, config: dict = None) -> PipelineConfig:
    return PipelineConfig(
        subnet=subnet,
        stages=[StageConfig(stage_type=stage_type, config=config or {})],
        resilience=ResilienceConfig(),
    )


class TestStageSizeValidation:
    """Stage builder should enforce per-stage MAX_SUBNET_SIZE constraints."""

    def test_icmp_within_limit_ok(self):
        """ICMP stage on a /24 (254 IPs) should build without error."""
        stages = build_stages(_make_pipeline(StageType.ICMP_DISCOVERY, "192.168.1.0/24"))
        assert len(stages) == 1

    def test_icmp_exceeds_limit_raises(self):
        """ICMP stage on a /8 (~16M IPs) should raise ValueError."""
        with pytest.raises(ValueError, match="icmp_discovery"):
            build_stages(_make_pipeline(StageType.ICMP_DISCOVERY, "10.0.0.0/8"))

    def test_poke_arp_medium_subnet_ok(self):
        """Poke+ARP stage on a /17 (~32k IPs, within 64k limit) should build ok."""
        stages = build_stages(_make_pipeline(StageType.POKE_ARP_DISCOVERY, "10.0.0.0/17"))
        assert len(stages) == 1

    def test_poke_arp_exceeds_limit_raises(self):
        """Poke+ARP on a /8 (~16M IPs) should raise ValueError."""
        with pytest.raises(ValueError, match="poke_arp_discovery"):
            build_stages(_make_pipeline(StageType.POKE_ARP_DISCOVERY, "10.0.0.0/8"))

    def test_icmp_at_exact_limit_ok(self):
        """ICMP stage at exactly 25,000 IPs should be allowed."""
        # 10.0.0.0/17 = 32,766 IPs — too large. Use /18 = 16,382 IPs (within 25k)
        stages = build_stages(_make_pipeline(StageType.ICMP_DISCOVERY, "10.0.0.0/18"))
        assert len(stages) == 1


class TestIPv6NoParsing:
    """IPv6-only pipelines must not enumerate the subnet (allows unlimited subnet sizes)."""

    def test_ndp_large_subnet_ok(self):
        """NDP stage on /64 (huge IPv6) should build without error."""
        pipeline = _make_pipeline(StageType.IPV6_NDP_DISCOVERY, "fd00::/64")
        stages = build_stages(pipeline)
        assert len(stages) == 1

    def test_mdns_large_subnet_ok(self):
        """mDNS stage on /48 (enormous IPv6) should build without error."""
        pipeline = _make_pipeline(StageType.IPV6_MDNS_DISCOVERY, "fd00::/48")
        stages = build_stages(pipeline)
        assert len(stages) == 1

    def test_port_scan_only_ok(self):
        """Port scan stage (no subnet enumeration) should work for any subnet."""
        pipeline = _make_pipeline(StageType.PORT_SCAN, "10.0.0.0/8")
        stages = build_stages(pipeline)
        assert len(stages) == 1


class TestMaxSubnetSizeClassVars:
    """Verify ClassVar constants are accessible but not in Pydantic schema."""

    def test_icmp_max_subnet_size(self):
        """ICMPDiscoveryStageConfig.MAX_SUBNET_SIZE == 25_000."""
        assert ICMPDiscoveryStageConfig.MAX_SUBNET_SIZE == 25_000

    def test_poke_arp_max_subnet_size(self):
        """PokeARPDiscoveryStageConfig.MAX_SUBNET_SIZE == 64_000."""
        assert PokeARPDiscoveryStageConfig.MAX_SUBNET_SIZE == 64_000

    def test_max_subnet_size_not_in_schema(self):
        """MAX_SUBNET_SIZE should not appear in Pydantic model fields."""
        fields = ICMPDiscoveryStageConfig.model_fields
        assert "MAX_SUBNET_SIZE" not in fields.keys()
