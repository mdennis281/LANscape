"""
Tests for the tools WebSocket handler utilities.
"""

from lanscape.ui.ws.handlers.tools import _format_ip_count


class TestFormatIpCount:
    """Tests for the _format_ip_count helper function."""

    # --- exact count (< 1,000) ---

    def test_singular(self):
        """Single IP uses singular form."""
        assert _format_ip_count(1) == "1 IP"

    def test_plural_small(self):
        """Small plural count."""
        assert _format_ip_count(500) == "500 IPs"

    def test_999(self):
        """999 stays in exact form."""
        assert _format_ip_count(999) == "999 IPs"

    # --- k tier (1,000 – 999,999) ---

    def test_exactly_1k(self):
        """1,000 formats as 1k."""
        assert _format_ip_count(1_000) == "1k IPs"

    def test_12450(self):
        """12,450 → 12.45k IPs (example from spec)."""
        assert _format_ip_count(12_450) == "12.45k IPs"

    def test_trailing_zero_stripped_k(self):
        """Trailing zeros stripped: 10,000 → 10k, not 10.00k."""
        assert _format_ip_count(10_000) == "10k IPs"

    def test_1500(self):
        """1,500 → 1.5k."""
        assert _format_ip_count(1_500) == "1.5k IPs"

    def test_999999(self):
        """999,999 stays in k tier."""
        result = _format_ip_count(999_999)
        assert result.endswith("k IPs")

    # --- M tier (1,000,000 – 999,999,999) ---

    def test_one_point_two_million(self):
        """1,200,005 → 1.2M IPs (example from spec)."""
        assert _format_ip_count(1_200_005) == "1.2M IPs"

    def test_exactly_one_million(self):
        """1,000,000 → 1M IPs."""
        assert _format_ip_count(1_000_000) == "1M IPs"

    def test_trailing_zero_stripped_million(self):
        """10,000,000 → 10M IPs (not 10.0M)."""
        assert _format_ip_count(10_000_000) == "10M IPs"

    # --- B tier (1,000,000,000 – 999,999,999,999) ---

    def test_one_point_three_billion(self):
        """1,300,400,100 → 1.3B IPs (example from spec)."""
        assert _format_ip_count(1_300_400_100) == "1.3B IPs"

    def test_exactly_one_billion(self):
        """1,000,000,000 → 1B IPs."""
        assert _format_ip_count(1_000_000_000) == "1B IPs"

    # --- T tier (1,000,000,000,000 – 999,999,999,999,999) ---

    def test_two_point_five_trillion(self):
        """2,500,000,000,000 → 2.5T IPs (example from spec)."""
        assert _format_ip_count(2_500_000_000_000) == "2.5T IPs"

    def test_exactly_one_trillion(self):
        """1,000,000,000,000 → 1T IPs."""
        assert _format_ip_count(1_000_000_000_000) == "1T IPs"

    def test_nine_nine_nine_trillion_upper_bound(self):
        """999,999,999,999,999 stays in T tier."""
        result = _format_ip_count(999_999_999_999_999)
        assert result.endswith("T IPs")

    # --- scientific (>= 10^15 / > 999T) ---

    def test_scientific_10_15(self):
        """10^15 uses scientific notation."""
        result = _format_ip_count(10 ** 15)
        assert "e+" in result
        assert result.endswith(" IPs")

    def test_scientific_very_large(self):
        """Very large numbers use scientific notation."""
        result = _format_ip_count(10 ** 30)
        assert "e+" in result
