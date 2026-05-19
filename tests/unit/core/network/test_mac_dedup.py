"""Tests for ScanContext device consolidation (hostname + MAC dedup)."""

from lanscape.core.scan_context import ScanContext
from lanscape.core.net_tools.device import Device


class TestScanContextConsolidation:
    """Verify that devices sharing a hostname or MAC are merged."""

    def _make_device(
        self,
        ip: str,
        hostname: str | None = None,
        macs: list[str] | None = None,
    ) -> Device:
        """Create a minimal alive Device."""
        dev = Device(ip=ip)
        dev.alive = True
        dev.hostname = hostname
        if macs:
            dev.macs = macs
        return dev

    # ── Hostname-based consolidation ─────────────────────────────

    def test_same_hostname_merged(self):
        """Two IPv6 addresses resolving to the same hostname produce one device."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", hostname="myserver.local")
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", hostname="myserver.local")

        ctx.add_device(dev1)
        ctx.add_device(dev2)
        assert len(ctx.devices) == 2

        merged = ctx.consolidate_devices()
        assert merged == 1
        assert len(ctx.devices) == 1
        assert ctx.devices[0].ip == dev1.ip
        assert "2601:2c5:4000:20e9::1001" in dev1.merged_ips

    def test_different_hostnames_not_merged(self):
        """Devices with different hostnames remain separate."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", hostname="server-a.local")
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", hostname="server-b.local")

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 0
        assert len(ctx.devices) == 2

    def test_hostname_case_insensitive(self):
        """Hostname comparison should be case-insensitive."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", hostname="MyServer.Local")
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", hostname="myserver.local")

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 1
        assert len(ctx.devices) == 1

    # ── MAC-based consolidation ──────────────────────────────────

    def test_same_mac_merged(self):
        """Two IPv6 addresses with the same MAC produce one device."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")
        mac = "AA:BB:CC:DD:EE:FF"

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", macs=[mac])
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", macs=[mac])

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 1
        assert len(ctx.devices) == 1
        assert "2601:2c5:4000:20e9::1001" in dev1.merged_ips

    def test_different_macs_not_merged(self):
        """Devices with different MACs remain separate."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", macs=["AA:BB:CC:DD:EE:01"])
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", macs=["AA:BB:CC:DD:EE:02"])

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 0
        assert len(ctx.devices) == 2

    def test_mac_case_insensitive(self):
        """MAC comparison should be case-insensitive."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", macs=["aa:bb:cc:dd:ee:ff"])
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", macs=["AA:BB:CC:DD:EE:FF"])

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 1
        assert len(ctx.devices) == 1

    def test_multiple_ips_same_mac(self):
        """Three IPs from one host (privacy extensions) all merge."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")
        mac = "40:ED:CF:9A:ED:11"

        devs = [
            self._make_device(f"2601:2c5:4000:20e9::{i}", macs=[mac])
            for i in range(1000, 1003)
        ]
        for d in devs:
            ctx.add_device(d)

        merged = ctx.consolidate_devices()
        assert merged == 2
        assert len(ctx.devices) == 1
        assert len(devs[0].merged_ips) == 2

    # ── No-identity devices ──────────────────────────────────────

    def test_no_hostname_no_mac_not_merged(self):
        """Devices without hostname or MAC are never merged."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000")
        dev2 = self._make_device("2601:2c5:4000:20e9::1001")

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_devices()
        assert merged == 0
        assert len(ctx.devices) == 2

    # ── Mixed signals ────────────────────────────────────────────

    def test_mixed_hostname_and_mac(self):
        """One device has hostname, another shares MAC — both consolidate."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")
        mac = "26:27:B6:E3:91:E1"

        dev1 = self._make_device(
            "2601:2c5:4000:20e9::1000", hostname="desktop.local", macs=[mac],
        )
        dev2 = self._make_device(
            "2601:2c5:4000:20e9::1001", macs=[mac],
        )
        dev3 = self._make_device(
            "2601:2c5:4000:20e9::1002", hostname="desktop.local",
        )

        for d in [dev1, dev2, dev3]:
            ctx.add_device(d)

        merged = ctx.consolidate_devices()
        assert merged == 2
        assert len(ctx.devices) == 1
        assert len(dev1.merged_ips) == 2

    def test_mixed_hostname_mac_and_bare_devices(self):
        """Only matching devices merge; bare ones stay."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device(
            "2601:2c5:4000:20e9::1000", hostname="nas.local", macs=["AA:BB:CC:DD:EE:FF"],
        )
        dev2 = self._make_device(
            "2601:2c5:4000:20e9::1001", macs=["AA:BB:CC:DD:EE:FF"],
        )
        dev3 = self._make_device("2601:2c5:4000:20e9::1002")  # no hostname or MAC
        dev4 = self._make_device(
            "2601:2c5:4000:20e9::1003", hostname="printer.local",
        )

        for d in [dev1, dev2, dev3, dev4]:
            ctx.add_device(d)

        merged = ctx.consolidate_devices()
        assert merged == 1
        assert len(ctx.devices) == 3

    # ── Edge cases ───────────────────────────────────────────────

    def test_consolidate_idempotent(self):
        """Calling consolidate twice should not cause double-merge."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", macs=["AA:BB:CC:DD:EE:FF"])
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", macs=["AA:BB:CC:DD:EE:FF"])

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        assert ctx.consolidate_devices() == 1
        assert ctx.consolidate_devices() == 0
        assert len(ctx.devices) == 1

    def test_duplicate_ip_still_rejected(self):
        """Same IP should still be rejected by add_device."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000")
        dev2 = self._make_device("2601:2c5:4000:20e9::1000")

        assert ctx.add_device(dev1) is True
        assert ctx.add_device(dev2) is False
        assert len(ctx.devices) == 1

    def test_devices_alive_after_consolidation(self):
        """devices_alive should reflect the consolidated count."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", macs=["AA:BB:CC:DD:EE:FF"])
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", macs=["AA:BB:CC:DD:EE:FF"])

        ctx.add_device(dev1)
        ctx.add_device(dev2)
        assert ctx.devices_alive == 2

        ctx.consolidate_devices()
        assert ctx.devices_alive == 1

    def test_backwards_compat_alias(self):
        """consolidate_by_hostname alias should still work."""
        ctx = ScanContext(subnet="2601:2c5:4000:20e9::/64")

        dev1 = self._make_device("2601:2c5:4000:20e9::1000", hostname="box.local")
        dev2 = self._make_device("2601:2c5:4000:20e9::1001", hostname="box.local")

        ctx.add_device(dev1)
        ctx.add_device(dev2)

        merged = ctx.consolidate_by_hostname()
        assert merged == 1
        assert len(ctx.devices) == 1


class TestDeviceMergedIpsInResult:
    """Verify merged IPs appear in the final DeviceResult model."""

    def test_merged_ips_in_ipv6_addresses(self):
        """Merged IPv6 addresses should appear in ipv6_addresses after alt-IP resolution."""
        dev = Device(ip="2601:2c5:4000:20e9::1000")
        dev.alive = True
        dev.macs = ["AA:BB:CC:DD:EE:FF"]
        dev.merged_ips = [
            "2601:2c5:4000:20e9::1001",
            "2601:2c5:4000:20e9::1002",
        ]

        # Simulate what _resolve_alt_ips does with merged_ips
        all_ips = [dev.ip] + dev.alt_ips + dev.merged_ips
        seen: set[str] = set()
        unique: list[str] = []
        for ip in all_ips:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        dev.ipv6_addresses = [ip for ip in unique if ':' in ip]

        result = dev.to_result()
        assert "2601:2c5:4000:20e9::1000" in result.ipv6_addresses
        assert "2601:2c5:4000:20e9::1001" in result.ipv6_addresses
        assert "2601:2c5:4000:20e9::1002" in result.ipv6_addresses
