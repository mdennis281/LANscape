"""
Investigation script: scan an IPv6 range and check hostname-based dedup.

Multiple IPv6 addresses can map to the same physical device (SLAAC, privacy
extensions, temporary addresses, etc.).  This script scans a range, shows
which devices were consolidated by hostname, and reports any remaining
duplicates.
"""

import logging
from collections import defaultdict
from lanscape import ScanManager, PipelineConfig, StageConfig, recommend_stages

logging.basicConfig(level=logging.INFO)

SUBNET = "2601:2c5:4000:20e9::1000-2000"

sm = ScanManager()

# Use auto-recommended stages
recommendations = recommend_stages(SUBNET)
stage_configs = [
    StageConfig(stage_type=r.stage_type, config=r.to_dict()['config'])
    for r in recommendations
]

print("Recommended stages:")
for r in recommendations:
    print(f"  - {r.stage_type.value}: {r.reason}")

cfg = PipelineConfig(
    subnet=SUBNET,
    stages=stage_configs,
)

try:
    scan = sm.new_scan(cfg)
    scan.debug_active_scan()
except KeyboardInterrupt:
    print("\nTerminating scan...")
    scan.terminate()

# ── Analyze results ──────────────────────────────────────────────
results = scan.results
devices = results.devices

print(f"\n{'=' * 60}")
print(f"Scan complete — {len(devices)} unique device(s)")
print(f"{'=' * 60}\n")

# Show devices with their merged IPs
for d in devices:
    mac = d.get_mac() if hasattr(d, 'get_mac') else (d.macs[0] if d.macs else '—')
    print(f"  {d.ip:<45}  MAC: {mac:<20}  host: {d.hostname or '—'}")
    if d.merged_ips:
        print(f"    Consolidated {len(d.merged_ips)} additional IP(s):")
        for mip in d.merged_ips:
            print(f"      + {mip}")
    if d.ipv6_addresses and len(d.ipv6_addresses) > 1:
        print(f"    All IPv6 addresses: {d.ipv6_addresses}")
    print()

# Check for remaining hostname duplicates (should be 0 with consolidation)
hostname_groups: dict[str, list] = defaultdict(list)
for d in devices:
    if d.hostname:
        hostname_groups[d.hostname.lower()].append(d)

remaining_dups = {h: devs for h, devs in hostname_groups.items() if len(devs) > 1}
if remaining_dups:
    print(f"WARNING: {len(remaining_dups)} hostname(s) still have multiple entries:")
    for hostname, devs in remaining_dups.items():
        print(f"  {hostname}: {[d.ip for d in devs]}")
else:
    print("All devices with matching hostnames were successfully consolidated.")
