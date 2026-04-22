"""Quick IPv6 scan to diagnose dedup behavior."""
import logging
import time
from collections import defaultdict
from lanscape import ScanManager, PipelineConfig, StageConfig, recommend_stages

logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(message)s')

SUBNET = "2601:2c5:4000:20e9::1000-2000"

sm = ScanManager()
recommendations = recommend_stages(SUBNET)
stage_configs = [
    StageConfig(stage_type=r.stage_type, config=r.to_dict()['config'])
    for r in recommendations
]

print("Stages:")
for r in recommendations:
    print(f"  {r.stage_type.value}: {r.reason}")

cfg = PipelineConfig(subnet=SUBNET, stages=stage_configs)
scan = sm.new_scan(cfg)

# Poll until done
while scan.running:
    time.sleep(2)
    print(f"  ... running, {len(scan.results.devices)} devices so far")

devices = scan.results.devices
print(f"\n{'='*70}")
print(f"RESULTS: {len(devices)} device entries")
print(f"{'='*70}")

# Group by hostname
hostname_groups: dict[str, list] = defaultdict(list)
mac_groups: dict[str, list] = defaultdict(list)

for d in devices:
    mac = d.get_mac() if hasattr(d, 'get_mac') else ''
    hostname = d.hostname or ''
    print(f"  IP: {d.ip:<45} MAC: {mac:<20} host: {hostname}")
    print(f"    merged_ips={d.merged_ips}  ipv6_addresses={d.ipv6_addresses}")
    if hostname:
        hostname_groups[hostname.lower()].append(d)
    if mac:
        mac_groups[mac.upper()].append(d)

print("\n--- Hostname groups ---")
for h, devs in hostname_groups.items():
    if len(devs) > 1:
        print(f"  DUPLICATE hostname '{h}': {[d.ip for d in devs]}")
    else:
        print(f"  OK '{h}': {devs[0].ip}")

print("\n--- MAC groups ---")
for m, devs in mac_groups.items():
    if len(devs) > 1:
        print(f"  DUPLICATE MAC {m}: {[d.ip for d in devs]}")
    else:
        print(f"  OK {m}: {devs[0].ip}")
