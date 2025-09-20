"""
Example script to run a network scan using lanscape library.
"""
from lanscape import ScanManager, ScanConfig, net_tools, ScanType, PokeConfig



sm = ScanManager()

cfg = ScanConfig(
    subnet=net_tools.smart_select_primary_subnet(),
    port_list='medium',
    lookup_type=[ScanType.POKE_THEN_ARP],
    poke_config=PokeConfig(
        timeout=.25,
        retries=4
    )
)
try:
    scan = sm.new_scan(cfg)
    scan.debug_active_scan()
except KeyboardInterrupt:
    print("Terminating scan...")
    scan.terminate()

print(scan.results)
