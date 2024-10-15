from src.lanscape import ScanManager, ScanConfig, net_tools

sm = ScanManager()

cfg = ScanConfig(
    subnet= net_tools.smart_select_primary_subnet(),
    port_list='small',
    parallelism=.5
)

scan = sm.new_scan(cfg)

scan.debug_active_scan()

print(scan.results)