from lanscape import ScanManager, ScanConfig, net_tools

sm = ScanManager()

cfg = ScanConfig(
    subnet= net_tools.smart_select_primary_subnet(),
    port_list='small',
    t_multiplier=1
)

try:
    scan = sm.new_scan(cfg)

    scan.debug_active_scan()
except KeyboardInterrupt:
    print("Terminating scan...")
    scan.terminate()

print(scan.results)
