from src.lanscape import ScanManager, ScanConfig, net_tools
from tabulate import tabulate
import os, time

sm = ScanManager()

cfg = ScanConfig(
    subnet = net_tools.smart_select_primary_subnet(),
    port_list = 'large',
    t_multiplier = 1
)
try:
    for _ in range(5):
        scan = sm.new_scan(cfg)
        while scan.running:
            time.sleep(2)
            buffer = ''
            for scan in sm.scans:
                buffer += f"Scan {scan.uid.split('-')[0]} - Stage: {scan.results.stage}, Progress: {scan.calc_percent_complete()}%\n"
            os.system('cls' if os.name == 'nt' else 'clear')
            print(buffer)
            


except KeyboardInterrupt:
    scan.terminate()
headers = ['UID', 'Devices', 'Ports', 'Timing']
table = []
for s in sm.scans:
    port_cnt = 0
    for d in s.results.devices:
        port_cnt += len(d.ports)
    row = [
        s.uid,
        len(s.results.devices),
        port_cnt,
        f"{s.results.get_runtime():.2f}"
    ]
    table.append(row)



print( tabulate(table, headers=headers, tablefmt="grid") )