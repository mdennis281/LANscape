from lanscape import ScanManager, ScanConfig, net_tools
from tabulate import tabulate
import os, time

sm = ScanManager()

cfg = ScanConfig(
    subnet = net_tools.smart_select_primary_subnet(),
    port_list = 'small',
    t_multiplier = 1
)
try:
    for _ in range(5):
        scan = sm.new_scan(cfg)
        while scan.running:
            time.sleep(2)
            buffer = ''
            for scan in sm.scans:
                buffer += f"Scan {scan.uid.split('-')[0]} - Stage: {scan.results.stage}, Progress: {scan.calc_percent_complete()}%"
                if scan.running:
                    r = scan.results
                    found_scanned_total = f'{len(r.devices)}/{r.devices_scanned}/{r.devices_total} scanned'
                    buffer += f' found/scanned/total: {found_scanned_total}'
                buffer += '\n'
            os.system('cls' if os.name == 'nt' else 'clear')
            print(buffer)
            


except KeyboardInterrupt:
    print("Terminating scans...")
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