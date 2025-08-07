"""
Network scan reliability test script for LANscape.
Performs multiple scans and displays progress and summary information.
"""

import os
import time

# Third-party imports - install with 'pip install tabulate'
from tabulate import tabulate

# LANscape imports
from lanscape import ScanManager, ScanConfig, net_tools
def main():
    """run reliability test for local network scans"""
    
    # Initialize scan manager
    sm = ScanManager()

    # Configure scan settings
    cfg = ScanConfig(
        subnet=net_tools.smart_select_primary_subnet(),
        port_list='small',
        t_multiplier=1
    )

    try:
        for _ in range(5):
            scan = sm.new_scan(cfg)
            while scan.running:
                time.sleep(2)
                status_text = ''
                for current_scan in sm.scans:
                    # First line: basic scan info and progress
                    status_line = (
                        f"Scan {current_scan.uid.split('-')[0]} - "
                        f"Stage: {current_scan.results.stage}, "
                        f"Progress: {current_scan.calc_percent_complete()}%"
                    )
                    
                    # Add device stats if scan is running
                    if current_scan.running:
                        results = current_scan.results
                        found_scanned_total = (
                            f'{len(results.devices)}/{results.devices_scanned}/'
                            f'{results.devices_total} scanned'
                        )
                        status_line += f' found/scanned/total: {found_scanned_total}'
                    
                    status_text += status_line + '\n'
                    
                os.system('cls' if os.name == 'nt' else 'clear')
                print(status_text)
                
    except KeyboardInterrupt:
        print("Terminating scans...")
        scan.terminate()

    # Display results in a table
    headers = ['UID', 'Devices', 'Ports', 'Timing']
    table = []
    for s in sm.scans:
        port_count = 0
        for d in s.results.devices:
            port_count += len(d.ports)
        row = [
            s.uid,
            len(s.results.devices),
            port_count,
            f"{s.results.get_runtime():.2f}"
        ]
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="grid"))
    
if __name__ == '__main__':
    main()