import _to_parent
from concurrent.futures import ThreadPoolExecutor
from libraries.subnet_scan import SubnetScanner
from libraries.net_tools import Device
from time import time


network = '10.0.0.0/20'

def test_ping_reliability(threads=128,scans=2):
    scanner = SubnetScanner(network, 'small', 1)
    def scan_host():
        count = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scanner._ping, Device(str(ip))): str(ip) for ip in scanner.subnet}
            for future in futures:
                ans = future.result()
                if ans:
                    count += 1
        return count
    scans = [scan_host() for _ in range(scans)]
    return scans
    
for i in range(20):
    start = time()
    threads = (i+1)*50
    scans = test_ping_reliability(threads=threads) 
    t = round(time()-start)
    print(f'Threads: {threads} Cnt:  Results: {scans} Time: {t}s')