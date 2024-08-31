from libraries.subnet_scan import SubnetScanner, cleanup_old_jobs
from time import sleep

def main():

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner('10.0.0.0/20', 'large', .6)
    scanner.scan_subnet_threaded()
    scanner.debug_active_scan()
    cleanup_old_jobs()
main()
