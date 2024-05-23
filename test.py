from libraries.subnet_scan import SubnetScanner
from libraries.port_manager import PortManager
from time import sleep

def main():
    ports_to_scan = PortManager().get_port_list('medium').keys()

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner('10.0.10.0/24', ports_to_scan)
    scanner.scan_subnet_threaded()
    scanner.debug_active_scan()
    
main()