from libraries.subnet_scan import SubnetScanner
from libraries.port_manager import PortManager
from time import sleep

def main():

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner('10.0.0.0/20', 'medium')
    scanner.scan_subnet_threaded()
    scanner.debug_active_scan()
    
main()
