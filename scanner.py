from libraries.subnet_scan import SubnetScanner
import sys

if len(sys.argv) < 2:
    print('Usage: python scanner.py <scan_id>')
    sys.exit(1)

scanner = SubnetScanner.instantiate_scan(sys.argv[1])
scanner.scan_subnet()
