import _to_parent
from libraries.subnet_scan import SubnetScanner, cleanup_old_jobs
import subprocess


def copy2clip(txt):
    cmd='echo '+txt.strip()+'|clip'
    return subprocess.check_call(cmd, shell=True)
def main():

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner('10.0.0.0/20', 'large', 1)
    scanner.scan_subnet_threaded()
    copy2clip(scanner.uid)
    scanner.debug_active_scan()
    cleanup_old_jobs()
def main2():
    scanner = SubnetScanner('10.0.0.0/26', 'small', .5)
    print(scanner.uid)
    scanner.scan_subnet()

def main3():
    uid = SubnetScanner.scan_subnet_standalone('10.0.10.0/24','small', 1)
    copy2clip(uid)
    print(uid)
#main()
#main2()
main3()