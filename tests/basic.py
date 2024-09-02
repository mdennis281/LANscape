from libraries.subnet_scan import SubnetScanner, cleanup_old_jobs
import subprocess

def copy2clip(txt):
    cmd='echo '+txt.strip()+'|clip'
    return subprocess.check_call(cmd, shell=True)
def main():

    # Create a SubnetScanner instance and start scanning
    scanner = SubnetScanner('10.0.0.0/20', 'medium', 1)
    scanner.scan_subnet_threaded()
    copy2clip(scanner.uid)
    scanner.debug_active_scan()
    cleanup_old_jobs()
def main2():
    scanner = SubnetScanner('10.0.0.0/26', 'small', .5)
    print(scanner.uid)
    scanner.scan_subnet()
main()
#main2()