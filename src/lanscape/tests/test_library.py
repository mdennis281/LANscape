import unittest
from ..libraries.net_tools import smart_select_primary_subnet
from ._helpers import right_size_subnet
from ..libraries.subnet_scan import ScanManager, ScanConfig

sm = ScanManager()

class LibraryTestCase(unittest.TestCase):
    def test_scan(self):
        subnet = smart_select_primary_subnet()
        self.assertIsNotNone(subnet)
        cfg = ScanConfig(
            subnet = right_size_subnet(subnet),
            parallelism=1.0,
            port_list='small'
        )
        scan = sm.new_scan(cfg)
        self.assertTrue(scan.running)
        sm.wait_until_complete(scan.uid)

        self.assertFalse(scan.running)

        # ensure there are not any remaining running threads
        self.assertDictEqual(scan.job_stats.running,{})


        cnt_with_hostname = 0
        ips = []
        macs = []
        for d in scan.results.devices:
            if d.hostname: cnt_with_hostname += 1
            # ensure there arent dupe mac addresses
            self.assertNotIn(d.mac_addr, macs)
            macs.append(d.mac_addr)

            # ensure there arent dupe ips
            self.assertNotIn(d.ip, ips)
            ips.append(d.ip)

            # device must be alive to be in this list
            self.assertTrue(d.alive)
    
        # find at least one device
        self.assertGreater(len(scan.results.devices),0)

        # ensure everything got scanned
        self.assertEqual(scan.results.devices_scanned, scan.results.devices_total)




        
        