import unittest

from lanscape.libraries.version_manager import lookup_latest_version
from lanscape.libraries.app_scope import ResourceManager, is_local_run
from lanscape.libraries.net_tools import is_arp_supported


class EnvTestCase(unittest.TestCase):
    def test_versioning(self):
        version = lookup_latest_version()
        self.assertIsNotNone(version)

    def test_resource_manager(self):
        ports = ResourceManager('ports')
        self.assertGreater(len(ports.list()), 0)
        mac = ResourceManager('mac_addresses')
        mac_list = mac.get('mac_db.json')
        self.assertIsNotNone(mac_list)

    def test_local_version(self):
        self.assertTrue(is_local_run())

    def test_arp_support(self):
        arp_supported = is_arp_supported()
        self.assertIn(arp_supported, [True, False],
                      f"ARP support should be either True or False, not {arp_supported}"
                      )
