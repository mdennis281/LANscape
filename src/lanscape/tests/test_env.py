import unittest

from ..libraries.version_manager import lookup_latest_version 
from ..libraries.resource_manager import ResourceManager



class EnvTestCase(unittest.TestCase):
    def test_versioning(self):
        version = lookup_latest_version()
        self.assertIsNotNone(version)

    def test_resource_manager(self):
        ports = ResourceManager('ports')
        self.assertGreater(len(ports.list()),0)
        mac = ResourceManager('mac_addresses')
        mac_list = mac.get('mac_db.json')
        self.assertIsNotNone(mac_list)
        
        

