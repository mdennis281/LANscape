"""
Environment tests for the LANscape application.
Verifies functionality related to version checking, resource management,
execution environment detection, and network support features.
"""

import unittest

from lanscape.libraries.version_manager import lookup_latest_version
from lanscape.libraries.app_scope import ResourceManager, is_local_run
from lanscape.libraries.net_tools import is_arp_supported


class EnvTestCase(unittest.TestCase):
    """
    Test cases verifying the application's environment-related functionality.
    Tests version lookups, resource access, and system feature detection.
    """

    def test_versioning(self):
        """Test that the version lookup functionality works correctly."""
        version = lookup_latest_version()
        self.assertIsNotNone(version)

    def test_resource_manager(self):
        """
        Test the ResourceManager can access embedded resources.
        Verifies both listing and retrieving specific resources.
        """
        ports = ResourceManager('ports')
        self.assertGreater(len(ports.list()), 0)
        mac = ResourceManager('mac_addresses')
        mac_list = mac.get('mac_db.json')
        self.assertIsNotNone(mac_list)

    def test_local_version(self):
        """Test that the app correctly identifies its running in a local environment."""
        self.assertTrue(is_local_run())

    def test_arp_support(self):
        """Test that ARP support detection returns a valid boolean value."""
        arp_supported = is_arp_supported()
        self.assertIn(arp_supported, [True, False],
                      f"ARP support should be either True or False, not {arp_supported}"
                      )
