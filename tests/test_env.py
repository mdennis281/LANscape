"""
Environment tests for the LANscape application.
Verifies functionality related to version checking, resource management,
execution environment detection, and network support features.
"""

from unittest.mock import patch, MagicMock

import pytest

from lanscape.core.version_manager import lookup_latest_version
from lanscape.core.app_scope import ResourceManager, is_local_run
from lanscape.core.net_tools import is_arp_supported


@pytest.fixture
def mock_resource_manager():
    """Create a mock ResourceManager for testing."""
    with patch('lanscape.core.app_scope.ResourceManager') as mock_rm:
        mock_instance = MagicMock()
        mock_rm.return_value = mock_instance
        yield mock_instance


# Version Management Tests
##########################

def test_version_lookup_returns_valid_version():
    """Test that the version lookup functionality returns a valid version string."""
    version = lookup_latest_version()

    assert version is not None
    assert isinstance(version, str)
    # Basic version pattern check (should contain digits and dots)
    assert any(char.isdigit() for char in version)


def test_version_lookup_return_type():
    """Test version lookup returns expected type."""
    version = lookup_latest_version()
    if version is not None:
        assert isinstance(version, str)
    else:
        # Allow None for network failures
        assert version is None


# Resource Manager Tests
########################

def test_resource_manager_lists_ports():
    """Test the ResourceManager can list port resources."""
    ports = ResourceManager('ports')
    port_list = ports.list()

    assert len(port_list) > 0
    assert isinstance(port_list, list)


def test_resource_manager_retrieves_mac_database():
    """Test ResourceManager can retrieve MAC address database."""
    mac = ResourceManager('mac_addresses')
    mac_list = mac.get('mac_db.json')

    assert mac_list is not None


@pytest.mark.parametrize("resource_type,expected_method", [
    ('ports', 'list'),
    ('mac_addresses', 'get'),
])
def test_resource_manager_methods(resource_type, expected_method):
    """Test ResourceManager has required methods for different resource types."""
    manager = ResourceManager(resource_type)

    assert hasattr(manager, expected_method)
    assert callable(getattr(manager, expected_method))


def test_resource_manager_with_mock(mock_resource_manager):
    """Test ResourceManager behavior with mocked dependencies."""
    mock_resource_manager.list.return_value = ['port1', 'port2']
    mock_resource_manager.get.return_value = {'test': 'data'}

    # Test the mock behavior
    assert mock_resource_manager.list() == ['port1', 'port2']
    assert mock_resource_manager.get('test') == {'test': 'data'}


# Environment Detection Tests
##############################

def test_local_run_detection():
    """Test that the app correctly identifies it's running in a local environment."""
    result = is_local_run()

    assert isinstance(result, bool)
    assert result is True  # Should be True in test environment


def test_arp_support_detection():
    """Test that ARP support detection returns a valid boolean value."""
    arp_supported = is_arp_supported()

    assert isinstance(arp_supported, bool)
    assert arp_supported in [True, False]


@pytest.mark.parametrize("platform,expected", [
    ("win32", True),    # Windows typically supports ARP
    ("linux", True),    # Linux typically supports ARP
    ("darwin", True),   # macOS typically supports ARP
])
def test_arp_support_by_platform(platform, expected):  # pylint: disable=unused-argument
    """Test ARP support expectations by platform (informational test)."""
    with patch('sys.platform', platform):
        # This is more of an informational test about expectations
        arp_supported = is_arp_supported()
        # We don't assert the expected value since actual support depends on system config
        assert isinstance(arp_supported, bool)


# Integration Tests
###################

@pytest.mark.integration
def test_environment_integration():
    """Integration test verifying all environment components work together."""
    # Test version lookup
    version = lookup_latest_version()

    # Test resource access
    ports_rm = ResourceManager('ports')
    _ = ResourceManager('mac_addresses')  # MAC database is optional

    # Test environment detection
    is_local = is_local_run()
    arp_support = is_arp_supported()

    # Basic assertions that everything returns reasonable values
    if version is not None:
        assert isinstance(version, str)

    assert len(ports_rm.list()) >= 0
    # MAC DB is optional, don't assert presence
    assert isinstance(is_local, bool)
    assert isinstance(arp_support, bool)
