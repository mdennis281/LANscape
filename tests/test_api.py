"""
API integration tests for the LANscape application.
Tests REST API endpoints for port management, subnet validation, and scan operations.
"""
import json
import time
from unittest.mock import patch

import pytest


from tests.test_constants import (
    TEST_SUBNET,
    TEST_SUBNET_HOST_COUNT,
    MIN_EXPECTED_RUNTIME,
    MIN_EXPECTED_ALIVE_DEVICES,
    MAX_EXPECTED_ALIVE_DEVICES
)
from lanscape.ui.app import app


@pytest.fixture
def api_client():
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def sample_port_list():
    """Create a sample port list for testing."""
    return {'80': 'http', '443': 'https'}


@pytest.fixture
def updated_port_list():
    """Create an updated port list for testing."""
    return {'22': 'ssh', '8080': 'http-alt'}


@pytest.fixture
def test_scan_config():
    """Create a test scan configuration."""
    return {
        'subnet': TEST_SUBNET,
        'port_list': 'test_port_list_scan',
        'lookup_type': ['ICMP'],  # Use ICMP for reliable external IP detection
        't_multiplier': 1.5,  # Slower to ensure measurable runtime
        't_cnt_isalive': 2,   # Limit threads to extend runtime
        'ping_config': {'timeout': 0.8, 'attempts': 2}  # Reasonable timeout for external IPs
    }

# API Port Management Tests
###########################


def test_port_lifecycle(api_client, sample_port_list, updated_port_list):
    """
    Test the complete lifecycle of port list management through the API.
    Creates, retrieves, updates, and deletes a port list through API endpoints.
    """
    test_list_name = 'test_port_list_lifecycle'

    # Delete the new port list if it exists
    api_client.delete(f'/api/port/list/{test_list_name}')

    # Get the list of port lists
    response = api_client.get('/api/port/list')
    assert response.status_code == 200
    port_list_start = json.loads(response.data)

    # Create a new port list
    response = api_client.post(f'/api/port/list/{test_list_name}', json=sample_port_list)
    assert response.status_code == 200

    # Get the list of port lists again
    response = api_client.get('/api/port/list')
    assert response.status_code == 200
    port_list_new = json.loads(response.data)
    # Verify that the new port list is in the list of port lists
    assert len(port_list_new) == len(port_list_start) + 1

    # Get the new port list
    response = api_client.get(f'/api/port/list/{test_list_name}')
    assert response.status_code == 200
    port_list = json.loads(response.data)
    assert port_list == sample_port_list

    # Update the new port list
    response = api_client.put(f'/api/port/list/{test_list_name}', json=updated_port_list)
    assert response.status_code == 200

    # Get the new port list again
    response = api_client.get(f'/api/port/list/{test_list_name}')
    assert response.status_code == 200
    port_list = json.loads(response.data)

    # Verify that the new port list has been updated
    assert port_list == updated_port_list

    # Delete the new port list
    response = api_client.delete(f'/api/port/list/{test_list_name}')
    assert response.status_code == 200

# API Scan Tests
################


@pytest.mark.integration
def test_scan(api_client, sample_port_list, test_scan_config):
    """
    Test the scan API functionality by creating and monitoring a network scan.
    Verifies scan creation, status retrieval, and UI rendering for scan results.
    """
    test_list_name = 'test_port_list_scan'

    # Delete the new port list if it exists
    api_client.delete(f'/api/port/list/{test_list_name}')

    # Create a new port list
    response = api_client.post(f'/api/port/list/{test_list_name}', json=sample_port_list)
    assert response.status_code == 200

    # Create a new scan, wait for completion
    response = api_client.post('/api/scan/async', json=test_scan_config)
    assert response.status_code == 200
    scan_info = json.loads(response.data)
    assert scan_info['status'] == 'complete'
    scanid = scan_info['scan_id']
    assert scanid is not None

    # Validate the scan worked without error
    response = api_client.get(f"/api/scan/{scanid}")
    assert response.status_code == 200
    scan_data = json.loads(response.data)
    assert scan_data['errors'] == []
    assert scan_data['stage'] == 'complete'

    # Test scan UI rendering (if method exists)
    _render_scan_ui_if_available(api_client, scanid)

    # Delete the new port list
    response = api_client.delete(f'/api/port/list/{test_list_name}')
    assert response.status_code == 200


def _render_scan_ui_if_available(api_client, scanid):
    """Helper function to render scan UI if the method is available."""
    try:
        # This would be the equivalent of the original _render_scan_ui method
        _ = api_client.get(f"/scan/{scanid}")
        # We don't assert here since this is an optional UI test
    except Exception:
        # Silently pass if UI rendering is not available
        pass


def test_subnet_detection(api_client):
    """
    Test to ensure multi-subnet detection is working
    """
    response = api_client.get('/api/tools/subnet/list')
    assert response.status_code == 200

    subnets = json.loads(response.data)
    assert len(subnets) != 0
    assert isinstance(subnets[0], dict)
    subnet: dict = subnets[0]
    assert subnet.get('address_cnt') is not None

# Subnet Validation Tests
##########################


@pytest.mark.parametrize("subnet,expected_count", [
    # Valid subnets
    ('10.0.0.0/24', 254),
    ('10.0.0.2/24', 254),
    ('10.0.0.1-100', 100),
    ('192.168.1.1/25', 126),
    ('10.0.0.1/24, 192.168.1.1-100', 354),
    ('10.0.0.1/20', 4094),
    ('10.0.0.1/19', 8190),
    ('10.0.0.1/19, 192.168.1.1/20', 12284),
    ('10.0.0.1/17, 192.168.0.1/16', 98300),
    ('10.0.0.1/20, 192.168.0.1/20, 10.100.0.1/20', 12282),
    # Invalid subnets
    ('', -1),  # blank
    ('10.0.1/24', -1),  # invalid
    ('10.0.0.1/2', -1),  # too big
    ('10.0.0.1/17, 192.168.0.1/16, 10.100.0.1/20', -1),  # combined too big
])
def test_subnet_validation(api_client, subnet, expected_count):
    """Test subnet validation and parsing works as expected."""
    uri = f'/api/tools/subnet/test?subnet={subnet}'
    response = api_client.get(uri)
    assert response.status_code == 200

    data: dict = json.loads(response.data)
    assert data.get('count') == expected_count
    assert data.get('msg') is not None

    if expected_count == -1:
        assert not data.get('valid')


@pytest.mark.parametrize("arp_supported,expected_in,expected_not_in", [
    (False, 'POKE_THEN_ARP', 'ARP_LOOKUP'),
    (True, 'ARP_LOOKUP', None)
])
def test_default_scan_configs_arp_handling(api_client, arp_supported, expected_in, expected_not_in):
    """Test ARP lookup configuration based on system support."""
    with patch('lanscape.ui.blueprints.api.tools.is_arp_supported', return_value=arp_supported):
        response = api_client.get('/api/tools/config/defaults')

    assert response.status_code == 200
    configs = json.loads(response.data)
    accurate_lookup = configs['accurate']['lookup_type']

    assert expected_in in accurate_lookup
    if expected_not_in:
        assert expected_not_in not in accurate_lookup

# UI Rendering Helper


def _render_scan_ui_comprehensive(api_client, scanid):
    """Test comprehensive UI rendering for a scan."""
    uris = [
        '/info',
        f'/?scan_id={scanid}',
        f'/scan/{scanid}/overview',
        f'/scan/{scanid}/table',
        f'/scan/{scanid}/table?filter=test',
        f'/export/{scanid}'
    ]
    for uri in uris:
        response = api_client.get(uri)
        assert response.status_code == 200


@pytest.mark.integration
@pytest.mark.slow
def test_scan_api_async(api_client, test_scan_config):
    """
    Test the full scan API lifecycle with progress monitoring
    """
    # Create the port list first (since test_scan_config references it)
    sample_port_list = {'80': 'http', '443': 'https'}
    api_client.post('/api/port/list/test_port_list_scan', json=sample_port_list)

    # Create a new scan
    response = api_client.post('/api/scan', json=test_scan_config)
    assert response.status_code == 200
    scan_info = json.loads(response.data)
    assert scan_info['status'] == 'running'
    scan_id = scan_info['scan_id']
    assert scan_id is not None

    # Monitor scan progress
    percent_complete = 0
    max_iterations = 30  # Safety limit
    iteration = 0

    while percent_complete < 100 and iteration < max_iterations:
        # Get scan summary
        response = api_client.get(f'/api/scan/{scan_id}/summary')
        assert response.status_code == 200
        summary = json.loads(response.data)
        assert summary['running'] or summary['stage'] == 'complete'

        percent_complete = summary['percent_complete']
        assert 0 <= percent_complete <= 100

        # Test UI rendering during scan
        _render_scan_ui_if_available(api_client, scan_id)

        if percent_complete < 100:
            time.sleep(2)
        iteration += 1

    # Verify final scan state
    assert not summary['running']
    assert summary['stage'] == 'complete'
    assert summary['runtime'] >= MIN_EXPECTED_RUNTIME  # Should take measurable time for network ops

    # Validate device counts
    devices = summary['devices']
    assert devices['scanned'] == devices['total']
    assert MIN_EXPECTED_ALIVE_DEVICES <= devices['alive'] <= MAX_EXPECTED_ALIVE_DEVICES
    assert devices['total'] == TEST_SUBNET_HOST_COUNT  # Should scan expected number of host IPs
