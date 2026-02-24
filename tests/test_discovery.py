"""
Tests for mDNS discovery module.
"""
import errno
import ipaddress
import json
import socket
from unittest.mock import MagicMock, patch

from lanscape.ui.react_proxy.discovery import (
    DiscoveredInstance,
    DiscoverResponse,
    DiscoveryService,
    SERVICE_TYPE,
    _best_lan_address,
    _get_local_addresses,
    _get_local_subnets,
    build_default_route,
)


class TestGetLocalAddresses:
    """Tests for the _get_local_addresses helper."""

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_returns_private_ipv4(self, mock_psutil):
        """Test that private LAN IPv4 addresses are collected."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_addr = MagicMock()
        mock_addr.family = socket.AF_INET
        mock_addr.address = '192.168.1.100'
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert socket.inet_aton('192.168.1.100') in result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_loopback(self, mock_psutil):
        """Test that loopback addresses are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'lo': MagicMock(isup=True),
        }
        mock_addr = MagicMock()
        mock_addr.family = socket.AF_INET
        mock_addr.address = '127.0.0.1'
        mock_psutil.net_if_addrs.return_value = {'lo': [mock_addr]}

        result = _get_local_addresses()
        assert not result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_virtual_interfaces(self, mock_psutil):
        """Test that virtual adapter interfaces are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'VMnet8': MagicMock(isup=True),
            'docker0': MagicMock(isup=True),
        }
        mock_vm_addr = MagicMock(family=socket.AF_INET, address='172.16.0.1')
        mock_dk_addr = MagicMock(family=socket.AF_INET, address='172.17.0.1')
        mock_psutil.net_if_addrs.return_value = {
            'VMnet8': [mock_vm_addr],
            'docker0': [mock_dk_addr],
        }

        result = _get_local_addresses()
        assert not result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_down_interfaces(self, mock_psutil):
        """Test that down interfaces are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=False),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='192.168.1.50')
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert not result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_link_local(self, mock_psutil):
        """Test that link-local addresses are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='169.254.1.1')
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert not result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_zerotier_interface(self, mock_psutil):
        """Test that ZeroTier overlay interfaces are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'ZeroTier One [abc123]': MagicMock(isup=True),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='10.69.69.69')
        mock_psutil.net_if_addrs.return_value = {
            'ZeroTier One [abc123]': [mock_addr]
        }

        result = _get_local_addresses()
        assert not result

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_ics_subnet(self, mock_psutil):
        """Test that Windows ICS (192.168.137.x) addresses are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='192.168.137.1')
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert not result


class TestGetLocalSubnets:
    """Tests for the _get_local_subnets helper."""

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_returns_subnet_from_interface(self, mock_psutil):
        """Test that subnets are correctly derived from interface info."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_addr = MagicMock(
            family=socket.AF_INET,
            address='10.0.4.1',
            netmask='255.255.240.0',
        )
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_subnets()
        assert len(result) == 1
        assert result[0] == ipaddress.ip_network('10.0.0.0/20')

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_virtual_interfaces(self, mock_psutil):
        """Test that virtual interfaces are excluded from subnets."""
        mock_psutil.net_if_stats.return_value = {
            'ZeroTier One [x]': MagicMock(isup=True),
        }
        mock_addr = MagicMock(
            family=socket.AF_INET,
            address='10.69.69.69',
            netmask='255.255.255.0',
        )
        mock_psutil.net_if_addrs.return_value = {
            'ZeroTier One [x]': [mock_addr]
        }

        result = _get_local_subnets()
        assert not result


class TestBestLanAddress:
    """Tests for _best_lan_address subnet-aware selection."""

    def test_prefers_same_subnet(self):
        """Test that an address on the same subnet is preferred."""
        subnets = [ipaddress.ip_network('10.0.0.0/20')]
        # ZeroTier first, ICS second, real LAN last
        addrs = ['10.69.69.3', '192.168.137.1', '10.0.11.221']
        assert _best_lan_address(addrs, subnets) == '10.0.11.221'

    def test_falls_back_to_private(self):
        """Test fallback to any private address when no subnet match."""
        subnets = [ipaddress.ip_network('172.16.0.0/24')]  # different subnet
        addrs = ['10.0.4.1', '10.69.69.69']
        assert _best_lan_address(addrs, subnets) == '10.0.4.1'

    def test_skips_ics_in_fallback(self):
        """Test that ICS addresses are skipped in fallback."""
        subnets = []  # no local subnets
        addrs = ['192.168.137.1', '10.0.11.221']
        assert _best_lan_address(addrs, subnets) == '10.0.11.221'

    def test_empty_returns_none(self):
        """Test that empty address list returns None."""
        assert _best_lan_address([], []) is None

    def test_last_resort_returns_first(self):
        """Test that a non-private address is returned as last resort."""
        subnets = []
        addrs = ['8.8.8.8']
        assert _best_lan_address(addrs, subnets) == '8.8.8.8'


class TestDiscoveredInstance:
    """Tests for the DiscoveredInstance model."""

    def test_create_instance(self):
        """Test creating a discovered instance."""
        inst = DiscoveredInstance(
            host='192.168.1.10',
            ws_port=8766,
            http_port=5001,
            version='1.2.3',
            hostname='my-pc',
        )
        assert inst.host == '192.168.1.10'
        assert inst.ws_port == 8766
        assert inst.http_port == 5001
        assert inst.version == '1.2.3'
        assert inst.hostname == 'my-pc'

    def test_model_dump(self):
        """Test that model_dump returns correct dict."""
        inst = DiscoveredInstance(
            host='10.0.0.5',
            ws_port=9999,
            http_port=8080,
            version='2.0.0',
            hostname='server-a',
        )
        data = inst.model_dump()
        assert data == {
            'host': '10.0.0.5',
            'ws_port': 9999,
            'http_port': 8080,
            'version': '2.0.0',
            'hostname': 'server-a',
        }


class TestDiscoveryServiceInit:
    """Tests for DiscoveryService initialization."""

    def test_default_service_name_includes_hostname(self):
        """Test that the default service name includes the machine hostname."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        hostname = socket.gethostname()
        assert hostname in svc._service_name  # pylint: disable=protected-access

    def test_custom_service_name(self):
        """Test that a custom service name is used."""
        svc = DiscoveryService(
            ws_port=8766, http_port=5001, service_name='TestService'
        )
        assert svc._service_name == 'TestService'  # pylint: disable=protected-access

    def test_instances_empty_initially(self):
        """Test that the discovered instances list starts empty."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        assert svc.get_instances() == []


class TestDiscoveryServiceGetInstances:
    """Tests for DiscoveryService.get_instances / get_instances_json."""

    def test_get_instances_returns_copy(self):
        """Test that get_instances returns a snapshot, not the internal dict."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        # Manually inject an instance
        inst = DiscoveredInstance(
            host='1.2.3.4', ws_port=8766, http_port=5001,
            version='1.0', hostname='test',
        )
        svc._instances['fake'] = inst  # pylint: disable=protected-access

        result = svc.get_instances()
        assert len(result) == 1
        assert result[0]['host'] == '1.2.3.4'

    def test_get_instances_json(self):
        """Test that get_instances_json returns valid JSON."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        inst = DiscoveredInstance(
            host='10.0.0.1', ws_port=1234, http_port=5678,
            version='3.0', hostname='box',
        )
        svc._instances['svc1'] = inst  # pylint: disable=protected-access

        raw = svc.get_instances_json()
        data = json.loads(raw)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['ws_port'] == 1234

    def test_get_instances_empty_json(self):
        """Test that empty instances returns empty JSON array."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        assert svc.get_instances_json() == '[]'


class TestDiscoveryServiceLifecycle:
    """Tests for start / stop lifecycle with mocked zeroconf."""

    @patch('lanscape.ui.react_proxy.discovery._get_local_addresses')
    @patch('lanscape.ui.react_proxy.discovery.ServiceBrowser')
    @patch('lanscape.ui.react_proxy.discovery.Zeroconf')
    @patch('lanscape.ui.react_proxy.discovery.get_installed_version', return_value='1.0.0')
    def test_start_registers_and_browses(
        self, _mock_version, mock_zc_cls, mock_browser_cls, mock_addrs
    ):
        """Test that start() registers the service and creates a browser."""
        mock_addrs.return_value = [socket.inet_aton('192.168.1.10')]
        mock_zc = mock_zc_cls.return_value

        svc = DiscoveryService(ws_port=8766, http_port=5001, service_name='Test')
        svc.start()

        mock_zc.register_service.assert_called_once()
        registered_info = mock_zc.register_service.call_args[0][0]
        assert SERVICE_TYPE in registered_info.type
        # Verify addresses are passed to ServiceInfo
        assert registered_info.addresses is not None
        assert socket.inet_aton('192.168.1.10') in registered_info.addresses

        mock_browser_cls.assert_called_once()
        assert mock_browser_cls.call_args[0][1] == SERVICE_TYPE

    @patch('lanscape.ui.react_proxy.discovery._get_local_addresses')
    @patch('lanscape.ui.react_proxy.discovery.ServiceBrowser')
    @patch('lanscape.ui.react_proxy.discovery.Zeroconf')
    @patch('lanscape.ui.react_proxy.discovery.get_installed_version', return_value='1.0.0')
    def test_start_registers_and_browses_no_addrs(
        self, _mock_version, mock_zc_cls, _mock_browser_cls, mock_addrs
    ):
        """Test that start() still registers even with no local addresses."""
        mock_addrs.return_value = []
        mock_zc = mock_zc_cls.return_value

        svc = DiscoveryService(ws_port=8766, http_port=5001, service_name='Test')
        svc.start()

        mock_zc.register_service.assert_called_once()

    @patch('lanscape.ui.react_proxy.discovery._get_local_addresses')
    @patch('lanscape.ui.react_proxy.discovery.ServiceBrowser')
    @patch('lanscape.ui.react_proxy.discovery.Zeroconf')
    @patch('lanscape.ui.react_proxy.discovery.get_installed_version', return_value='1.0.0')
    def test_stop_unregisters_and_closes(
        self, _mock_version, mock_zc_cls, _mock_browser_cls, mock_addrs
    ):
        """Test that stop() unregisters the service and closes zeroconf."""
        mock_addrs.return_value = [socket.inet_aton('10.0.0.1')]
        mock_zc = mock_zc_cls.return_value

        svc = DiscoveryService(ws_port=8766, http_port=5001, service_name='Test')
        svc.start()
        svc.stop()

        mock_zc.unregister_service.assert_called_once()
        mock_zc.close.assert_called_once()

    def test_stop_without_start_is_safe(self):
        """Test that calling stop() without start() doesn't raise."""
        svc = DiscoveryService(ws_port=8766, http_port=5001)
        svc.stop()  # Should not raise

    @patch('lanscape.ui.react_proxy.discovery._get_local_addresses')
    @patch('lanscape.ui.react_proxy.discovery.ServiceBrowser')
    @patch('lanscape.ui.react_proxy.discovery.Zeroconf')
    @patch('lanscape.ui.react_proxy.discovery.get_installed_version', return_value='1.0.0')
    def test_start_falls_back_to_unicast_on_eaddrinuse(
        self, _mock_version, mock_zc_cls, _mock_browser_cls, mock_addrs
    ):
        """Test that start() falls back to unicast mode when port 5353 is in use."""
        mock_addrs.return_value = [socket.inet_aton('192.168.1.10')]
        mock_zc_unicast = MagicMock()
        # First call (normal) raises EADDRINUSE, second call (unicast) succeeds
        mock_zc_cls.side_effect = [
            OSError(errno.EADDRINUSE, 'Address already in use'),
            mock_zc_unicast,
        ]

        svc = DiscoveryService(ws_port=8766, http_port=5001, service_name='Test')
        svc.start()

        # Verify Zeroconf was called twice: once normal, once unicast
        assert mock_zc_cls.call_count == 2
        first_call = mock_zc_cls.call_args_list[0]
        second_call = mock_zc_cls.call_args_list[1]
        assert first_call.kwargs.get('unicast', False) is False
        assert second_call.kwargs.get('unicast') is True

        # Service should still be registered and browser created
        mock_zc_unicast.register_service.assert_called_once()

    @patch('lanscape.ui.react_proxy.discovery.Zeroconf')
    def test_start_reraises_non_eaddrinuse(self, mock_zc_cls):
        """Test that start() re-raises OSError if not EADDRINUSE."""
        mock_zc_cls.side_effect = OSError(errno.EACCES, 'Permission denied')

        svc = DiscoveryService(ws_port=8766, http_port=5001)
        try:
            svc.start()
            assert False, 'Expected OSError'  # pragma: no cover
        except OSError as exc:
            assert exc.errno == errno.EACCES


class TestDiscoveryServiceBrowseCallback:
    """Tests for the internal _on_service_state_change callback."""

    def _make_service(self) -> DiscoveryService:
        """Create a DiscoveryService without starting it."""
        return DiscoveryService(ws_port=8766, http_port=5001, service_name='Test')

    def _make_mock_info(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        host: str = '192.168.1.50',
        ws_port: int = 8766,
        http_port: int = 5001,
        version: str = '1.0.0',
        hostname: str = 'test-host',
    ) -> MagicMock:
        """Create a mock ServiceInfo."""
        mock_info = MagicMock()
        mock_info.parsed_addresses.return_value = [host]
        mock_info.port = ws_port
        mock_info.properties = {
            b'ws_port': str(ws_port).encode(),
            b'http_port': str(http_port).encode(),
            b'version': version.encode(),
            b'hostname': hostname.encode(),
        }
        return mock_info

    def test_add_service(self):
        """Test that an Added event populates the instances dict."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = self._make_mock_info()

        svc._on_service_state_change(  # pylint: disable=protected-access
            mock_zc, SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Added,
        )

        instances = svc.get_instances()
        assert len(instances) == 1
        assert instances[0]['host'] == '192.168.1.50'

    def test_remove_service(self):
        """Test that a Removed event removes the instance."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()

        # Pre-populate
        svc._instances['test._lanscape._tcp.local.'] = DiscoveredInstance(  # pylint: disable=protected-access
            host='10.0.0.1', ws_port=8766, http_port=5001,
            version='1.0', hostname='x',
        )

        svc._on_service_state_change(  # pylint: disable=protected-access
            MagicMock(), SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Removed,
        )

        assert svc.get_instances() == []

    def test_no_addresses_skips(self):
        """Test that a service with no resolved addresses is ignored."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()
        mock_zc = MagicMock()
        mock_info = self._make_mock_info()
        mock_info.parsed_addresses.return_value = []
        mock_zc.get_service_info.return_value = mock_info

        svc._on_service_state_change(  # pylint: disable=protected-access
            mock_zc, SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Added,
        )

        assert svc.get_instances() == []

    def test_none_info_retries_then_skips(self):
        """Test that a None service info is retried 3 times then skipped."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None

        svc._on_service_state_change(  # pylint: disable=protected-access
            mock_zc, SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Added,
        )

        assert svc.get_instances() == []
        # Verify it retried 3 times
        assert mock_zc.get_service_info.call_count == 3

    def test_retry_succeeds_on_second_attempt(self):
        """Test that a service is resolved when retry succeeds."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()
        mock_zc = MagicMock()
        # First call returns None, second succeeds
        mock_zc.get_service_info.side_effect = [
            None, self._make_mock_info()
        ]

        svc._on_service_state_change(  # pylint: disable=protected-access
            mock_zc, SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Added,
        )

        instances = svc.get_instances()
        assert len(instances) == 1
        assert mock_zc.get_service_info.call_count == 2


class TestServiceType:
    """Tests for the service type constant."""

    def test_service_type_format(self):
        """Test that the service type follows DNS-SD conventions."""
        assert SERVICE_TYPE == '_lanscape._tcp.local.'
        assert SERVICE_TYPE.startswith('_')
        assert SERVICE_TYPE.endswith('.')


class TestDiscoverResponse:
    """Tests for the DiscoverResponse Pydantic model."""

    def test_defaults(self):
        """Test creating a response with no instances."""
        resp = DiscoverResponse(
            mdns_enabled=True,
            default_route='http://localhost:5001',
            instances=[],
        )
        assert resp.mdns_enabled is True
        assert resp.default_route == 'http://localhost:5001'
        assert resp.instances == []

    def test_with_instances(self):
        """Test creating a response with discovered instances."""
        inst = DiscoveredInstance(
            host='10.0.0.5',
            ws_port=8766,
            http_port=5001,
            version='2.0.0',
            hostname='my-server',
        )
        resp = DiscoverResponse(
            mdns_enabled=True,
            default_route='http://10.0.0.5:5001',
            instances=[inst],
        )
        assert len(resp.instances) == 1
        assert resp.instances[0].host == '10.0.0.5'

    def test_json_round_trip(self):
        """Test JSON serialization round-trip."""
        resp = DiscoverResponse(
            mdns_enabled=False,
            default_route='http://localhost:9999',
            instances=[],
        )
        data = json.loads(resp.model_dump_json())
        assert data['mdns_enabled'] is False
        assert data['default_route'] == 'http://localhost:9999'
        assert data['instances'] == []

    def test_mdns_disabled_flag(self):
        """Test that mdns_enabled=False is preserved."""
        resp = DiscoverResponse(
            mdns_enabled=False,
            default_route='http://localhost:5001',
            instances=[],
        )
        assert resp.mdns_enabled is False


class TestBuildDefaultRoute:
    """Tests for the build_default_route helper."""

    @patch('lanscape.ui.react_proxy.discovery.get_local_address_strings')
    def test_uses_first_lan_address(self, mock_addrs):
        """Test that the first LAN address is preferred."""
        mock_addrs.return_value = ['10.0.12.14', '192.168.1.5']
        result = build_default_route(5001)
        assert result == 'http://10.0.12.14:5001'

    @patch('lanscape.ui.react_proxy.discovery.get_local_address_strings')
    def test_falls_back_to_localhost(self, mock_addrs):
        """Test fallback to localhost when no LAN addresses exist."""
        mock_addrs.return_value = []
        result = build_default_route(8080)
        assert result == 'http://localhost:8080'

    @patch('lanscape.ui.react_proxy.discovery.get_local_address_strings')
    def test_custom_port(self, mock_addrs):
        """Test that custom port is included in the route."""
        mock_addrs.return_value = ['192.168.1.100']
        result = build_default_route(9999)
        assert result == 'http://192.168.1.100:9999'
