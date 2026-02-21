"""
Tests for mDNS discovery module.
"""
import json
import socket
from unittest.mock import MagicMock, patch

from lanscape.ui.react_proxy.discovery import (
    DiscoveredInstance,
    DiscoveryService,
    SERVICE_TYPE,
    _get_local_addresses,
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
        assert result == []

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
        assert result == []

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_down_interfaces(self, mock_psutil):
        """Test that down interfaces are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=False),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='192.168.1.50')
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert result == []

    @patch('lanscape.ui.react_proxy.discovery.psutil')
    def test_skips_link_local(self, mock_psutil):
        """Test that link-local addresses are excluded."""
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
        }
        mock_addr = MagicMock(family=socket.AF_INET, address='169.254.1.1')
        mock_psutil.net_if_addrs.return_value = {'eth0': [mock_addr]}

        result = _get_local_addresses()
        assert result == []


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

    def test_none_info_skips(self):
        """Test that a None service info is ignored."""
        from zeroconf import ServiceStateChange  # pylint: disable=import-outside-toplevel
        svc = self._make_service()
        mock_zc = MagicMock()
        mock_zc.get_service_info.return_value = None

        svc._on_service_state_change(  # pylint: disable=protected-access
            mock_zc, SERVICE_TYPE, 'test._lanscape._tcp.local.',
            ServiceStateChange.Added,
        )

        assert svc.get_instances() == []


class TestServiceType:
    """Tests for the service type constant."""

    def test_service_type_format(self):
        """Test that the service type follows DNS-SD conventions."""
        assert SERVICE_TYPE == '_lanscape._tcp.local.'
        assert SERVICE_TYPE.startswith('_')
        assert SERVICE_TYPE.endswith('.')
