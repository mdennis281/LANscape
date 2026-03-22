"""
Tests for the react_proxy module - serving the bundled React UI.
"""
import json
import shutil
import tempfile
import threading
import urllib.request
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from lanscape.ui.react_proxy.discovery import DiscoveredInstance
from lanscape.ui.react_proxy.server import (
    start_webapp_server,
    SPAHandler,
    WebappServerController,
    REACT_BUILD_DIR,
    start_static_server
)


@pytest.fixture
def temp_webapp_dir():
    """Create a temporary directory simulating a React build."""
    temp_dir = Path(tempfile.mkdtemp())
    # Create a minimal webapp structure
    (temp_dir / 'index.html').write_text('<html><body>Test</body></html>')
    (temp_dir / 'assets').mkdir()
    (temp_dir / 'assets' / 'main.js').write_text('console.log("test")')
    yield temp_dir
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def empty_dir():
    """Create an empty temporary directory."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


class TestReactBuildDir:
    """Tests for the bundled react_build directory constant."""

    def test_react_build_dir_is_path(self):
        """Test that REACT_BUILD_DIR is a Path object."""
        assert isinstance(REACT_BUILD_DIR, Path)

    def test_react_build_dir_points_to_react_build(self):
        """Test that REACT_BUILD_DIR points to the correct location."""
        assert REACT_BUILD_DIR.name == 'react_build'
        assert REACT_BUILD_DIR.parent.name == 'ui'


class TestStartWebappServer:
    """Tests for start_webapp_server function."""

    @patch('lanscape.ui.react_proxy.server.WebappServerController')
    def test_creates_missing_build_dir(self, mock_controller_cls, tmp_path):
        """Test that missing build directory is created (graceful degradation)."""
        fake_dir = tmp_path / 'nonexistent'
        with patch('lanscape.ui.react_proxy.server.REACT_BUILD_DIR', fake_dir):
            start_webapp_server()
            # Directory should be created
            assert fake_dir.exists()
            # Server should still start
            mock_controller_cls.assert_called_once()

    @patch('lanscape.ui.react_proxy.server.WebappServerController')
    def test_starts_with_empty_build_dir(self, mock_controller_cls, empty_dir):
        """Test that empty build directory logs warning but starts server."""
        with patch('lanscape.ui.react_proxy.server.REACT_BUILD_DIR', empty_dir):
            start_webapp_server()
            # Server should still start (will show error page)
            mock_controller_cls.assert_called_once()

    @patch('lanscape.ui.react_proxy.server.WebappServerController')
    def test_starts_controller_with_defaults(self, mock_controller_cls, temp_webapp_dir):
        """Test that server starts with correct default parameters."""
        with patch('lanscape.ui.react_proxy.server.REACT_BUILD_DIR', temp_webapp_dir):
            start_webapp_server()

        mock_controller_cls.assert_called_once_with(
            http_port=5001,
            ws_port=8766,
            host='127.0.0.1',
            persistent=False,
            mdns_enabled=True,
            debug_mode=False,
        )
        mock_controller_cls.return_value.start.assert_called_once_with(
            temp_webapp_dir, open_browser=True
        )

    @patch('lanscape.ui.react_proxy.server.WebappServerController')
    def test_starts_controller_with_custom_params(self, mock_controller_cls, temp_webapp_dir):
        """Test that custom parameters are passed through."""
        with patch('lanscape.ui.react_proxy.server.REACT_BUILD_DIR', temp_webapp_dir):
            start_webapp_server(
                http_port=8080,
                ws_port=9090,
                host='0.0.0.0',
                open_browser=False,
                persistent=True,
                mdns_enabled=False,
            )

        mock_controller_cls.assert_called_once_with(
            http_port=8080,
            ws_port=9090,
            host='0.0.0.0',
            persistent=True,
            mdns_enabled=False,
            debug_mode=False,
        )
        mock_controller_cls.return_value.start.assert_called_once_with(
            temp_webapp_dir, open_browser=False
        )

    @patch('lanscape.ui.react_proxy.server.WebappServerController')
    def test_no_force_download_parameter(self, _mock_controller_cls, temp_webapp_dir):
        """Test that force_download parameter no longer exists."""
        with patch('lanscape.ui.react_proxy.server.REACT_BUILD_DIR', temp_webapp_dir):
            with pytest.raises(TypeError):
                start_webapp_server(force_download=True)  # pylint: disable=unexpected-keyword-arg


class TestSPAHandler:
    """Tests for the SPA static file handler."""

    def test_spa_handler_exists(self):
        """Test that SPAHandler class is available."""
        assert SPAHandler is not None

    def test_spa_handler_inherits_simple_handler(self):
        """Test SPAHandler inherits from SimpleHTTPRequestHandler."""
        assert issubclass(SPAHandler, SimpleHTTPRequestHandler)


class TestWebappServerController:
    """Tests for WebappServerController."""

    def test_controller_init_defaults(self):
        """Test controller initializes with correct defaults."""
        controller = WebappServerController()
        assert controller.http_port == 5001
        assert controller.ws_port == 8766
        assert controller.host == '127.0.0.1'
        assert controller.persistent is False
        assert controller.mdns_enabled is True
        assert controller.debug_mode is False

    def test_controller_init_custom(self):
        """Test controller with custom parameters."""
        controller = WebappServerController(
            http_port=8080,
            ws_port=9090,
            host='0.0.0.0',
            persistent=True,
            mdns_enabled=False,
            debug_mode=True,
        )
        assert controller.http_port == 8080
        assert controller.ws_port == 9090
        assert controller.host == '0.0.0.0'
        assert controller.persistent is True
        assert controller.mdns_enabled is False
        assert controller.debug_mode is True


class TestStartStaticServer:
    """Tests for static server startup."""

    def test_start_static_server(self, temp_webapp_dir):
        """Test starting the static file server."""
        server = start_static_server(temp_webapp_dir, 0)  # port 0 = OS picks
        try:
            assert server is not None
            assert server.server_address[1] != 0  # Port was assigned
        finally:
            server.server_close()

    def test_start_static_server_custom_host(self, temp_webapp_dir):
        """Test starting static server with custom host."""
        server = start_static_server(temp_webapp_dir, 0, host='127.0.0.1')
        try:
            assert server.server_address[0] == '127.0.0.1'
        finally:
            server.server_close()


class TestCacheHeaders:
    """Tests for cache-control headers on served files."""

    @staticmethod
    def _make_server(temp_webapp_dir):
        """Start a test server and return (base_url, server, thread)."""
        server = start_static_server(temp_webapp_dir, 0)
        base_url = f'http://127.0.0.1:{server.server_address[1]}'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return base_url, server

    @staticmethod
    def _get_headers(base_url: str, path: str) -> dict:
        """Fetch a path and return the response headers as a dict."""
        with urllib.request.urlopen(f'{base_url}{path}') as resp:
            return dict(resp.headers)

    def test_index_html_no_cache(self, temp_webapp_dir):
        """Test that index.html has no-cache headers."""
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            headers = self._get_headers(base_url, '/index.html')
            assert 'no-cache' in headers.get('Cache-Control', '')
            assert 'no-store' in headers.get('Cache-Control', '')
            assert headers.get('Pragma') == 'no-cache'
        finally:
            server.shutdown()
            server.server_close()

    def test_assets_immutable_cache(self, temp_webapp_dir):
        """Test that /assets/* files have long-term immutable cache headers."""
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            headers = self._get_headers(base_url, '/assets/main.js')
            cache_control = headers.get('Cache-Control', '')
            assert 'immutable' in cache_control
            assert 'max-age=31536000' in cache_control
        finally:
            server.shutdown()
            server.server_close()

    def test_spa_fallback_no_cache(self, temp_webapp_dir):
        """Test that SPA fallback responses (unknown routes) have no-cache headers."""
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            headers = self._get_headers(base_url, '/some/random/route')
            assert 'no-cache' in headers.get('Cache-Control', '')
        finally:
            server.shutdown()
            server.server_close()


class TestDiscoverEndpoint:
    """Tests for the /api/discover endpoint."""

    @staticmethod
    def _make_server(temp_webapp_dir):
        """Start a test server and return (base_url, server)."""
        server = start_static_server(temp_webapp_dir, 0)
        base_url = f'http://127.0.0.1:{server.server_address[1]}'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return base_url, server

    def test_discover_returns_json(self, temp_webapp_dir):
        """Test that /api/discover returns valid JSON with expected keys."""
        SPAHandler.discovery = None
        SPAHandler.mdns_enabled = True
        SPAHandler.default_route = 'http://localhost:5001'
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/discover') as resp:
                data = json.loads(resp.read())
            assert 'mdns_enabled' in data
            assert 'default_route' in data
            assert 'instances' in data
            assert data['mdns_enabled'] is True
            assert data['default_route'] == 'http://localhost:5001'
            assert data['instances'] == []
        finally:
            server.shutdown()
            server.server_close()

    def test_discover_mdns_disabled(self, temp_webapp_dir):
        """Test that /api/discover reflects mdns_enabled=False."""
        SPAHandler.discovery = None
        SPAHandler.mdns_enabled = False
        SPAHandler.default_route = 'http://10.0.0.5:8080'
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/discover') as resp:
                data = json.loads(resp.read())
            assert data['mdns_enabled'] is False
            assert data['default_route'] == 'http://10.0.0.5:8080'
            assert data['instances'] == []
        finally:
            server.shutdown()
            server.server_close()

    def test_discover_with_instances(self, temp_webapp_dir):
        """Test that /api/discover includes discovered instances."""
        mock_discovery = MagicMock()
        mock_discovery.get_instances.return_value = [
            DiscoveredInstance(
                host='10.0.0.2',
                ws_port=8766,
                http_port=5001,
                version='1.0.0',
                hostname='test-host',
            ).model_dump()
        ]
        SPAHandler.discovery = mock_discovery
        SPAHandler.mdns_enabled = True
        SPAHandler.default_route = 'http://localhost:5001'
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/discover') as resp:
                data = json.loads(resp.read())
            assert len(data['instances']) == 1
            assert data['instances'][0]['host'] == '10.0.0.2'
            assert data['instances'][0]['hostname'] == 'test-host'
        finally:
            server.shutdown()
            server.server_close()
            SPAHandler.discovery = None


class TestVersionEndpoint:
    """Tests for the /api/version endpoint."""

    @staticmethod
    def _make_server(temp_webapp_dir):
        """Start a test server and return (base_url, server)."""
        server = start_static_server(temp_webapp_dir, 0)
        base_url = f'http://127.0.0.1:{server.server_address[1]}'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return base_url, server

    @pytest.fixture(autouse=True)
    def _reset_version_cache(self):
        """Clear the cached version between tests."""
        with patch.object(SPAHandler, '_cached_version', None):
            yield

    def test_version_returns_json_with_file(self, temp_webapp_dir):
        """Test that /api/version returns version.json contents."""
        version_data = {'version': '2026.03.19.12345', 'buildTime': '2026-03-19T00:00:00Z'}
        (temp_webapp_dir / 'version.json').write_text(json.dumps(version_data))
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/version') as resp:
                data = json.loads(resp.read())
            assert data['ui_version'] == '2026.03.19.12345'
            assert data['build_time'] == '2026-03-19T00:00:00Z'
        finally:
            server.shutdown()
            server.server_close()

    def test_version_fallback_when_missing(self, temp_webapp_dir):
        """Test that /api/version returns fallback when version.json is absent."""
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/version') as resp:
                data = json.loads(resp.read())
            assert data['ui_version'] == '0.0.0'
            assert data['build_time'] == ''
        finally:
            server.shutdown()
            server.server_close()

    def test_version_fallback_on_corrupt_json(self, temp_webapp_dir):
        """Test that /api/version returns fallback when version.json is invalid."""
        (temp_webapp_dir / 'version.json').write_text('NOT VALID JSON{{{')
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/version') as resp:
                data = json.loads(resp.read())
            assert data['ui_version'] == '0.0.0'
            assert data['build_time'] == ''
        finally:
            server.shutdown()
            server.server_close()

    def test_version_has_cors_headers(self, temp_webapp_dir):
        """Test that /api/version includes CORS headers."""
        base_url, server = self._make_server(temp_webapp_dir)
        try:
            with urllib.request.urlopen(f'{base_url}/api/version') as resp:
                headers = dict(resp.headers)
            assert headers.get('Access-Control-Allow-Origin') == '*'
        finally:
            server.shutdown()
            server.server_close()
