"""
LANscape React Proxy Module - Serves the React UI without requiring Node.js.

This module downloads and caches the pre-built React webapp from GitHub releases,
then serves it locally alongside the WebSocket API endpoints.

Version compatibility is enforced via SUPPORTED_UI_VERSIONS to ensure the
downloaded webapp is compatible with this version of the Python backend.
"""

from lanscape.ui.react_proxy.manager import WebappManager
from lanscape.ui.react_proxy.server import start_webapp_server
from lanscape.ui.react_proxy.version_compat import (
    SUPPORTED_UI_VERSIONS,
    VersionRange,
    is_version_compatible,
    get_supported_range
)

__all__ = [
    'WebappManager',
    'start_webapp_server',
    'SUPPORTED_UI_VERSIONS',
    'VersionRange',
    'is_version_compatible',
    'get_supported_range'
]
