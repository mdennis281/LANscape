"""Tests for the scan WebSocket handler — scan.history action."""
# pylint: disable=missing-function-docstring,protected-access

from unittest.mock import MagicMock
from lanscape.ui.ws.handlers.scan import ScanHandler


def _make_scan(uid: str, running: bool = False) -> MagicMock:
    """Create a minimal mock SubnetScanner."""
    scan = MagicMock()
    scan.uid = uid
    scan.running = running
    return scan


class TestScanHistory:
    """scan.history endpoint returns scan IDs in reverse order."""

    def test_empty_history(self):
        mgr = MagicMock()
        mgr.scans = []
        handler = ScanHandler(scan_manager=mgr)

        result = handler._handle_history({})
        assert result == {'scan_ids': []}

    def test_single_scan(self):
        mgr = MagicMock()
        mgr.scans = [_make_scan('aaa')]
        handler = ScanHandler(scan_manager=mgr)

        result = handler._handle_history({})
        assert result == {'scan_ids': ['aaa']}

    def test_multiple_scans_newest_first(self):
        mgr = MagicMock()
        mgr.scans = [
            _make_scan('first'),
            _make_scan('second'),
            _make_scan('third'),
        ]
        handler = ScanHandler(scan_manager=mgr)

        result = handler._handle_history({})
        assert result == {'scan_ids': ['third', 'second', 'first']}

    def test_history_ignores_params(self):
        mgr = MagicMock()
        mgr.scans = [_make_scan('x')]
        handler = ScanHandler(scan_manager=mgr)

        result = handler._handle_history({'bogus': 'value'})
        assert result == {'scan_ids': ['x']}
