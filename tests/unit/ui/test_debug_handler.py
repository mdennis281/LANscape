"""Tests for the debug WebSocket handler — cache flush actions."""
# pylint: disable=missing-function-docstring

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from lanscape.ui.ws.handlers.debug import DebugHandler, _run_flush, _get_flush_commands


# ── _get_flush_commands ─────────────────────────────────────────────

class TestGetFlushCommands:
    """Platform-aware flush command selection."""

    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_windows_arp(self, mock_psutil):
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmds = _get_flush_commands(want_v6=False)
        assert len(cmds) == 1
        joined = ' '.join(cmds[0])
        assert 'RunAs' in joined
        assert 'arpcache' in joined

    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_windows_ndp(self, mock_psutil):
        mock_psutil.WINDOWS = True
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmds = _get_flush_commands(want_v6=True)
        assert len(cmds) == 1
        joined = ' '.join(cmds[0])
        assert 'RunAs' in joined
        assert 'ipv6' in joined

    @patch('lanscape.ui.ws.handlers.debug.shutil.which', return_value='/usr/sbin/ip')
    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_linux_arp(self, mock_psutil, _mock_which):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        cmds = _get_flush_commands(want_v6=False)
        assert any('ip' in cmd[0] for cmd in cmds)
        assert any('-4' in cmd for cmd in cmds)

    @patch('lanscape.ui.ws.handlers.debug.shutil.which', return_value='/usr/sbin/ip')
    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_linux_ndp(self, mock_psutil, _mock_which):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = True
        mock_psutil.MACOS = False
        cmds = _get_flush_commands(want_v6=True)
        assert any('-6' in cmd for cmd in cmds)

    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_macos_arp(self, mock_psutil):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True
        cmds = _get_flush_commands(want_v6=False)
        assert cmds[0][0] == 'arp'

    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_macos_ndp(self, mock_psutil):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = True
        cmds = _get_flush_commands(want_v6=True)
        assert cmds[0][0] == 'ndp'

    @patch('lanscape.ui.ws.handlers.debug.psutil')
    def test_unknown_platform(self, mock_psutil):
        mock_psutil.WINDOWS = False
        mock_psutil.LINUX = False
        mock_psutil.MACOS = False
        cmds = _get_flush_commands(want_v6=False)
        assert not cmds


# ── _run_flush ──────────────────────────────────────────────────────

class TestRunFlush:
    """Flush execution with success/failure paths."""

    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands', return_value=[])
    def test_no_commands_returns_error(self, _mock_cmds):
        result = _run_flush(want_v6=False)
        assert result['success'] is False
        assert 'ARP' in result['error']

    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands', return_value=[])
    def test_no_commands_ndp_label(self, _mock_cmds):
        result = _run_flush(want_v6=True)
        assert result['success'] is False
        assert 'NDP' in result['error']

    @patch('lanscape.ui.ws.handlers.debug.subprocess.run')
    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands',
           return_value=[['netsh', 'interface', 'ipv4', 'delete', 'arpcache']])
    def test_success(self, _mock_cmds, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = _run_flush(want_v6=False)
        assert result['success'] is True

    @patch('lanscape.ui.ws.handlers.debug.subprocess.run')
    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands',
           return_value=[['netsh', 'interface', 'ipv4', 'delete', 'arpcache']])
    def test_nonzero_exit(self, _mock_cmds, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr=b'Access denied'
        )
        result = _run_flush(want_v6=False)
        assert result['success'] is False
        assert 'details' in result
        assert any('Access denied' in d for d in result['details'])

    @patch('lanscape.ui.ws.handlers.debug.subprocess.run',
           side_effect=subprocess.TimeoutExpired(cmd='test', timeout=10))
    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands',
           return_value=[['fake', 'cmd']])
    def test_timeout(self, _mock_cmds, _mock_run):
        result = _run_flush(want_v6=False)
        assert result['success'] is False
        assert 'details' in result

    @patch('lanscape.ui.ws.handlers.debug.subprocess.run',
           side_effect=FileNotFoundError('not found'))
    @patch('lanscape.ui.ws.handlers.debug._get_flush_commands',
           return_value=[['missing_bin']])
    def test_file_not_found(self, _mock_cmds, _mock_run):
        result = _run_flush(want_v6=False)
        assert result['success'] is False
        assert 'details' in result


# ── DebugHandler integration ────────────────────────────────────────

class TestDebugHandlerActions:
    """DebugHandler registers and dispatches flush actions."""

    @pytest.fixture
    def handler(self):
        return DebugHandler()

    def test_registers_clear_arp(self, handler):
        assert handler.can_handle('debug.clear_arp')

    def test_registers_clear_ndp(self, handler):
        assert handler.can_handle('debug.clear_ndp')

    @patch('lanscape.ui.ws.handlers.debug._run_flush', return_value={'success': True})
    def test_clear_arp_invokes_flush(self, mock_flush, handler):
        result = handler.invoke('clear_arp')
        mock_flush.assert_called_once_with(want_v6=False)
        assert result['success'] is True

    @patch('lanscape.ui.ws.handlers.debug._run_flush', return_value={'success': True})
    def test_clear_ndp_invokes_flush(self, mock_flush, handler):
        result = handler.invoke('clear_ndp')
        mock_flush.assert_called_once_with(want_v6=True)
        assert result['success'] is True

    @patch('lanscape.ui.ws.handlers.debug._run_flush',
           return_value={'success': False, 'error': 'boom', 'details': ['x']})
    def test_clear_arp_returns_error(self, _mock_flush, handler):
        result = handler.invoke('clear_arp')
        assert result['success'] is False
        assert result['error'] == 'boom'
        assert result['details'] == ['x']
