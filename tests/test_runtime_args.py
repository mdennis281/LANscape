"""Tests for runtime argument parsing."""

import sys
from unittest.mock import patch

import pytest
from lanscape.core.runtime_args import parse_args, was_port_explicit, was_ws_port_explicit


class TestParseArgsDefaults:
    """Tests for default argument values."""

    def test_defaults(self) -> None:
        """Default values are returned when no args provided."""
        with patch.object(sys, 'argv', ['lanscape']):
            args = parse_args()
        assert args.ui_port == 5001
        assert args.logfile is None
        assert args.loglevel == 'INFO'
        assert args.persistent is False
        assert args.ws_server is False
        assert args.ws_port == 8766
        assert args.mdns_enabled is True


class TestParseArgsCustom:
    """Tests for explicitly provided arguments."""

    def test_custom_ui_port(self) -> None:
        """--ui-port sets the ui_port value."""
        with patch.object(sys, 'argv', ['lanscape', '--ui-port', '9090']):
            args = parse_args()
        assert args.ui_port == 9090

    def test_logfile(self) -> None:
        """--logfile sets the logfile path."""
        with patch.object(sys, 'argv', ['lanscape', '--logfile', '/tmp/test.log']):
            args = parse_args()
        assert args.logfile == '/tmp/test.log'

    def test_loglevel(self) -> None:
        """--loglevel sets log level (uppercased)."""
        with patch.object(sys, 'argv', ['lanscape', '--loglevel', 'warning']):
            args = parse_args()
        assert args.loglevel == 'WARNING'

    def test_persistent(self) -> None:
        """--persistent enables persistent mode."""
        with patch.object(sys, 'argv', ['lanscape', '--persistent']):
            args = parse_args()
        assert args.persistent is True

    def test_ws_server(self) -> None:
        """--ws-server enables websocket-only mode."""
        with patch.object(sys, 'argv', ['lanscape', '--ws-server']):
            args = parse_args()
        assert args.ws_server is True

    def test_ws_port(self) -> None:
        """--ws-port sets the websocket port."""
        with patch.object(sys, 'argv', ['lanscape', '--ws-port', '9999']):
            args = parse_args()
        assert args.ws_port == 9999

    def test_debug_sets_loglevel(self) -> None:
        """--debug overrides loglevel to DEBUG."""
        with patch.object(sys, 'argv', ['lanscape', '--debug']):
            args = parse_args()
        assert args.loglevel == 'DEBUG'

    def test_debug_defaults_false(self) -> None:
        """debug defaults to False when --debug is not provided."""
        with patch.object(sys, 'argv', ['lanscape']):
            args = parse_args()
        assert args.debug is False

    def test_debug_flag_sets_debug_true(self) -> None:
        """--debug sets args.debug to True."""
        with patch.object(sys, 'argv', ['lanscape', '--debug']):
            args = parse_args()
        assert args.debug is True

    def test_mdns_off(self) -> None:
        """--mdns-off disables mDNS discovery."""
        with patch.object(sys, 'argv', ['lanscape', '--mdns-off']):
            args = parse_args()
        assert args.mdns_enabled is False

    def test_invalid_loglevel_raises(self) -> None:
        """Invalid log level raises ValueError."""
        with patch.object(sys, 'argv', ['lanscape', '--loglevel', 'INVALID']):
            with pytest.raises(ValueError, match="Invalid log level"):
                parse_args()


class TestVersionFlag:
    """Tests for the --version flag."""

    def test_version_prints_and_exits(self) -> None:
        """--version prints version string and exits."""
        with patch.object(sys, 'argv', ['lanscape', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code == 0

    def test_version_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--version output contains 'LANscape v'."""
        with patch.object(sys, 'argv', ['lanscape', '--version']):
            with pytest.raises(SystemExit):
                parse_args()
        captured = capsys.readouterr()
        assert 'LANscape v' in captured.out


class TestExplicitPortChecks:
    """Tests for was_port_explicit and was_ws_port_explicit."""

    def test_port_not_explicit(self) -> None:
        """was_port_explicit returns False when --ui-port not in argv."""
        with patch.object(sys, 'argv', ['lanscape']):
            assert was_port_explicit() is False

    def test_port_explicit(self) -> None:
        """was_port_explicit returns True when --ui-port is in argv."""
        with patch.object(sys, 'argv', ['lanscape', '--ui-port', '8080']):
            assert was_port_explicit() is True

    def test_ws_port_not_explicit(self) -> None:
        """was_ws_port_explicit returns False when --ws-port not in argv."""
        with patch.object(sys, 'argv', ['lanscape']):
            assert was_ws_port_explicit() is False

    def test_ws_port_explicit(self) -> None:
        """was_ws_port_explicit returns True when --ws-port is in argv."""
        with patch.object(sys, 'argv', ['lanscape', '--ws-port', '9000']):
            assert was_ws_port_explicit() is True
