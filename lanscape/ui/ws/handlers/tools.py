"""
WebSocket handler for utility tools.

Provides handlers for:
- Subnet validation and listing
- Default configuration retrieval
- App info (version, runtime args)
"""

import traceback
from typing import Any, Callable, Optional

from lanscape.core.net_tools import (
    get_all_network_subnets, is_arp_supported, smart_select_primary_subnet
)
from lanscape.core.ip_parser import parse_ip_input
from lanscape.core.errors import SubnetTooLargeError
from lanscape.core.scan_config import get_default_configs_with_arp_fallback
from lanscape.core.version_manager import (
    get_installed_version, is_update_available, get_latest_version
)
from lanscape.core.runtime_args import parse_args
from lanscape.ui.ws.handlers.base import BaseHandler


class ToolsHandler(BaseHandler):
    """
    Handler for utility tool WebSocket actions.

    Supports actions:
    - tools.subnet_test: Validate a subnet string
    - tools.subnet_list: List all network subnets on the system
    - tools.config_defaults: Get default scan configurations
    - tools.arp_supported: Check if ARP is supported on this system
    - tools.app_info: Get app version, runtime args, and update status
    """

    def __init__(self):
        """Initialize the tools handler."""
        super().__init__()

        # Register handlers
        self.register('subnet_test', self._handle_subnet_test)
        self.register('subnet_list', self._handle_subnet_list)
        self.register('config_defaults', self._handle_config_defaults)
        self.register('arp_supported', self._handle_arp_supported)
        self.register('app_info', self._handle_app_info)

    @property
    def prefix(self) -> str:
        """Return the action prefix for this handler."""
        return 'tools'

    def _handle_subnet_test(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Validate a subnet string.

        Params:
            subnet: The subnet string to validate

        Returns:
            Dict with 'valid', 'msg', and 'count' fields
        """
        subnet = self._get_param(params, 'subnet')

        if not subnet:
            return {'valid': False, 'msg': 'Subnet cannot be blank', 'count': -1}

        try:
            ips = parse_ip_input(subnet)
            length = len(ips)
            return {
                'valid': True,
                'msg': f"{length} IP{'s' if length > 1 else ''}",
                'count': length
            }
        except SubnetTooLargeError:
            return {
                'valid': False,
                'msg': 'subnet too large',
                'error': traceback.format_exc(),
                'count': -1
            }
        except Exception:
            return {
                'valid': False,
                'msg': 'invalid subnet',
                'error': traceback.format_exc(),
                'count': -1
            }

    def _handle_subnet_list(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> list | dict:
        """
        List all network subnets on the system.

        The primary subnet (as determined by :func:`smart_select_primary_subnet`)
        is moved to the front of the list so the UI can default to it.

        Returns:
            List of subnet information or error dict
        """
        try:
            subnets = get_all_network_subnets()
            primary = smart_select_primary_subnet(subnets)
            if primary:
                subnets.sort(key=lambda s: s.get('subnet') != primary)
            return subnets
        except Exception:
            return {'error': traceback.format_exc()}

    def _handle_config_defaults(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get default scan configurations.

        Adjusts presets that rely on ARP_LOOKUP when ARP is not supported.

        Returns:
            Dict of preset name -> ScanConfig dict
        """
        return get_default_configs_with_arp_fallback(is_arp_supported())

    def _handle_arp_supported(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Check if ARP is supported on this system.

        Returns:
            Dict with 'supported' boolean
        """
        return {'supported': is_arp_supported()}

    def _handle_app_info(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get application info including version, runtime args, and update status.

        Returns:
            Dict with app info:
            - name: Application name
            - version: Current installed version
            - arp_supported: Whether ARP is supported
            - update_available: Whether an update is available
            - latest_version: Latest available version (if update available)
            - runtime_args: Dict of current runtime arguments
        """
        args = parse_args()

        # Build runtime args dict (excluding None values)
        runtime_args = {
            'port': args.port,
            'ws_port': args.ws_port,
            'loglevel': args.loglevel,
            'persistent': args.persistent,
        }
        if args.logfile:
            runtime_args['logfile'] = args.logfile

        result = {
            'name': 'LANscape',
            'version': get_installed_version(),
            'arp_supported': is_arp_supported(),
            'runtime_args': runtime_args,
        }

        # Check for updates (safely)
        try:
            result['update_available'] = is_update_available()
            result['latest_version'] = get_latest_version()
        except Exception:
            result['update_available'] = False
            result['latest_version'] = None

        return result
