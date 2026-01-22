"""
WebSocket handler for utility tools.

Provides handlers for:
- Subnet validation and listing
- Default configuration retrieval
"""

import traceback
from typing import Any, Callable, Optional

from lanscape.core.net_tools import get_all_network_subnets, is_arp_supported
from lanscape.core.ip_parser import parse_ip_input
from lanscape.core.errors import SubnetTooLargeError
from lanscape.core.scan_config import DEFAULT_CONFIGS
from lanscape.ui.ws.handlers.base import BaseHandler


class ToolsHandler(BaseHandler):
    """
    Handler for utility tool WebSocket actions.

    Supports actions:
    - tools.subnet_test: Validate a subnet string
    - tools.subnet_list: List all network subnets on the system
    - tools.config_defaults: Get default scan configurations
    - tools.arp_supported: Check if ARP is supported on this system
    """

    def __init__(self):
        """Initialize the tools handler."""
        super().__init__()

        # Register handlers
        self.register('subnet_test', self._handle_subnet_test)
        self.register('subnet_list', self._handle_subnet_list)
        self.register('config_defaults', self._handle_config_defaults)
        self.register('arp_supported', self._handle_arp_supported)

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

        Returns:
            List of subnet information or error dict
        """
        try:
            return get_all_network_subnets()
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
        arp_supported = is_arp_supported()

        configs = {}
        for key, config in DEFAULT_CONFIGS.items():
            config_dict = config.to_dict()

            if not arp_supported:
                lookup_types = list(config_dict.get('lookup_type') or [])
                if 'ARP_LOOKUP' in lookup_types:
                    lookup_types = [lt for lt in lookup_types if lt != 'ARP_LOOKUP']
                    if 'POKE_THEN_ARP' not in lookup_types:
                        lookup_types.append('POKE_THEN_ARP')
                    config_dict['lookup_type'] = lookup_types

            configs[key] = config_dict

        return configs

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
