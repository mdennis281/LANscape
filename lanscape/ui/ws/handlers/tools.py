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
from lanscape.core.auto_stages import (
    recommend_stages, _is_ipv6, _is_local_subnet, _matching_interface,
)
from lanscape.core.scan_config import (
    get_default_configs_with_arp_fallback, get_stage_config_defaults
)
from lanscape.core.stage_presets import get_stage_presets
from lanscape.core.stage_estimates import estimate_stage_time
from lanscape.core.models.enums import StageType
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
    - tools.stage_defaults: Get default per-stage configurations
    - tools.stage_presets: Get fast/balanced/accurate presets per stage
    - tools.stage_estimate: Estimate time for one unit of work
    - tools.arp_supported: Check if ARP is supported on this system
    - tools.app_info: Get app version, runtime args
    - tools.auto_stages: Recommend scan stages for a subnet
    - tools.update_check: Check for available updates
    """

    def __init__(self):
        """Initialize the tools handler."""
        super().__init__()

        # Register handlers
        self.register('subnet_test', self._handle_subnet_test)
        self.register('subnet_list', self._handle_subnet_list)
        self.register('auto_stages', self._handle_auto_stages)
        self.register('config_defaults', self._handle_config_defaults)
        self.register('stage_defaults', self._handle_stage_defaults)
        self.register('stage_presets', self._handle_stage_presets)
        self.register('stage_estimate', self._handle_stage_estimate)
        self.register('arp_supported', self._handle_arp_supported)
        self.register('app_info', self._handle_app_info)
        self.register('update_check', self._handle_update_check)

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
                'count': length,
                'is_ipv6': _is_ipv6(subnet),
                'is_local': _is_local_subnet(subnet),
                'matching_interface': _matching_interface(subnet),
            }
        except SubnetTooLargeError as e:
            return {
                'valid': False,
                'msg': f'subnet too large ({e.count:,} IPs)',
                'error': traceback.format_exc(),
                'count': e.count
            }
        except Exception:
            return {
                'valid': False,
                'msg': 'invalid subnet',
                'error': traceback.format_exc(),
                'count': -1
            }

    def _handle_auto_stages(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Recommend scan stages for a subnet based on system context.

        Params:
            subnet: The target subnet string

        Returns:
            Dict with 'stages' list of recommended stage configs
        """
        subnet = self._get_param(params, 'subnet')
        if not subnet:
            return {'stages': [], 'error': 'subnet is required'}

        try:
            recommendations = recommend_stages(
                subnet=subnet,
                arp_supported=is_arp_supported(),
            )
            return {
                'stages': [r.to_dict() for r in recommendations],
            }
        except Exception:
            return {'stages': [], 'error': traceback.format_exc()}

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

        When ``arp_supported`` is passed in *params* as ``false``, the
        returned presets replace ARP-only stages with fallback equivalents.
        Defaults to ``True`` so the first (fast) call assumes ARP works;
        the frontend re-fetches after the real ARP check if needed.

        Returns:
            Dict of preset name -> ScanConfig dict
        """
        arp_supported = params.get('arp_supported', True)
        return get_default_configs_with_arp_fallback(arp_supported)

    def _handle_stage_defaults(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get the default configuration for each stage type.

        Returns:
            Dict of stage_type -> default config dict
        """
        return get_stage_config_defaults()

    def _handle_stage_presets(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get fast/balanced/accurate preset configs for each stage type.

        Returns:
            Dict of stage_type -> {preset_name -> config dict}
        """
        return get_stage_presets()

    def _handle_stage_estimate(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Estimate worst-case time for one unit of work in a stage.

        Params:
            stage_type: The stage type string
            config: The stage config dict

        Returns:
            Dict with 'seconds' float
        """
        stage_type_str = self._get_param(params, 'stage_type')
        config = params.get('config', {})
        try:
            st = StageType(stage_type_str)
            seconds = estimate_stage_time(st, config)
            return {'seconds': seconds}
        except Exception:
            return {'error': traceback.format_exc()}

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
        Get application info (fast path — no network or ARP calls).

        Expensive checks (ARP support, update availability) are deferred
        to ``tools.capabilities`` so the UI can render immediately.

        Returns:
            Dict with app info:
            - name: Application name
            - version: Current installed version
            - runtime_args: Dict of current runtime arguments
        """
        args = parse_args()

        # Build runtime args dict (excluding None values)
        runtime_args = {
            'ui_port': args.ui_port,
            'ws_port': args.ws_port,
            'loglevel': args.loglevel,
            'persistent': args.persistent,
        }
        if args.logfile:
            runtime_args['logfile'] = args.logfile

        return {
            'name': 'LANscape',
            'version': get_installed_version(),
            'runtime_args': runtime_args,
        }

    def _handle_update_check(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Check for available updates on PyPI.

        Returns:
            Dict with:
            - update_available: Whether a newer version exists on PyPI
            - latest_version: Latest version string (or None)
        """
        try:
            return {
                'update_available': is_update_available(),
                'latest_version': get_latest_version(),
            }
        except Exception:  # pylint: disable=broad-exception-caught
            return {
                'update_available': False,
                'latest_version': None,
            }
