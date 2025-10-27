"""
API endpoints for subnet testing and listing.
"""

import traceback
from flask import request, jsonify
from lanscape.ui.blueprints.api import api_bp
from lanscape.core.net_tools import get_all_network_subnets, is_arp_supported
from lanscape.core.ip_parser import parse_ip_input
from lanscape.core.errors import SubnetTooLargeError
from lanscape.core.scan_config import DEFAULT_CONFIGS


@api_bp.route('/api/tools/subnet/test')
def test_subnet():
    """check validity of a subnet"""
    subnet = request.args.get('subnet')
    if not subnet:
        return jsonify({'valid': False, 'msg': 'Subnet cannot be blank', 'count': -1})
    try:
        ips = parse_ip_input(subnet)
        length = len(ips)
        return jsonify({'valid': True,
                        'msg': f"{length} IP{'s' if length > 1 else ''}",
                        'count': length})
    except SubnetTooLargeError:
        return jsonify({'valid': False, 'msg': 'subnet too large',
                       'error': traceback.format_exc(), 'count': -1})
    except BaseException:
        return jsonify({'valid': False, 'msg': 'invalid subnet',
                       'error': traceback.format_exc(), 'count': -1})


@api_bp.route('/api/tools/subnet/list')
def list_subnet():
    """
    list all interface subnets
    """
    try:
        return jsonify(get_all_network_subnets())
    except BaseException:
        return jsonify({'error': traceback.format_exc()})


@api_bp.route('/api/tools/config/defaults')
def get_default_configs():
    """
    Get default scan configurations.

    When active ARP lookups are not supported on the host system, adjust any
    presets that rely on ``ARP_LOOKUP`` to use the ``POKE_THEN_ARP`` fallback
    instead. This keeps presets such as ``accurate`` usable without requiring
    frontend overrides.
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

    return jsonify(configs)

