"""
API endpoints for subnet testing and listing.
"""

import traceback
from flask import request, jsonify
from lanscape.ui.blueprints.api import api_bp
from lanscape.libraries.net_tools import get_all_network_subnets
from lanscape.libraries.ip_parser import parse_ip_input
from lanscape.libraries.errors import SubnetTooLargeError
from lanscape.libraries.scan_config import DEFAULT_CONFIGS


@api_bp.route('/api/tools/subnet/test')
def test_subnet():
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
    """
    return jsonify(
        {key: config.to_dict() for key, config in DEFAULT_CONFIGS.items()}
    )
