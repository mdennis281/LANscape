from flask import request, jsonify
from . import api_bp
from lanscape.libraries.net_tools import get_all_network_subnets
from lanscape.libraries.ip_parser import parse_ip_input
from lanscape.libraries.errors import SubnetTooLargeError
import traceback


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
    list all interface subets
    """
    try:
        return jsonify(get_all_network_subnets())
    except BaseException:
        return jsonify({'error': traceback.format_exc()})
