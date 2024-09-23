from flask import request, jsonify
from . import api_bp
from ...libraries.net_tools import get_all_network_subnets
from ...libraries.ip_parser import parse_ip_input, SubnetTooLargeError
import traceback


@api_bp.route('/api/tools/subnet/test')
def test_subnet():
    subnet = request.args.get('subnet')
    if not subnet: return jsonify({'valid': False, 'msg': 'Subnet cannot be blank'})
    try:
        ips = parse_ip_input(subnet)
        length = len(ips)
        return jsonify({'valid': True, 'msg': f"{length} IP{'s' if length > 1 else ''}"})
    except SubnetTooLargeError:
        return jsonify({'valid': False, 'msg': 'subnet too large', 'error': traceback.format_exc()})
    except:
        return jsonify({'valid': False, 'msg': 'invalid subnet', 'error': traceback.format_exc()})
    
@api_bp.route('/api/tools/subnet/list')
def list_subnet():
    """
    list all interface sunets
    """
    try: 
        return jsonify(get_all_network_subnets())
    except:
        return jsonify({'error': traceback.format_exc()})