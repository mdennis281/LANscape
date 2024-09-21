from flask import request, jsonify
from . import api_bp
from ...libraries.subnet_scan import SubnetScanner
from ...libraries.ip_parser import parse_ip_input, SubnetTooLargeError
import traceback

# Subnet Scanner API
############################################
@api_bp.route('/api/scan', methods=['POST'])
@api_bp.route('/api/scan/threaded', methods=['POST'])
def scan_subnet_threaded():
    try:
        data = request.get_json()

        scanner = SubnetScanner(
            data['subnet'], 
            data['port_list'], 
            data.get('parallelism', 1.0)
        )
        scanner.scan_subnet_threaded()

        return jsonify({'status': 'running', 'scan_id': scanner.uid})
    except:
        return jsonify({'status': 'error', 'traceback': traceback.format_exc()}), 500


@api_bp.route('/api/scan/standalone', methods=['POST'])
def scan_subnet_standalone():
    data = request.get_json()

    try:
        uid = SubnetScanner.scan_subnet_standalone(
            data['subnet'], 
            data['port_list'],
            float(data.get('parallelism', 1.0))
        )

        return jsonify({'status': 'running', 'scan_id': uid})
    except:
        return jsonify({'status': 'error', 'traceback': traceback.format_exc()}), 500
    

@api_bp.route('/api/scan/async', methods=['POST'])
def scan_subnet_async():
    data = request.get_json()

    scanner = SubnetScanner(
        data['subnet'], 
        data['port_list'], 
        data.get('parallelism', 1.0)
    )
    scanner.scan_subnet()
    return jsonify({'status': 'complete', 'scan_id': scanner.uid})

@api_bp.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = SubnetScanner.get_scan(scan_id)
    return jsonify(scan)

@api_bp.route('/api/scan/subnet/test')
def test_subnet():
    subnet = request.args.get('subnet')
    if not subnet: return jsonify({'valid': False, 'msg': 'Subnet cannot be blank'})
    try:
        ips = parse_ip_input(subnet)
        length = len(ips)
        return jsonify({'valid': True, 'msg': f'{length} IP{'s' if length > 1 else ''}'})
    except SubnetTooLargeError:
        return jsonify({'valid': False, 'msg': 'subnet too large', 'error': traceback.format_exc()})
    except:
        return jsonify({'valid': False, 'msg': 'invalid subnet', 'error': traceback.format_exc()})