from flask import request, jsonify
from . import api_bp
from libraries.subnet_scan import SubnetScanner
import traceback

# Subnet Scanner API
############################################
@api_bp.route('/api/scan', methods=['POST'])
def scan_subnet():
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
