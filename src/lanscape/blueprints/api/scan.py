from . import api_bp
from ...libraries.subnet_scan import ScanConfig
from .. import scan_manager

from flask import request, jsonify
import traceback

# Subnet Scanner API
############################################
@api_bp.route('/api/scan', methods=['POST'])
@api_bp.route('/api/scan/threaded', methods=['POST'])
def scan_subnet_threaded():
    try:
        config = get_scan_config()
        scan = scan_manager.new_scan(config)

        return jsonify({'status': 'running', 'scan_id': scan.uid})
    except:
        return jsonify({'status': 'error', 'traceback': traceback.format_exc()}), 500
    

@api_bp.route('/api/scan/async', methods=['POST'])
def scan_subnet_async():
    config = get_scan_config()
    scan = scan_manager.new_scan(config)
    scan_manager.wait_until_complete(scan.uid)

    return jsonify({'status': 'complete', 'scan_id': scan.uid})

@api_bp.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = scan_manager.get_scan(scan_id)
    return jsonify(scan.results.export())

@api_bp.route('/api/scan/<scan_id>/terminate', methods=['GET'])
def terminate_scan(scan_id):
    scan = scan_manager.get_scan(scan_id)
    scan.terminate()
    return jsonify({'success': True})

def get_scan_config():
    """
    pulls config from the request body
    """
    data = request.get_json()
    return ScanConfig(
        subnet = data['subnet'],
        port_list= data['port_list'],
        parallelism=data.get('parallelism',1.0)
    )