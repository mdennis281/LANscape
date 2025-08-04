from lanscape.ui.blueprints.api import api_bp
from lanscape.libraries.subnet_scan import ScanConfig
from lanscape.ui.blueprints import scan_manager

from flask import request, jsonify
import json
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
    except BaseException:
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
    # cast to str and back to handle custom JSON serialization
    return jsonify(json.loads(scan.results.export(str)))


@api_bp.route('/api/scan/<scan_id>/summary', methods=['GET'])
def get_scan_summary(scan_id):
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'scan not found'}), 404
    return jsonify({
        'running': scan.running,
        'percent_complete': scan.calc_percent_complete(),
        'stage': scan.results.stage,
        'runtime': scan.results.get_runtime(),
        'devices': {
            'scanned': scan.results.devices_scanned,
            'alive': len(scan.results.devices),
            'total': scan.results.devices_total
        }
    })


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
    return ScanConfig.from_dict(data)
