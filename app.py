from flask import Flask, request, jsonify,render_template
from libraries.port_manager import PortManager
from libraries.subnet_scan import SubnetScanner

import traceback

app = Flask(__name__)

# Port Manager API
############################################
@app.route('/api/port/list', methods=['GET'])
def get_port_lists():
    return jsonify(PortManager().get_port_lists())

@app.route('/api/port/list/<port_list>', methods=['GET'])
def get_port_list(port_list):
    return jsonify(PortManager().get_port_list(port_list))

@app.route('/api/port/list/<port_list>', methods=['POST'])
def create_port_list(port_list):
    data = request.get_json()
    return jsonify(PortManager().create_port_list(port_list, data))

@app.route('/api/port/list/<port_list>', methods=['PUT'])
def update_port_list(port_list):
    data = request.get_json()
    return jsonify(PortManager().update_port_list(port_list, data))

@app.route('/api/port/list/<port_list>', methods=['DELETE'])
def delete_port_list(port_list):
    return jsonify(PortManager().delete_port_list(port_list))

# Subnet Scanner API
############################################
@app.route('/api/scan', methods=['POST'])
def scan_subnet():
    data = request.get_json()

    try:
        scanner = SubnetScanner(
            data['subnet'], 
            data['port_list'],
            parallelism=data.get('parallelism', 1.0)
        )
        scanner.scan_subnet_threaded()
        return jsonify({'status': 'running', 'scan_id': scanner.uid})
    except:
        return jsonify({'status': 'error', 'traceback': traceback.format_exc()}), 500
    
@app.route('/api/scan/async', methods=['POST'])
def scan_subnet_async():
    data = request.get_json()

    scanner = SubnetScanner(data['subnet'], data['port_list'])
    scanner.scan_subnet()
    return jsonify({'status': 'complete', 'scan_id': scanner.uid})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = SubnetScanner.get_scan(scan_id)
    return jsonify(scan)

# Template Renderer
############################################
@app.route('/scan/<scan_id>', methods=['GET'])
def render_scan(scan_id):
    data = SubnetScanner.get_scan(scan_id)
    return render_template('scan.html', data=data) 