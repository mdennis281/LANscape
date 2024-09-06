from flask import Flask, request, jsonify,render_template, request
from libraries.port_manager import PortManager
from libraries.subnet_scan import SubnetScanner
from libraries.net_tools import get_primary_network_subnet

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
        uid = SubnetScanner.scan_subnet_standalone(
            data['subnet'], 
            data['port_list'],
            float(data.get('parallelism', 1.0))
        )

        return jsonify({'status': 'running', 'scan_id': uid})
    except:
        return jsonify({'status': 'error', 'traceback': traceback.format_exc()}), 500
    

    
@app.route('/api/scan/async', methods=['POST'])
def scan_subnet_async():
    data = request.get_json()

    scanner = SubnetScanner(
        data['subnet'], 
        data['port_list'], 
        data.get('parallelism', 1.0)
    )
    scanner.scan_subnet()
    return jsonify({'status': 'complete', 'scan_id': scanner.uid})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = SubnetScanner.get_scan(scan_id)
    return jsonify(scan)

# Template Renderer
############################################
@app.route('/', methods=['GET'])
def index():
    return render_template('main.html',subnet=get_primary_network_subnet())    

def is_substring_in_values(results: dict, substring: str) -> bool:
    return any(substring.lower() in str(v).lower() for v in results.values()) if substring else True

app.jinja_env.filters['is_substring_in_values'] = is_substring_in_values

@app.route('/scan/<scan_id>', methods=['GET'])
@app.route('/scan/<scan_id>/<section>', methods=['GET'])
def render_scan(scan_id, section='all'):
    data = SubnetScanner.get_scan(scan_id)
    filter = request.args.get('filter')
    return render_template('scan.html', data=data,section=section,filter=filter) 