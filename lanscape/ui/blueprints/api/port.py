from flask import request, jsonify
from lanscape.ui.blueprints.api import api_bp
from lanscape.libraries.port_manager import PortManager

# Port Manager API
############################################


@api_bp.route('/api/port/list', methods=['GET'])
def get_port_lists():
    return jsonify(PortManager().get_port_lists())


@api_bp.route('/api/port/list/<port_list>', methods=['GET'])
def get_port_list(port_list):
    return jsonify(PortManager().get_port_list(port_list))


@api_bp.route('/api/port/list/<port_list>', methods=['POST'])
def create_port_list(port_list):
    data = request.get_json()
    return jsonify(PortManager().create_port_list(port_list, data))


@api_bp.route('/api/port/list/<port_list>', methods=['PUT'])
def update_port_list(port_list):
    data = request.get_json()
    return jsonify(PortManager().update_port_list(port_list, data))


@api_bp.route('/api/port/list/<port_list>', methods=['DELETE'])
def delete_port_list(port_list):
    return jsonify(PortManager().delete_port_list(port_list))
