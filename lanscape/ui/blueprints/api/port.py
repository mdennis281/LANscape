"""
API endpoints for port list management in the LANscape application.
Provides CRUD operations for managing port lists used in network scans.
"""
from flask import request, jsonify
from lanscape.ui.blueprints.api import api_bp
from lanscape.libraries.port_manager import PortManager

# Port Manager API
############################################


@api_bp.route('/api/port/list', methods=['GET'])
def get_port_lists():
    """
    Get all available port lists.

    Returns:
        JSON array of port list names
    """
    return jsonify(PortManager().get_port_lists())


@api_bp.route('/api/port/list/<port_list>', methods=['GET'])
def get_port_list(port_list):
    """
    Get a specific port list by name.

    Args:
        port_list: Name of the port list to retrieve

    Returns:
        JSON object mapping port numbers to service names
    """
    return jsonify(PortManager().get_port_list(port_list))


@api_bp.route('/api/port/list/<port_list>', methods=['POST'])
def create_port_list(port_list):
    """
    Create a new port list.

    Args:
        port_list: Name for the new port list

    Returns:
        JSON response indicating success or failure
    """
    data = request.get_json()
    return jsonify(PortManager().create_port_list(port_list, data))


@api_bp.route('/api/port/list/<port_list>', methods=['PUT'])
def update_port_list(port_list):
    """
    Update an existing port list.

    Args:
        port_list: Name of the port list to update

    Returns:
        JSON response indicating success or failure
    """
    data = request.get_json()
    return jsonify(PortManager().update_port_list(port_list, data))


@api_bp.route('/api/port/list/<port_list>', methods=['DELETE'])
def delete_port_list(port_list):
    """
    Delete a port list.

    Args:
        port_list: Name of the port list to delete

    Returns:
        JSON response indicating success or failure
    """
    return jsonify(PortManager().delete_port_list(port_list))
