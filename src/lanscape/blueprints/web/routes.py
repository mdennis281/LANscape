from flask import render_template, request
from . import web_bp
from ...libraries.subnet_scan import SubnetScanner
from ...libraries.net_tools import get_network_subnet, get_all_network_subnets
from .. import scan_manager
import os

# Template Renderer
############################################
@web_bp.route('/', methods=['GET'])
def index():
    subnet = get_network_subnet()
    subnets = get_all_network_subnets()
    port_list = 'medium'
    parallelism = 0.7
    if scan_id := request.args.get('scan_id'):
        scanner = scan_manager.get_scan(scan_id)
        scan = scanner.results.export()
        subnet = scan['subnet']
        port_list = scan['port_list']
        parallelism = scan['parallelism']
    return render_template(
        'main.html',
        subnet=subnet, 
        port_list=port_list, 
        parallelism=parallelism,
        alternate_subnets=subnets
    )

@web_bp.route('/scan/<scan_id>', methods=['GET'])
@web_bp.route('/scan/<scan_id>/<section>', methods=['GET'])
def render_scan(scan_id, section='all'):
    scanner = scan_manager.get_scan(scan_id)
    data = scanner.results.export()
    filter = request.args.get('filter')
    return render_template('scan.html', data=data, section=section, filter=filter)

@web_bp.route('/errors/<scan_id>')
def view_errors(scan_id):
    scanner = scan_manager.get_scan(scan_id)
    data = scanner.results.export()
    return render_template('scan/scan-error.html',data=data)

@web_bp.route('/shutdown-ui')
def shutdown_ui():
    return render_template('shutdown.html')

@web_bp.route('/info')
def app_info():
    return render_template('info.html')