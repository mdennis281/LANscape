from flask import render_template, request
from . import web_bp
from ...libraries.subnet_scan import SubnetScanner
from ...libraries.net_tools import get_primary_network_subnet

# Template Renderer
############################################
@web_bp.route('/', methods=['GET'])
def index():
    subnet = get_primary_network_subnet()
    port_list = 'medium'
    parallelism = 1.0
    if request.args.get('scan_id'):
        scan = SubnetScanner.get_scan(request.args.get('scan_id'))
        subnet = scan['subnet']
        port_list = scan['port_list']
        parallelism = scan['parallelism']
    return render_template(
        'main.html',
        subnet=subnet, 
        port_list=port_list, 
        parallelism=parallelism
    )

@web_bp.route('/scan/<scan_id>', methods=['GET'])
@web_bp.route('/scan/<scan_id>/<section>', methods=['GET'])
def render_scan(scan_id, section='all'):
    data = SubnetScanner.get_scan(scan_id)
    filter = request.args.get('filter')
    return render_template('scan.html', data=data, section=section, filter=filter)

