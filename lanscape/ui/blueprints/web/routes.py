"""
Web blueprint routes for the LANscape application.
Handles UI views including the main dashboard, scan results, error display, and exports.
"""
from flask import render_template, request, redirect
from lanscape.ui.blueprints.web import web_bp
from lanscape.libraries.net_tools import (
    get_all_network_subnets,
    smart_select_primary_subnet
)
from lanscape.ui.blueprints import scan_manager, log

# Template Renderer
############################################


@web_bp.route('/', methods=['GET'])
def index():
    """
    Render the main application interface.

    Displays the primary network subnet selection interface and existing scan results.
    If a scan_id is provided, it loads the configuration from that scan.
    """
    subnets = get_all_network_subnets()
    subnet = smart_select_primary_subnet(subnets)

    port_list = 'medium'
    if scan_id := request.args.get('scan_id'):
        if scan := scan_manager.get_scan(scan_id):
            subnet = scan.cfg.subnet
            port_list = scan.cfg.port_list

        else:
            log.debug(f'Redirecting, scan {scan_id} doesnt exist in memory')
            return redirect('/')
    return render_template(
        'main.html',
        subnet=subnet,
        port_list=port_list,
        alternate_subnets=subnets
    )


@web_bp.route('/scan/<scan_id>', methods=['GET'])
@web_bp.route('/scan/<scan_id>/<section>', methods=['GET'])
def render_scan(scan_id, section='all'):
    """
    Render a specific scan result.

    Args:
        scan_id: Unique identifier for the scan
        section: Section of the scan results to display (default: 'all')

    Returns:
        Rendered scan template or redirect to home if scan not found
    """
    if scanner := scan_manager.get_scan(scan_id):
        data = scanner.results.export()
        filter_text = request.args.get('filter')
        return render_template('scan.html', data=data, section=section, filter=filter_text)
    log.debug(f'Redirecting, scan {scan_id} doesnt exist in memory')
    return redirect('/')


@web_bp.route('/errors/<scan_id>')
def view_errors(scan_id):
    """
    Display errors that occurred during a scan.

    Args:
        scan_id: Unique identifier for the scan

    Returns:
        Rendered error template or redirect to home if scan not found
    """
    if scanner := scan_manager.get_scan(scan_id):
        data = scanner.results.export()
        return render_template('scan/scan-error.html', data=data)
    log.debug(f'Redirecting, scan {scan_id} doesnt exist in memory')
    return redirect('/')


@web_bp.route('/export/<scan_id>')
def export_scan(scan_id):
    """
    Provide an exportable view of scan results.

    Args:
        scan_id: Unique identifier for the scan

    Returns:
        Rendered export template or redirect to home if scan not found
    """
    if scanner := scan_manager.get_scan(scan_id):
        export_json = scanner.results.export(str)
        return render_template(
            'scan/export.html',
            scan=scanner,
            export_json=export_json
        )
    log.debug(f'Redirecting, scan {scan_id} doesnt exist in memory')
    return redirect('/')


@web_bp.route('/shutdown-ui')
def shutdown_ui():
    """
    Display the shutdown confirmation page.

    Returns:
        Rendered shutdown template
    """
    return render_template('shutdown.html')


@web_bp.route('/info')
def app_info():
    """
    Display application information and version details.

    Returns:
        Rendered info template
    """
    return render_template('info.html')
