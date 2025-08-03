from lanscape.libraries.subnet_scan import ScanManager
import logging
# defining here so blueprints can access the same
# manager instance
scan_manager = ScanManager()

log = logging.getLogger('Blueprints')
