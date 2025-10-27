"""Source for all things blueprint related in LANscape UI"""
import logging

from lanscape.core.subnet_scan import ScanManager

# defining here so blueprints can access the same
# manager instance
scan_manager = ScanManager()

log = logging.getLogger('Blueprints')
