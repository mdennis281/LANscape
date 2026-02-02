"""
Enumeration types for scanner models.
"""

from enum import Enum


class DeviceStage(str, Enum):
    """Stage of device discovery/scanning."""
    FOUND = "found"
    SCANNING = "scanning"
    COMPLETE = "complete"


class ScanStage(str, Enum):
    """Overall scan stage."""
    INSTANTIATED = "instantiated"
    SCANNING_DEVICES = "scanning devices"
    TESTING_PORTS = "testing ports"
    COMPLETE = "complete"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
