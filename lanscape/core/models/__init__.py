"""
Pydantic models for LANscape scanner results.

This package provides structured, validated models for all scan-related
data that flows through the system, including WebSocket communication.
"""

from lanscape.core.models.enums import DeviceStage, ScanStage
from lanscape.core.models.device import DeviceErrorInfo, DeviceResult, ServiceInfo
from lanscape.core.models.scan import (
    ScanErrorInfo,
    ScanWarningInfo,
    ScanMetadata,
    ScanResults,
    ScanDelta,
    ScanSummary,
    ScanListItem,
)

__all__ = [
    # Enums
    "DeviceStage",
    "ScanStage",
    # Device models
    "DeviceErrorInfo",
    "DeviceResult",
    "ServiceInfo",
    # Scan models
    "ScanErrorInfo",
    "ScanWarningInfo",
    "ScanMetadata",
    "ScanResults",
    "ScanDelta",
    "ScanSummary",
    "ScanListItem",
]
