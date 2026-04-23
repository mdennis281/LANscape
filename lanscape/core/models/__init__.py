"""
Pydantic models for LANscape scanner results.

This package provides structured, validated models for all scan-related
data that flows through the system, including WebSocket communication.
"""

from lanscape.core.models.enums import DeviceStage, ScanStage, StageType, WarningCategory
from lanscape.core.models.device import (
    DeviceErrorInfo, DeviceResult, ProbeResponseInfo, ServiceInfo
)
from lanscape.core.models.scan import (
    StageProgress,
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
    "StageType",
    "WarningCategory",
    # Device models
    "DeviceErrorInfo",
    "DeviceResult",
    "ProbeResponseInfo",
    "ServiceInfo",
    # Scan models
    "StageProgress",
    "ScanErrorInfo",
    "ScanWarningInfo",
    "ScanMetadata",
    "ScanResults",
    "ScanDelta",
    "ScanSummary",
    "ScanListItem",
]
