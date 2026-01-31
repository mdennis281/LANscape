"""
Pydantic models for LANscape scanner results.

This package provides structured, validated models for all scan-related
data that flows through the system, including WebSocket communication.
"""

from lanscape.core.models.enums import DeviceStage, ScanStage
from lanscape.core.models.device import DeviceErrorInfo, DeviceResult
from lanscape.core.models.scan import (
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
    # Scan models
    "ScanMetadata",
    "ScanResults",
    "ScanDelta",
    "ScanSummary",
    "ScanListItem",
]
