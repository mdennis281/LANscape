"""
Scan-related Pydantic models for scanner results.
"""

from typing import List, Optional, Any, Dict

from pydantic import BaseModel, Field

from lanscape.core.models.enums import ScanStage
from lanscape.core.models.device import DeviceResult

class ScanErrorInfo(BaseModel):
    """Serializable representation of a scan-level error."""
    basic: str = Field(description="Brief error summary")
    traceback: Optional[str] = Field(default=None, description="Full traceback if available")

class ScanWarningInfo(BaseModel):
    """Serializable representation of a scan-level warning."""
    type: str = Field(description="Warning type identifier")
    message: str = Field(description="Human-readable warning message")
    old_multiplier: Optional[float] = Field(default=None, description="Previous multiplier")
    new_multiplier: Optional[float] = Field(default=None, description="New multiplier")
    decrease_percent: Optional[float] = Field(default=None, description="Percent decrease")
    timestamp: Optional[float] = Field(default=None, description="Unix timestamp")

class ScanMetadata(BaseModel):
    """
    Scan progress and status metadata.

    This is the "header" information about a scan, separate from devices.
    """
    scan_id: str = Field(description="Unique scan identifier (UUID)")
    subnet: str = Field(description="Target subnet being scanned")
    port_list: str = Field(description="Name of port list being used")

    # Progress tracking
    running: bool = Field(default=False, description="Whether scan is actively running")
    stage: ScanStage = Field(default=ScanStage.INSTANTIATED, description="Current scan stage")
    percent_complete: float = Field(default=0.0, ge=0, le=100, description="Overall progress 0-100")

    # Device counts
    devices_total: int = Field(default=0, ge=0, description="Total IPs to scan")
    devices_scanned: int = Field(default=0, ge=0, description="IPs checked so far")
    devices_alive: int = Field(default=0, ge=0, description="Devices found alive")

    # Port scanning progress
    port_list_length: int = Field(default=0, ge=0, description="Number of ports to test")

    # Timing
    start_time: float = Field(default=0.0, description="Unix timestamp when scan started")
    end_time: Optional[float] = Field(default=None, description="Unix timestamp when scan ended")
    run_time: int = Field(default=0, ge=0, description="Runtime in seconds")

    # Errors at scan level
    errors: List[ScanErrorInfo] = Field(default_factory=list, description="Scan-level errors")

    # Warnings at scan level (e.g., multiplier reductions)
    warnings: List[ScanWarningInfo] = Field(default_factory=list, description="Scan-level warnings")


class ScanResults(BaseModel):
    """
    Complete scan results including metadata and devices.

    This is the full response format for scan.get and scan exports.
    """
    metadata: ScanMetadata
    devices: List[DeviceResult] = Field(default_factory=list)
    config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Scan configuration used (ScanConfig as dict)"
    )


class ScanDelta(BaseModel):
    """
    Delta update for efficient real-time scan updates.

    Only contains fields that have changed since last request.
    Used for scan.update and scan.delta WebSocket events.
    """
    scan_id: str
    running: bool
    has_changes: bool = Field(default=False)

    # Optional - only present if changed
    metadata: Optional[ScanMetadata] = Field(default=None)
    devices: List[DeviceResult] = Field(
        default_factory=list,
        description="Only devices that have changed"
    )


class ScanSummary(BaseModel):
    """
    Lightweight scan summary for progress display.

    Response format for scan.summary action.
    """
    metadata: ScanMetadata
    ports_found: List[int] = Field(
        default_factory=list,
        description="Open ports found across all devices"
    )
    services_found: List[str] = Field(
        default_factory=list,
        description="Services identified across all devices"
    )
    warnings: List[dict] = Field(
        default_factory=list,
        description="Warnings generated during scan"
    )


class ScanListItem(BaseModel):
    """Summary info for a scan in the scan list."""
    scan_id: str
    subnet: str
    running: bool = Field(default=False)
    stage: ScanStage = Field(default=ScanStage.INSTANTIATED)
    percent_complete: float = Field(default=0.0)
    devices_alive: int = Field(default=0)
    devices_total: int = Field(default=0)
