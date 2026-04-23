"""
Scan-related Pydantic models for scanner results.
"""

from typing import List, Optional, Any, Dict

from pydantic import BaseModel, Field

from lanscape.core.models.enums import ScanStage, StageType, WarningCategory
from lanscape.core.models.device import DeviceResult


class StageEvalContext(BaseModel):
    """Context used by stages to decide whether they can execute."""
    subnet: str = Field(description="Target subnet string")
    is_ipv6: bool = Field(description="Whether the target subnet is IPv6")
    is_local: bool = Field(
        description="Whether the target subnet overlaps a local interface"
    )
    matching_interface: Optional[str] = Field(
        default=None, description="Name of the overlapping local interface"
    )
    arp_supported: bool = Field(description="Whether the system supports ARP")
    os_platform: str = Field(
        description="Normalised OS: 'windows', 'linux', or 'darwin'"
    )

    @classmethod
    def build(cls, subnet: str) -> 'StageEvalContext':
        """Construct from a subnet string by probing the local system."""
        # Deferred import to avoid circular dependency:
        # scan.py → subnet_utils → scan_config → ... → scan.py
        from lanscape.core.net_tools.subnet_utils import (  # pylint: disable=import-outside-toplevel
            is_ipv6_subnet,
            is_local_subnet,
            matching_interface,
            get_os_platform,
        )
        from lanscape.core.net_tools import is_arp_supported  # pylint: disable=import-outside-toplevel
        return cls(
            subnet=subnet,
            is_ipv6=is_ipv6_subnet(subnet),
            is_local=is_local_subnet(subnet),
            matching_interface=matching_interface(subnet),
            arp_supported=is_arp_supported(),
            os_platform=get_os_platform(),
        )


class StageProgress(BaseModel):
    """Progress snapshot for a single scan stage."""
    stage_name: str = Field(description="Human-readable stage name")
    stage_type: StageType = Field(description="Stage type identifier")
    total: int = Field(default=0, ge=0, description="Total work items")
    completed: int = Field(default=0, ge=0, description="Completed work items")
    finished: bool = Field(default=False, description="Whether stage has finished")
    skipped: bool = Field(default=False, description="Whether stage was skipped by a guard")
    skip_reason: Optional[str] = Field(
        default=None, description="Reason the stage was skipped"
    )
    runtime: float = Field(default=0.0, ge=0, description="Elapsed seconds for this stage")
    counter_label: str = Field(
        default="items",
        description="Label for the progress counter (e.g. 'IPs scanned')"
    )
    auto: Optional[bool] = Field(
        default=None, description="Whether this stage was auto-recommended"
    )
    reason: Optional[str] = Field(default=None, description="Reason the stage was auto-recommended")



class ScanErrorInfo(BaseModel):
    """Serializable representation of a scan-level error."""
    basic: str = Field(description="Brief error summary")
    traceback: Optional[str] = Field(default=None, description="Full traceback if available")


class ScanWarningInfo(BaseModel):
    """Serializable representation of a scan-level warning.

    The backend owns all formatting — ``title`` and ``body`` may contain
    Markdown which the UI renders directly.
    """
    category: WarningCategory = Field(description="Warning category for grouping")
    title: str = Field(description="Short markdown summary (shown collapsed)")
    body: Optional[str] = Field(
        default=None, description="Longer markdown details (shown expanded)"
    )
    stage: Optional[str] = Field(default=None, description="Stage name when warning occurred")
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
    port_list_length: int = Field(default=0, ge=0, description="Number of ports to test per device")
    ports_scanned: int = Field(default=0, ge=0, description="Total port tests completed")
    ports_total: int = Field(default=0, ge=0, description="Total port tests expected")

    # Timing
    start_time: float = Field(default=0.0, description="Unix timestamp when scan started")
    end_time: Optional[float] = Field(default=None, description="Unix timestamp when scan ended")
    run_time: int = Field(default=0, ge=0, description="Runtime in seconds")

    # Errors at scan level
    errors: List[ScanErrorInfo] = Field(default_factory=list, description="Scan-level errors")

    # Warnings at scan level (e.g., multiplier reductions)
    warnings: List[ScanWarningInfo] = Field(default_factory=list, description="Scan-level warnings")

    # Per-stage progress (pipeline execution)
    stages: List[StageProgress] = Field(
        default_factory=list, description="Progress for each pipeline stage"
    )
    current_stage_index: Optional[int] = Field(
        default=None, description="Index of the currently executing stage"
    )


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
    warnings: List[ScanWarningInfo] = Field(
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
