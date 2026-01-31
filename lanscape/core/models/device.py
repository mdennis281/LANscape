"""
Device-related Pydantic models for scanner results.
"""

import traceback as tb_module
from typing import List, Dict, Optional

from pydantic import BaseModel, Field, computed_field

from lanscape.core.models.enums import DeviceStage


class DeviceErrorInfo(BaseModel):
    """Serializable representation of a device error."""
    source: str = Field(description="Method/source where error occurred")
    message: str = Field(description="Error message")
    traceback: Optional[str] = Field(default=None, description="Full traceback if available")

    @classmethod
    def from_exception(cls, exc: Exception, method: str = "unknown") -> "DeviceErrorInfo":
        """Create from an exception."""
        return cls(
            source=method,
            message=str(exc),
            traceback=tb_module.format_exc() if exc.__traceback__ else None
        )


class DeviceResult(BaseModel):
    """
    Result data for a discovered network device.

    This is the primary model for device information throughout the system,
    used for WebSocket communication and API responses.
    """
    ip: str = Field(description="IP address of the device")
    alive: Optional[bool] = Field(default=None, description="Whether the device responded")
    hostname: Optional[str] = Field(default=None, description="Resolved hostname")
    macs: List[str] = Field(default_factory=list, description="All discovered MAC addresses")
    manufacturer: Optional[str] = Field(default=None, description="MAC vendor/manufacturer")
    ports: List[int] = Field(default_factory=list, description="Open ports found")
    stage: DeviceStage = Field(default=DeviceStage.FOUND, description="Current scan stage")
    ports_scanned: int = Field(default=0, description="Number of ports tested")
    services: Dict[str, List[int]] = Field(
        default_factory=dict,
        description="Service name to list of ports mapping"
    )
    errors: List[DeviceErrorInfo] = Field(
        default_factory=list,
        description="Errors encountered during scanning"
    )

    @computed_field  # type: ignore[misc]
    @property
    def mac_addr(self) -> str:
        """Primary MAC address (first in list or empty)."""
        if self.macs and len(self.macs) > 0:
            return self.macs[0]
        return ""

    model_config = {
        "json_schema_extra": {
            "example": {
                "ip": "192.168.1.100",
                "alive": True,
                "hostname": "mydevice.local",
                "macs": ["AA:BB:CC:DD:EE:FF"],
                "manufacturer": "Apple Inc.",
                "ports": [22, 80, 443],
                "stage": "complete",
                "ports_scanned": 100,
                "services": {"ssh": [22], "http": [80, 443]},
                "errors": []
            }
        }
    }
