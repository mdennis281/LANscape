"""Pydantic models for service scanning."""

from typing import Optional, List

from pydantic import BaseModel, ConfigDict, Field


class BinarySignature(BaseModel):
    """A binary protocol signature for detecting services by byte patterns."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    pattern: bytes
    weight: int


class ServiceMatcher(BaseModel):
    """A pattern matcher for identifying services with weighted priority."""
    name: str
    weight: int
    patterns: List[str] = Field(default_factory=list)
    case_sensitive: bool = False

    def match(self, response: str) -> bool:
        """Check if response matches any pattern."""
        check_response = response if self.case_sensitive else response.lower()
        for pattern in self.patterns:
            check_pattern = pattern if self.case_sensitive else pattern.lower()
            if check_pattern in check_response:
                return True
        return False


class ProbeResponse(BaseModel):
    """A single probe's request/response pair."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    request: Optional[str] = None
    response: Optional[str] = None
    response_bytes: Optional[bytes] = None
    is_tls: bool = False
    service: str = 'Unknown'
    weight: int = 0


class ServiceScanResult(BaseModel):
    """Result of a service scan probe."""
    service: str
    response: Optional[str] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False
    all_responses: List[ProbeResponse] = Field(default_factory=list)
    error: Optional[str] = None


class ProbeResult(BaseModel):
    """Result from multi-probe operation with statistics."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    response: Optional[str] = None
    response_bytes: Optional[bytes] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False
    all_responses: List[ProbeResponse] = Field(default_factory=list)
