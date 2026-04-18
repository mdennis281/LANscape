"""Load service-scan resource files (JSONC) into runtime structures."""

import logging
from typing import Optional, Dict, List

from lanscape.core.app_scope import ResourceManager
from lanscape.core.service_scan.models import BinarySignature, ServiceMatcher

log = logging.getLogger('ServiceScan')

_svc_resources = ResourceManager('services')

# Legacy service definitions (hints, ports, probes from definitions.jsonc)
SERVICES = _svc_resources.get_jsonc('definitions.jsonc')

# Skip printer ports because they cause blank pages to be printed
PRINTER_PORTS = [9100, 631]

# Global override — set to False via --printer-mayhem to disable printer
# port safety library-wide.  Per-scan control via ServiceScanConfig.printer_safety.
PRINTER_SAFETY = True


def _load_binary_signatures() -> List[BinarySignature]:
    """Load binary protocol signatures from ``binary_signatures.jsonc``."""
    raw = _svc_resources.get_jsonc('binary_signatures.jsonc')
    return [
        BinarySignature(
            name=entry['name'],
            pattern=bytes.fromhex(entry['pattern']),
            weight=entry['weight'],
        )
        for entry in raw
    ]


def _load_protocol_probes() -> Dict[str, Optional[bytes]]:
    """Load protocol-specific probe payloads from ``protocol_probes.jsonc``."""
    raw = _svc_resources.get_jsonc('protocol_probes.jsonc')
    probes: Dict[str, Optional[bytes]] = {}
    for name, value in raw.items():
        if value is None:
            probes[name] = None
        elif isinstance(value, dict):
            prefix = bytes.fromhex(value['hex'])
            total = value['pad_to']
            probes[name] = prefix.ljust(total, b'\x00')
        else:
            probes[name] = bytes.fromhex(value)
    return probes


def _load_service_matchers() -> List[ServiceMatcher]:
    """Load text-based service matchers from ``service_matchers.jsonc``."""
    raw = _svc_resources.get_jsonc('service_matchers.jsonc')
    return [
        ServiceMatcher(
            name=entry['name'],
            weight=entry['weight'],
            patterns=entry.get('patterns', []),
            case_sensitive=entry.get('case_sensitive', False),
        )
        for entry in raw
    ]


def _load_port_specific_probes(
    protocol_probes: Dict[str, Optional[bytes]],
) -> Dict[int, List[Optional[bytes]]]:
    """Load port-to-probe mappings from ``port_probes.jsonc``."""
    raw = _svc_resources.get_jsonc('port_probes.jsonc')
    result: Dict[int, List[Optional[bytes]]] = {}
    for port_str, probe_names in raw.items():
        resolved_probes: List[Optional[bytes]] = []
        for name in probe_names:
            probe = protocol_probes.get(name)
            if probe is None and name not in protocol_probes:
                log.warning(
                    "Unknown protocol probe name '%s' referenced for port %s "
                    "in port_probes.jsonc; this entry will be ignored at runtime.",
                    name,
                    port_str,
                )
            resolved_probes.append(probe)
        result[int(port_str)] = resolved_probes
    return result


# ── Load once at import time ────────────────────────────────────────
try:
    BINARY_SIGNATURES: List[BinarySignature] = _load_binary_signatures()
    PROTOCOL_PROBES: Dict[str, Optional[bytes]] = _load_protocol_probes()
    SERVICE_MATCHERS: List[ServiceMatcher] = _load_service_matchers()
    PORT_SPECIFIC_PROBES: Dict[int, List[Optional[bytes]]] = _load_port_specific_probes(
        PROTOCOL_PROBES
    )
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "Failed to load service scan resources from 'lanscape/resources/services'. "
        "Ensure all required JSONC files are present and valid."
    ) from exc
