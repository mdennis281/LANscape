"""Service scanning for identifying services running on network ports."""

# Re-export public API for backward compatibility
from lanscape.core.service_scan.scanner import scan_service  # noqa: F401
from lanscape.core.service_scan.models import (  # noqa: F401
    BinarySignature,
    ServiceMatcher,
    ProbeResponse,
    ServiceScanResult,
    ProbeResult,
)
from lanscape.core.service_scan.resources import (  # noqa: F401
    SERVICES,
    PRINTER_PORTS,
    BINARY_SIGNATURES,
    PROTOCOL_PROBES,
    SERVICE_MATCHERS,
    PORT_SPECIFIC_PROBES,
)
from lanscape.core.service_scan.identification import (  # noqa: F401
    _match_binary_signature,
    _identify_service,
    _clean_response,
    _strip_redirect_noise,
    MAX_RESPONSE_LENGTH,
)
from lanscape.core.service_scan.probes import (  # noqa: F401
    _try_probe,
    _try_ssl_probe,
    _detect_tls_from_bytes,
    _handle_tls_escalation,
    _multi_probe_generic,
    _format_request,
    get_port_probes,
    HTTPS_PLAINTEXT_INDICATORS,
)
