"""Service identification via binary signatures and text pattern matching."""

from typing import Optional, Tuple

from lanscape.core.service_scan.resources import (
    BINARY_SIGNATURES,
    SERVICE_MATCHERS,
    SERVICES,
)

# Maximum length for stored responses to avoid bloating results
MAX_RESPONSE_LENGTH = 512


def _match_binary_signature(data: bytes) -> Optional[Tuple[str, int]]:
    """Check for binary protocol signatures. Returns ``(service_name, weight)`` or ``None``.

    Returns the highest-weight match across all signatures.
    """
    if not data:
        return None

    best_name: Optional[str] = None
    best_weight: int = -1

    # DNS detection: transaction ID 0xAABB echoed back with QR bit set
    dns_weight = 60
    for offset in range(min(len(data) - 2, 12)):
        if (data[offset] == 0xAA and data[offset + 1] == 0xBB
                and len(data) > offset + 2 and data[offset + 2] & 0x80):
            if dns_weight > best_weight:
                best_name = "DNS"
                best_weight = dns_weight
            break

    for sig in BINARY_SIGNATURES:
        if sig.pattern in data:
            if sig.weight > best_weight:
                best_name = sig.name
                best_weight = sig.weight

    if best_name is None:
        return None
    return (best_name, best_weight)


def _strip_redirect_noise(response: Optional[str]) -> str:
    """Remove ``Location:`` header values before text-based matching."""
    if not response:
        return ""
    lines = response.split('\n')
    return '\n'.join(
        line for line in lines
        if not line.strip().lower().startswith('location:')
    )


def _clean_response(response: str) -> str:
    """Sanitise and truncate a response string for storage."""
    if not response:
        return ""

    cleaned = response.strip()
    cleaned = ''.join(
        char if char.isprintable() or char in '\n\r\t' else f'\\x{ord(char):02x}'
        for char in cleaned
    )
    if len(cleaned) > MAX_RESPONSE_LENGTH:
        cleaned = cleaned[:MAX_RESPONSE_LENGTH] + '...'
    return cleaned


def _identify_service(
    response: str,
    response_bytes: Optional[bytes] = None,
    is_tls: bool = False,
) -> Tuple[str, int]:
    """Identify service using weighted matching (binary + text + legacy)."""
    best_service = "Unknown"
    best_weight = 0

    if is_tls:
        best_service = "HTTPS"
        best_weight = 80

    if response_bytes:
        match = _match_binary_signature(response_bytes)
        if match:
            sig_name, sig_weight = match
            if sig_weight > best_weight:
                best_service = sig_name
                best_weight = sig_weight

    match_text = _strip_redirect_noise(response)
    for matcher in SERVICE_MATCHERS:
        if matcher.name == "HTTPS" and not is_tls:
            continue
        if matcher.match(match_text):
            if matcher.weight > best_weight:
                best_service = matcher.name
                best_weight = matcher.weight

    if best_weight == 0 and match_text:
        for service, config in SERVICES.items():
            hints = config.get("hints", [])
            if any(hint.lower() in match_text.lower() for hint in hints):
                best_service = service
                best_weight = 30
                break

    return (best_service, best_weight)
