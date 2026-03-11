"""
Unit tests for hostname resolution in Device._get_hostname().

Tests cover:
- Standard reverse DNS lookup
- mDNS multicast PTR query (pure Python)
- NetBIOS NBSTAT query (pure Python)
- Platform-specific behavior (Windows skips fallbacks)
- Parser helpers for mDNS PTR and NBSTAT response packets
"""
# pylint: disable=protected-access,unused-argument

from unittest.mock import patch, MagicMock
import struct
import socket

import pytest

from lanscape.core.net_tools import (
    Device,
    _parse_mdns_ptr_response,
    _parse_nbstat_response,
    _dns_name_decode,
)


# ---------------------------------------------------------------------------
# Packet-building helpers
# ---------------------------------------------------------------------------

def _dns_encode(name: str) -> bytes:
    """Encode a dotted name into DNS wire format."""
    result = b''
    for label in name.split('.'):
        result += bytes([len(label)]) + label.encode('ascii')
    result += b'\x00'
    return result


def _build_mdns_ptr_response(
    reverse_name: str,
    hostname: str,
    *,
    qr: bool = True,
    ancount: int = 1,
) -> bytes:
    """Build a minimal mDNS PTR response packet."""
    flags = 0x8400 if qr else 0x0000
    header = (
        b'\x00\x00'
        + struct.pack('>H', flags)
        + b'\x00\x00'                      # QDCOUNT
        + struct.pack('>H', ancount)        # ANCOUNT
        + b'\x00\x00'                      # NSCOUNT
        + b'\x00\x00'                      # ARCOUNT
    )

    answer_name = _dns_encode(reverse_name)
    answer_meta = (
        b'\x00\x0c'              # Type: PTR
        b'\x00\x01'              # Class: IN
        b'\x00\x00\x00\x78'     # TTL: 120
    )
    rdata = _dns_encode(hostname)
    rdlength = struct.pack('>H', len(rdata))

    return header + answer_name + answer_meta + rdlength + rdata


def _build_nbstat_response(
    names: list,
    *,
    use_pointer: bool = False,
) -> bytes:
    """Build a minimal NBSTAT response.

    *names* is a list of ``(name_str, suffix_int, flags_int)`` tuples.
    """
    header = (
        b'\xa5\x6c'       # Transaction ID
        b'\x84\x00'       # Flags: response
        b'\x00\x00'       # QDCOUNT: 0
        b'\x00\x01'       # ANCOUNT: 1
        b'\x00\x00'       # NSCOUNT: 0
        b'\x00\x00'       # ARCOUNT: 0
    )

    if use_pointer:
        rr_name = b'\xc0\x0c'
    else:
        rr_name = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'

    rr_meta = (
        b'\x00\x21'           # Type: NBSTAT
        b'\x00\x01'           # Class: IN
        b'\x00\x00\x00\x00'  # TTL: 0
    )

    rdata = bytes([len(names)])
    for name_str, suffix, flags in names:
        padded = name_str.encode('ascii').ljust(15)[:15]
        rdata += padded + bytes([suffix]) + struct.pack('>H', flags)

    rdlength = struct.pack('>H', len(rdata))

    return header + rr_name + rr_meta + rdlength + rdata


# ---------------------------------------------------------------------------
# Tests — _get_hostname fallback chain
# ---------------------------------------------------------------------------

class TestGetHostname:
    """Tests for Device._get_hostname()."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="192.168.1.100", alive=True)

    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_reverse_dns_success(self, mock_dns, device):
        """Reverse DNS succeeds — should return hostname immediately."""
        mock_dns.return_value = ('myrouter.local', [], ['192.168.1.100'])

        result = device._get_hostname()

        assert result == 'myrouter.local'
        mock_dns.assert_called_once_with('192.168.1.100')

    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=True)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_windows_no_fallbacks(self, mock_dns, mock_os_handles, device):
        """On Windows, if DNS fails, should return None without trying fallbacks."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result is None

    @patch.object(Device, '_resolve_netbios', return_value=None)
    @patch.object(Device, '_resolve_mdns', return_value='livingroom-pi.local')
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_mdns_fallback_success(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os_handles, mock_mdns, mock_netbios, device
    ):
        """mDNS fallback resolves hostname when DNS fails on Linux."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result == 'livingroom-pi.local'

    @patch.object(Device, '_resolve_netbios', return_value='DESKTOP-ABC')
    @patch.object(Device, '_resolve_mdns', return_value=None)
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_netbios_fallback_success(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os_handles, mock_mdns, mock_netbios, device
    ):
        """NetBIOS fallback resolves hostname when DNS and mDNS fail."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result == 'DESKTOP-ABC'

    @patch.object(Device, '_resolve_netbios', return_value=None)
    @patch.object(Device, '_resolve_mdns', return_value=None)
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_all_methods_fail(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os_handles, mock_mdns, mock_netbios, device
    ):
        """All resolution methods fail — should return None."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result is None

    @patch.object(Device, '_resolve_netbios', return_value=None)
    @patch.object(Device, '_resolve_mdns', return_value='macbook.local')
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_macos_tries_fallbacks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os_handles, mock_mdns, mock_netbios, device
    ):
        """macOS should also attempt mDNS/NetBIOS fallbacks."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result == 'macbook.local'


# ---------------------------------------------------------------------------
# Tests — _resolve_mdns (pure-Python mDNS PTR query)
# ---------------------------------------------------------------------------

class TestResolveMdns:
    """Tests for Device._resolve_mdns() directly."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="10.0.0.5", alive=True)

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_success(self, mock_socket_cls, device):
        """Valid mDNS PTR response returns the hostname."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'mydevice.local'
        )
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 5353))

        assert device._resolve_mdns() == 'mydevice.local'
        mock_sock.sendto.assert_called_once()
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_timeout(self, mock_socket_cls, device):
        """Socket timeout returns None gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')

        assert device._resolve_mdns() is None
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_oserror(self, mock_socket_cls, device):
        """OSError returns None gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError('Network unreachable')

        assert device._resolve_mdns() is None
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_non_response_packet(self, mock_socket_cls, device):
        """A query echo (QR=0) is ignored, returning None."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'mydevice.local', qr=False
        )
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 5353))

        assert device._resolve_mdns() is None

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_sets_multicast_ttl(self, mock_socket_cls, device):
        """Verifies the socket sets the multicast TTL to 255."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'mydevice.local'
        )
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 5353))

        device._resolve_mdns()

        mock_sock.setsockopt.assert_called_once_with(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255
        )


# ---------------------------------------------------------------------------
# Tests — _resolve_netbios (pure-Python NBSTAT query)
# ---------------------------------------------------------------------------

class TestResolveNetbios:
    """Tests for Device._resolve_netbios() directly."""

    @pytest.fixture
    def device(self):
        """Create a test Device instance."""
        return Device(ip="10.0.0.5", alive=True)

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_success(self, mock_socket_cls, device):
        """Valid NBSTAT response returns the machine name."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_nbstat_response([
            ('DESKTOP-ABC', 0x00, 0x0400),    # unique workstation
            ('WORKGROUP', 0x00, 0x8400),       # group
        ])
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 137))

        assert device._resolve_netbios() == 'DESKTOP-ABC'
        mock_sock.sendto.assert_called_once()
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_timeout(self, mock_socket_cls, device):
        """Socket timeout returns None gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout('timed out')

        assert device._resolve_netbios() is None
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_oserror(self, mock_socket_cls, device):
        """OSError returns None gracefully."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError('Network unreachable')

        assert device._resolve_netbios() is None
        mock_sock.close.assert_called_once()

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_no_unique_name(self, mock_socket_cls, device):
        """Response with only GROUP names returns None."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_nbstat_response([
            ('WORKGROUP', 0x00, 0x8400),    # group
            ('WORKGROUP', 0x1e, 0x8400),    # group, browser election
        ])
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 137))

        assert device._resolve_netbios() is None

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_wildcard_name_ignored(self, mock_socket_cls, device):
        """Wildcard (*) NetBIOS names are skipped."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_nbstat_response([
            ('*', 0x00, 0x0400),  # unique but wildcard
        ])
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 137))

        assert device._resolve_netbios() is None

    @patch('lanscape.core.net_tools.device.socket.socket')
    def test_sends_to_port_137(self, mock_socket_cls, device):
        """Verifies the NBSTAT request is sent to UDP port 137."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        response = _build_nbstat_response([
            ('MYPC', 0x00, 0x0400),
        ])
        mock_sock.recvfrom.return_value = (response, ('10.0.0.5', 137))

        device._resolve_netbios()

        args, _ = mock_sock.sendto.call_args
        assert args[1] == ('10.0.0.5', 137)


# ---------------------------------------------------------------------------
# Tests — _parse_mdns_ptr_response
# ---------------------------------------------------------------------------

class TestParseMdnsPtrResponse:
    """Tests for the mDNS PTR response parser."""

    def test_valid_response(self):
        """Parses a standard PTR response correctly."""
        pkt = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'mydevice.local'
        )
        assert _parse_mdns_ptr_response(pkt) == 'mydevice.local'

    def test_too_short(self):
        """Packet shorter than DNS header returns None."""
        assert _parse_mdns_ptr_response(b'\x00' * 11) is None

    def test_query_not_response(self):
        """Packet with QR=0 (query) returns None."""
        pkt = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'device.local', qr=False
        )
        assert _parse_mdns_ptr_response(pkt) is None

    def test_zero_answers(self):
        """Packet with ANCOUNT=0 returns None."""
        pkt = _build_mdns_ptr_response(
            '5.0.0.10.in-addr.arpa', 'device.local', ancount=0
        )
        assert _parse_mdns_ptr_response(pkt) is None

    def test_compressed_name(self):
        """PTR RDATA with plain labels is resolved correctly."""
        header = (
            b'\x00\x00'
            b'\x84\x00'
            b'\x00\x00'           # QDCOUNT
            b'\x00\x01'           # ANCOUNT
            b'\x00\x00\x00\x00'  # NSCOUNT + ARCOUNT
        )
        answer_name = _dns_encode('5.0.0.10.in-addr.arpa')
        answer_type_class_ttl = (
            b'\x00\x0c'              # PTR
            b'\x00\x01'              # IN
            b'\x00\x00\x00\x78'     # TTL
        )

        rdata = b'\x06myhost\x05local\x00'
        rdlength = struct.pack('>H', len(rdata))

        pkt = header + answer_name + answer_type_class_ttl + rdlength + rdata
        assert _parse_mdns_ptr_response(pkt) == 'myhost.local'


# ---------------------------------------------------------------------------
# Tests — _parse_nbstat_response
# ---------------------------------------------------------------------------

class TestParseNbstatResponse:
    """Tests for the NBSTAT response parser."""

    def test_valid_response(self):
        """Parses a standard NBSTAT response with a unique workstation name."""
        pkt = _build_nbstat_response([
            ('DESKTOP-ABC', 0x00, 0x0400),
            ('WORKGROUP', 0x00, 0x8400),
        ])
        assert _parse_nbstat_response(pkt) == 'DESKTOP-ABC'

    def test_too_short(self):
        """Packet shorter than minimum returns None."""
        assert _parse_nbstat_response(b'\x00' * 42) is None

    def test_only_group_names(self):
        """Response with no unique names returns None."""
        pkt = _build_nbstat_response([
            ('WORKGROUP', 0x00, 0x8400),
            ('WORKGROUP', 0x1e, 0x8400),
        ])
        assert _parse_nbstat_response(pkt) is None

    def test_skips_non_zero_suffix(self):
        """Entries with suffix != 0x00 are skipped."""
        pkt = _build_nbstat_response([
            ('MYPC', 0x20, 0x0400),   # suffix 0x20 = file server, not 0x00
            ('MYPC', 0x00, 0x0400),   # this one matches
        ])
        assert _parse_nbstat_response(pkt) == 'MYPC'

    def test_wildcard_skipped(self):
        """Wildcard (*) name is skipped, returns None when it's the only entry."""
        pkt = _build_nbstat_response([
            ('*', 0x00, 0x0400),
        ])
        assert _parse_nbstat_response(pkt) is None

    def test_first_unique_name_returned(self):
        """Returns the first matching unique name."""
        pkt = _build_nbstat_response([
            ('WORKGROUP', 0x00, 0x8400),    # group — skipped
            ('SERVER-01', 0x00, 0x0400),     # first unique
            ('SERVER-01', 0x20, 0x0400),     # wrong suffix
        ])
        assert _parse_nbstat_response(pkt) == 'SERVER-01'

    def test_pointer_in_answer_name(self):
        """Handles a DNS pointer in the answer name field."""
        pkt = _build_nbstat_response(
            [('PTRHOST', 0x00, 0x0400)],
            use_pointer=True,
        )
        assert _parse_nbstat_response(pkt) == 'PTRHOST'


# ---------------------------------------------------------------------------
# Tests — _dns_name_decode
# ---------------------------------------------------------------------------

class TestDnsNameDecode:
    """Tests for the DNS name decoder."""

    def test_simple_name(self):
        """Decodes a simple multi-label name."""
        data = _dns_encode('myhost.local')
        name, offset = _dns_name_decode(data, 0)
        assert name == 'myhost.local'
        assert offset == len(data)

    def test_single_label(self):
        """Decodes a single-label name."""
        data = _dns_encode('localhost')
        name, _ = _dns_name_decode(data, 0)
        assert name == 'localhost'

    def test_pointer(self):
        """Follows a compression pointer correctly."""
        base_name = _dns_encode('example.local')
        pointer = b'\xc0\x00'
        data = base_name + pointer

        name, end_offset = _dns_name_decode(data, len(base_name))
        assert name == 'example.local'
        assert end_offset == len(base_name) + 2

    def test_empty_name(self):
        """Root name (just a null byte) decodes as empty string."""
        data = b'\x00'
        name, offset = _dns_name_decode(data, 0)
        assert name == ''
        assert offset == 1

    def test_offset_into_data(self):
        """Can start decoding at an arbitrary offset."""
        prefix = b'\xff' * 10
        encoded = _dns_encode('test.local')
        data = prefix + encoded

        name, _ = _dns_name_decode(data, 10)
        assert name == 'test.local'


# ---------------------------------------------------------------------------
# Tests — System mDNS helpers (avahi, dns-sd, LLMNR)
# ---------------------------------------------------------------------------

class TestResolveHostnameAvahi:
    """Tests for resolve_hostname_avahi() on Linux systems."""

    @patch('lanscape.core.system_compat.psutil.WINDOWS', True)
    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_returns_none_on_windows(self):
        """Should return None on Windows."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        assert resolve_hostname_avahi('192.168.1.1') is None

    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    @patch('lanscape.core.system_compat.psutil.MACOS', True)
    def test_returns_none_on_macos(self):
        """Should return None on macOS (use dns-sd instead)."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        assert resolve_hostname_avahi('192.168.1.1') is None

    @patch('lanscape.core.system_compat.shutil.which', return_value=None)
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_returns_none_without_avahi(self, mock_which):
        """Should return None if avahi-resolve-address is not installed."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        assert resolve_hostname_avahi('192.168.1.1') is None

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/avahi-resolve-address')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_parses_hostname_from_output(self, mock_which, mock_run):
        """Should parse hostname from avahi-resolve output."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        mock_run.return_value = MagicMock(returncode=0, stdout='192.168.1.100\tmyhost.local')
        result = resolve_hostname_avahi('192.168.1.100')
        assert result == 'myhost'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/avahi-resolve-address')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_handles_ipv6_with_scope(self, mock_which, mock_run):
        """Should strip scope ID from IPv6 addresses."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        mock_run.return_value = MagicMock(returncode=0, stdout='fe80::1\tdevice.local')
        result = resolve_hostname_avahi('fe80::1%eth0')
        mock_run.assert_called_once()
        # Check that scope was stripped
        call_args = mock_run.call_args[0][0]
        assert '%' not in call_args[-1]
        assert result == 'device'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/avahi-resolve-address')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_returns_none_on_failure(self, mock_which, mock_run):
        """Should return None if avahi-resolve fails."""
        from lanscape.core.system_compat import resolve_hostname_avahi
        mock_run.return_value = MagicMock(returncode=1, stdout='')
        assert resolve_hostname_avahi('192.168.1.100') is None


class TestResolveHostnameDnssd:
    """Tests for resolve_hostname_dnssd() on macOS systems."""

    @patch('lanscape.core.system_compat.psutil.MACOS', False)
    def test_returns_none_on_non_macos(self):
        """Should return None on non-macOS systems."""
        from lanscape.core.system_compat import resolve_hostname_dnssd
        assert resolve_hostname_dnssd('192.168.1.1') is None

    @patch('lanscape.core.system_compat.shutil.which', return_value=None)
    @patch('lanscape.core.system_compat.psutil.MACOS', True)
    def test_returns_none_without_dnssd(self, mock_which):
        """Should return None if dns-sd is not available."""
        from lanscape.core.system_compat import resolve_hostname_dnssd
        assert resolve_hostname_dnssd('192.168.1.1') is None


class TestResolveHostnameLlmnr:
    """Tests for resolve_hostname_llmnr() - LLMNR reverse lookups."""

    def test_invalid_ip_returns_none(self):
        """Should return None for invalid IP addresses."""
        from lanscape.core.system_compat import resolve_hostname_llmnr
        assert resolve_hostname_llmnr('not-an-ip') is None

    @patch('lanscape.core.system_compat.socket.socket')
    def test_ipv4_sends_to_correct_address(self, mock_socket_class):
        """IPv4 LLMNR should multicast to 224.0.0.252:5355."""
        from lanscape.core.system_compat import resolve_hostname_llmnr
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        resolve_hostname_llmnr('192.168.1.100')

        # Check socket was created with AF_INET
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        # Check sendto was called with LLMNR multicast address
        mock_sock.sendto.assert_called_once()
        _, addr = mock_sock.sendto.call_args[0]
        assert addr == ('224.0.0.252', 5355)

    @patch('lanscape.core.system_compat.socket.socket')
    def test_ipv6_sends_to_correct_address(self, mock_socket_class):
        """IPv6 LLMNR should multicast to ff02::1:3 port 5355."""
        from lanscape.core.system_compat import resolve_hostname_llmnr
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        resolve_hostname_llmnr('fe80::1')

        # Check socket was created with AF_INET6
        mock_socket_class.assert_called_with(socket.AF_INET6, socket.SOCK_DGRAM)
        # Check sendto was called with LLMNR IPv6 multicast address
        mock_sock.sendto.assert_called_once()
        _, addr = mock_sock.sendto.call_args[0]
        assert addr == ('ff02::1:3', 5355)

    def test_returns_none_on_timeout(self):
        """Should return None if no response is received."""
        from lanscape.core.system_compat import resolve_hostname_llmnr
        with patch('lanscape.core.system_compat.socket.socket') as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout()

            result = resolve_hostname_llmnr('192.168.1.100', timeout=0.1)
            assert result is None


class TestParseLlmnrPtrResponse:
    """Tests for _parse_llmnr_ptr_response() helper."""

    def test_empty_packet(self):
        """Should return None for empty packet."""
        from lanscape.core.system_compat import _parse_llmnr_ptr_response
        assert _parse_llmnr_ptr_response(b'') is None

    def test_short_packet(self):
        """Should return None for packet shorter than header."""
        from lanscape.core.system_compat import _parse_llmnr_ptr_response
        assert _parse_llmnr_ptr_response(b'\x00' * 10) is None


class TestResolveHostnameGetent:
    """Tests for resolve_hostname_getent() on Linux systems."""

    @patch('lanscape.core.system_compat.psutil.LINUX', False)
    def test_returns_none_on_non_linux(self):
        """Should return None on non-Linux systems."""
        from lanscape.core.system_compat import resolve_hostname_getent
        assert resolve_hostname_getent('192.168.1.1') is None

    @patch('lanscape.core.system_compat.shutil.which', return_value=None)
    @patch('lanscape.core.system_compat.psutil.LINUX', True)
    def test_returns_none_when_getent_not_found(self, mock_which):
        """Should return None if getent is not found."""
        from lanscape.core.system_compat import resolve_hostname_getent
        assert resolve_hostname_getent('192.168.1.1') is None

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/getent')
    @patch('lanscape.core.system_compat.psutil.LINUX', True)
    def test_successful_resolution(self, mock_which, mock_run):
        """Should successfully resolve hostname via getent."""
        from lanscape.core.system_compat import resolve_hostname_getent
        mock_run.return_value = MagicMock(returncode=0, stdout='192.168.1.1 myhost myhost.local')
        result = resolve_hostname_getent('192.168.1.1')
        assert result == 'myhost'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/getent')
    @patch('lanscape.core.system_compat.psutil.LINUX', True)
    def test_strips_local_suffix(self, mock_which, mock_run):
        """Should strip common suffixes like .local, .lan, .home."""
        from lanscape.core.system_compat import resolve_hostname_getent
        mock_run.return_value = MagicMock(returncode=0, stdout='192.168.1.1 router.local')
        result = resolve_hostname_getent('192.168.1.1')
        assert result == 'router'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/getent')
    @patch('lanscape.core.system_compat.psutil.LINUX', True)
    def test_handles_ipv6_scope(self, mock_which, mock_run):
        """Should strip scope ID from IPv6 address before calling getent."""
        from lanscape.core.system_compat import resolve_hostname_getent
        mock_run.return_value = MagicMock(returncode=0, stdout='fe80::1 device')
        result = resolve_hostname_getent('fe80::1%eth0')
        call_args = mock_run.call_args[0][0]
        assert '%' not in call_args[-1]
        assert result == 'device'


class TestResolveHostnameHostCmd:
    """Tests for resolve_hostname_host_cmd() on Unix systems."""

    @patch('lanscape.core.system_compat.psutil.WINDOWS', True)
    def test_returns_none_on_windows(self):
        """Should return None on Windows."""
        from lanscape.core.system_compat import resolve_hostname_host_cmd
        assert resolve_hostname_host_cmd('192.168.1.1') is None

    @patch('lanscape.core.system_compat.shutil.which', return_value=None)
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    def test_returns_none_when_host_not_found(self, mock_which):
        """Should return None if host command is not found."""
        from lanscape.core.system_compat import resolve_hostname_host_cmd
        assert resolve_hostname_host_cmd('192.168.1.1') is None

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/host')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    def test_successful_ipv4_resolution(self, mock_which, mock_run):
        """Should resolve hostname for IPv4 address."""
        from lanscape.core.system_compat import resolve_hostname_host_cmd
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='1.1.168.192.in-addr.arpa domain name pointer myhost.local.'
        )
        result = resolve_hostname_host_cmd('192.168.1.1')
        assert result == 'myhost'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/host')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    def test_successful_ipv6_resolution(self, mock_which, mock_run):
        """Should resolve hostname for IPv6 address."""
        from lanscape.core.system_compat import resolve_hostname_host_cmd
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='...ip6.arpa domain name pointer device.local.'
        )
        result = resolve_hostname_host_cmd('2001:db8::1')
        assert result == 'device'

    @patch('lanscape.core.system_compat.subprocess.run')
    @patch('lanscape.core.system_compat.shutil.which', return_value='/usr/bin/host')
    @patch('lanscape.core.system_compat.psutil.WINDOWS', False)
    def test_returns_none_on_failure(self, mock_which, mock_run):
        """Should return None if host command fails."""
        from lanscape.core.system_compat import resolve_hostname_host_cmd
        mock_run.return_value = MagicMock(returncode=1, stdout='')
        result = resolve_hostname_host_cmd('192.168.1.1')
        assert result is None


class TestHostnameResolutionFallbackChain:
    """Integration tests for the complete hostname resolution fallback chain."""

    @pytest.fixture
    def device(self):
        """Create a test device instance."""
        return Device(ip="192.168.1.100", alive=True)

    @patch('lanscape.core.net_tools.device.resolve_hostname_host_cmd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_getent', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_llmnr', return_value='WINDOWS-PC')
    @patch.object(Device, '_resolve_mdns', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_dnssd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_avahi', return_value=None)
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_llmnr_fallback_works(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os, mock_avahi, mock_dnssd, mock_mdns, mock_llmnr,
        mock_getent, mock_host, device
    ):
        """LLMNR fallback should be tried when other methods fail."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result == 'WINDOWS-PC'
        mock_llmnr.assert_called_once_with('192.168.1.100')

    @patch.object(Device, '_resolve_netbios', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_host_cmd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_getent', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_llmnr', return_value=None)
    @patch.object(Device, '_resolve_mdns', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_dnssd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_avahi', return_value='mydevice')
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_avahi_tried_before_mdns(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os, mock_avahi, mock_dnssd, mock_mdns, mock_llmnr,
        mock_getent, mock_host, mock_netbios, device
    ):
        """Avahi should be tried before raw mDNS query."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = device._get_hostname()

        assert result == 'mydevice'
        mock_avahi.assert_called_once()
        # mDNS should not be called since avahi succeeded
        mock_mdns.assert_not_called()

    @pytest.fixture
    def ipv6_device(self):
        """Create a test device with IPv6 address."""
        return Device(ip="fe80::1", alive=True)

    @patch.object(Device, '_resolve_netbios', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_host_cmd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_getent', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_llmnr', return_value='ipv6host')
    @patch.object(Device, '_resolve_mdns', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_dnssd', return_value=None)
    @patch('lanscape.core.net_tools.device.resolve_hostname_avahi', return_value=None)
    @patch('lanscape.core.net_tools.device.os_handles_hostname_resolution', return_value=False)
    @patch('lanscape.core.net_tools.device.socket.gethostbyaddr')
    def test_ipv6_hostname_resolution(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, mock_dns, mock_os, mock_avahi, mock_dnssd, mock_mdns, mock_llmnr,
        mock_getent, mock_host, mock_netbios, ipv6_device
    ):
        """IPv6 hostname resolution should try all fallbacks."""
        mock_dns.side_effect = socket.herror('Host not found')

        result = ipv6_device._get_hostname()

        assert result == 'ipv6host'
        # All methods should be tried since earlier ones failed
        mock_getent.assert_called_once()
        mock_avahi.assert_called_once()
        mock_dnssd.assert_called_once()
        mock_host.assert_called_once()
        mock_mdns.assert_called_once()
        mock_llmnr.assert_called_once()
