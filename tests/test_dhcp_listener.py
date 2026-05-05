"""
Unit tests for the DHCP lease request listener module.

Covers:
- DhcpMessageType enum helpers
- DHCP option parser (_parse_dhcp_options)
- Packet parser (_parse_packet) using synthetic scapy-like mock packets
- DhcpLeaseEvent model properties (effective_ip, is_client_message, etc.)
- DhcpListenerConfig subnet filter logic (_ip_in_networks, _build_subnet_networks)
- DhcpListener filter pipeline (_passes_filters)
- DhcpListener start/stop lifecycle (mocked AsyncSniffer)
- Context-manager usage
"""
# pylint: disable=protected-access,missing-function-docstring
import logging
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import ipaddress

import pytest

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP

from lanscape.core.dhcp_listener import (
    DhcpListener,
    DhcpListenerConfig,
    DhcpLeaseEvent,
    DhcpMessageType,
    _build_subnet_networks,
    _decode_bytes,
    _ip_in_networks,
    _mac_from_bytes,
    _parse_dhcp_options,
    _parse_packet,
)


# ═══════════════════════════════════════════════════════════════════
#  Fixtures / helpers
# ═══════════════════════════════════════════════════════════════════

def _make_mock_packet(**kwargs) -> MagicMock:
    """Build a minimal mock scapy packet with BOOTP and DHCP layers."""
    chaddr = kwargs.get("chaddr", b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00" * 10)
    ciaddr = kwargs.get("ciaddr", "0.0.0.0")
    yiaddr = kwargs.get("yiaddr", "0.0.0.0")
    siaddr = kwargs.get("siaddr", "0.0.0.0")
    src_ip = kwargs.get("src_ip", "0.0.0.0")
    dst_ip = kwargs.get("dst_ip", "255.255.255.255")
    dhcp_options = kwargs.get("dhcp_options")

    bootp = MagicMock(spec=BOOTP)
    bootp.chaddr = chaddr
    bootp.ciaddr = ciaddr
    bootp.yiaddr = yiaddr
    bootp.siaddr = siaddr

    dhcp = MagicMock(spec=DHCP)
    dhcp.options = dhcp_options or [
        ("message-type", 1),
        ("end", None),
    ]

    ip_layer = MagicMock(spec=IP)
    ip_layer.src = src_ip
    ip_layer.dst = dst_ip

    pkt = MagicMock()
    pkt.sniffed_on = "eth0"

    def contains(cls):
        return cls in (BOOTP, DHCP, IP)

    pkt.__contains__ = MagicMock(side_effect=contains)

    def getitem(cls):
        if cls is BOOTP:
            return bootp
        if cls is DHCP:
            return dhcp
        if cls is IP:
            return ip_layer
        raise KeyError(cls)

    pkt.__getitem__ = MagicMock(side_effect=getitem)
    return pkt


def _make_event(**kwargs) -> DhcpLeaseEvent:
    """Create a minimal DhcpLeaseEvent with sensible defaults."""
    defaults = {
        "message_type": DhcpMessageType.DISCOVER,
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "timestamp": datetime.now(timezone.utc),
    }
    defaults.update(kwargs)
    return DhcpLeaseEvent(**defaults)


# ═══════════════════════════════════════════════════════════════════
#  DhcpMessageType
# ═══════════════════════════════════════════════════════════════════

class TestDhcpMessageType:
    """Tests for DhcpMessageType enum helpers."""
    def test_known_values(self):
        assert DhcpMessageType.DISCOVER == 1
        assert DhcpMessageType.OFFER    == 2
        assert DhcpMessageType.REQUEST  == 3
        assert DhcpMessageType.ACK      == 5
        assert DhcpMessageType.NAK      == 6

    def test_from_int_known(self):
        assert DhcpMessageType.from_int(1) is DhcpMessageType.DISCOVER
        assert DhcpMessageType.from_int(5) is DhcpMessageType.ACK

    def test_from_int_unknown(self):
        assert DhcpMessageType.from_int(99) is None

    def test_from_int_zero(self):
        assert DhcpMessageType.from_int(0) is None


# ═══════════════════════════════════════════════════════════════════
#  Low-level helpers
# ═══════════════════════════════════════════════════════════════════

class TestDecodeBytes:
    """Tests for the _decode_bytes helper."""
    def test_bytes_to_str(self):
        assert _decode_bytes(b"mydevice") == "mydevice"

    def test_null_stripped(self):
        assert _decode_bytes(b"host\x00") == "host"

    def test_str_passthrough(self):
        assert _decode_bytes("hello") == "hello"

    def test_non_bytes_returns_none(self):
        assert _decode_bytes(42) is None
        assert _decode_bytes(None) is None


class TestMacFromBytes:
    """Tests for the _mac_from_bytes helper."""
    def test_six_bytes(self):
        assert _mac_from_bytes(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"

    def test_longer_bytes_truncates_to_six(self):
        raw = b"\x00\x11\x22\x33\x44\x55\xde\xad"
        assert _mac_from_bytes(raw) == "00:11:22:33:44:55"

    def test_zero_mac(self):
        assert _mac_from_bytes(b"\x00" * 6) == "00:00:00:00:00:00"


class TestParseDhcpOptions:
    """Tests for the _parse_dhcp_options helper."""
    def test_empty(self):
        assert not _parse_dhcp_options([])

    def test_end_and_pad_are_skipped(self):
        assert not _parse_dhcp_options([("end", None), ("pad", None)])

    def test_named_option_decoded_to_code(self):
        opts = _parse_dhcp_options([("message-type", 1), ("hostname", b"pc1")])
        # 'message-type' → 53, 'hostname' is not in _OPTION_NAME_TO_CODE → stays 'hostname'
        assert opts[53] == 1
        # 'hostname' is not in our map (code 12 uses key 'hostname' in scapy output
        # but our map key is 'hostname' → code 12)
        assert opts[12] == b"pc1"

    def test_integer_key_preserved(self):
        opts = _parse_dhcp_options([(250, b"\x01\x02")])
        assert opts[250] == b"\x01\x02"

    def test_tuple_and_list_items(self):
        opts = _parse_dhcp_options([["message-type", 3]])
        assert opts[53] == 3


# ═══════════════════════════════════════════════════════════════════
#  DhcpLeaseEvent model properties
# ═══════════════════════════════════════════════════════════════════

class TestDhcpLeaseEventProperties:
    """Tests for DhcpLeaseEvent computed properties."""
    def test_effective_ip_prefers_requested(self):
        e = _make_event(
            requested_ip="192.168.1.50",
            offered_ip="192.168.1.51",
            client_ip="192.168.1.52",
        )
        assert e.effective_ip == "192.168.1.50"

    def test_effective_ip_falls_back_to_offered(self):
        e = _make_event(offered_ip="192.168.1.51", client_ip="192.168.1.52")
        assert e.effective_ip == "192.168.1.51"

    def test_effective_ip_falls_back_to_client(self):
        e = _make_event(client_ip="192.168.1.52")
        assert e.effective_ip == "192.168.1.52"

    def test_effective_ip_none_when_all_absent(self):
        e = _make_event()
        assert e.effective_ip is None

    def test_is_client_message_discover(self):
        assert _make_event(message_type=DhcpMessageType.DISCOVER).is_client_message
        assert _make_event(message_type=DhcpMessageType.REQUEST).is_client_message
        assert _make_event(message_type=DhcpMessageType.RELEASE).is_client_message

    def test_is_client_message_offer_is_false(self):
        assert not _make_event(message_type=DhcpMessageType.OFFER).is_client_message

    def test_is_server_message_offer(self):
        assert _make_event(message_type=DhcpMessageType.OFFER).is_server_message
        assert _make_event(message_type=DhcpMessageType.ACK).is_server_message
        assert _make_event(message_type=DhcpMessageType.NAK).is_server_message

    def test_is_server_message_discover_is_false(self):
        assert not _make_event(message_type=DhcpMessageType.DISCOVER).is_server_message


# ═══════════════════════════════════════════════════════════════════
#  Subnet filter helpers
# ═══════════════════════════════════════════════════════════════════

class TestBuildSubnetNetworks:
    """Tests for _build_subnet_networks."""
    def test_none_returns_none(self):
        assert _build_subnet_networks(None) is None

    def test_empty_list_returns_none(self):
        assert _build_subnet_networks([]) is None

    def test_valid_subnet(self):
        result = _build_subnet_networks(["192.168.1.0/24"])
        nets: list = result or []
        assert len(nets) == 1
        assert isinstance(nets[0], ipaddress.IPv4Network)

    def test_invalid_subnet_skipped(self, caplog):
        with caplog.at_level(logging.WARNING):
            nets = _build_subnet_networks(["not-a-subnet", "10.0.0.0/8"])
        assert nets is not None and len(nets) == 1
        assert "not-a-subnet" in caplog.text

    def test_all_invalid_returns_none(self):
        assert _build_subnet_networks(["bad1", "bad2"]) is None


class TestIpInNetworks:
    """Tests for the _ip_in_networks helper."""

    nets: list  # assigned in setup_method

    def setup_method(self):
        self.nets = _build_subnet_networks(["192.168.1.0/24", "10.0.0.0/8"]) or []

    def test_ip_in_first_network(self):
        assert _ip_in_networks("192.168.1.100", self.nets)

    def test_ip_in_second_network(self):
        assert _ip_in_networks("10.5.6.7", self.nets)

    def test_ip_not_in_any_network(self):
        assert not _ip_in_networks("172.16.0.1", self.nets)

    def test_none_ip_returns_false(self):
        assert not _ip_in_networks(None, self.nets)

    def test_no_filter_always_true(self):
        assert _ip_in_networks("1.2.3.4", None)
        assert _ip_in_networks(None, None)

    def test_invalid_ip_returns_false(self):
        assert not _ip_in_networks("not-an-ip", self.nets)


# ═══════════════════════════════════════════════════════════════════
#  _parse_packet integration
# ═══════════════════════════════════════════════════════════════════

class TestParsePacket:
    """Tests for the _parse_packet function."""
    def test_discover_packet(self):
        pkt = _make_mock_packet(
            dhcp_options=[
                ("message-type", 1),
                ("hostname", b"my-laptop"),
                ("vendor_class_id", b"MSFT 5.0"),
                ("requested_addr", "192.168.1.50"),
                ("param_req_list", [1, 3, 6, 15]),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert event is not None
        assert event.message_type == DhcpMessageType.DISCOVER
        assert event.client_mac == "aa:bb:cc:dd:ee:ff"
        assert event.hostname == "my-laptop"
        assert event.vendor_class == "MSFT 5.0"
        assert event.requested_ip == "192.168.1.50"
        assert event.requested_options == [1, 3, 6, 15]

    def test_offer_packet(self):
        pkt = _make_mock_packet(
            yiaddr="192.168.1.100",
            siaddr="192.168.1.1",
            dhcp_options=[
                ("message-type", 2),
                ("subnet_mask", "255.255.255.0"),
                ("router", "192.168.1.1"),
                ("name_server", ["8.8.8.8", "8.8.4.4"]),
                ("lease_time", 86400),
                ("server_id", "192.168.1.1"),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert event is not None
        assert event.message_type == DhcpMessageType.OFFER
        assert event.offered_ip == "192.168.1.100"
        assert event.subnet_mask == "255.255.255.0"
        assert event.router == "192.168.1.1"
        assert event.dns_servers == ["8.8.8.8", "8.8.4.4"]
        assert event.lease_time == 86400
        assert event.server_identifier == "192.168.1.1"

    def test_client_ip_zero_becomes_none(self):
        pkt = _make_mock_packet(ciaddr="0.0.0.0")
        event = _parse_packet(pkt)
        assert event.client_ip is None

    def test_client_ip_nonzero_preserved(self):
        pkt = _make_mock_packet(ciaddr="192.168.1.55")
        event = _parse_packet(pkt)
        assert event.client_ip == "192.168.1.55"

    def test_mac_address_formatting(self):
        chaddr = b"\x00\x1a\x2b\x3c\x4d\x5e" + b"\x00" * 10
        pkt = _make_mock_packet(chaddr=chaddr)
        event = _parse_packet(pkt)
        assert event.client_mac == "00:1a:2b:3c:4d:5e"

    def test_returns_none_without_dhcp_layer(self):
        pkt = MagicMock()
        pkt.__contains__ = MagicMock(return_value=False)
        assert _parse_packet(pkt) is None

    def test_interface_captured(self):
        pkt = _make_mock_packet()
        event = _parse_packet(pkt)
        assert event.interface == "eth0"

    def test_client_id_mac_type(self):
        # Option 61: type byte 0x01 followed by 6-byte MAC
        raw = b"\x01\xde\xad\xbe\xef\x00\x01"
        pkt = _make_mock_packet(
            dhcp_options=[
                ("message-type", 3),
                ("client_id", raw),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert event.client_identifier == "de:ad:be:ef:00:01"

    def test_param_req_list_as_bytes(self):
        pkt = _make_mock_packet(
            dhcp_options=[
                ("message-type", 1),
                ("param_req_list", bytes([1, 3, 6, 15, 28, 43])),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert event.requested_options == [1, 3, 6, 15, 28, 43]

    def test_unknown_options_collected(self):
        pkt = _make_mock_packet(
            dhcp_options=[
                ("message-type", 1),
                (250, b"\xde\xad"),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert 250 in event.unknown_options

    def test_fqdn_option_decoded(self):
        # RFC 4702: 3 flag/rcode bytes + name
        fqdn_raw = b"\x00\x00\x00" + b"myhost.local"
        pkt = _make_mock_packet(
            dhcp_options=[
                ("message-type", 1),
                ("FQDN", fqdn_raw),
                ("end", None),
            ]
        )
        event = _parse_packet(pkt)
        assert event.fqdn == "myhost.local"

    def test_timestamp_is_utc(self):
        pkt = _make_mock_packet()
        event = _parse_packet(pkt)
        ts_value = event.model_dump().get("timestamp")
        assert isinstance(ts_value, datetime) and ts_value.tzinfo is not None


# ═══════════════════════════════════════════════════════════════════
#  DhcpListener._passes_filters
# ═══════════════════════════════════════════════════════════════════

class TestDhcpListenerFilters:
    """Tests for DhcpListener filter logic."""
    def _listener(self, **config_kwargs) -> DhcpListener:
        cfg = DhcpListenerConfig(**config_kwargs)
        return DhcpListener(cfg, on_event=lambda e: None)

    # ── message type filter ──

    def test_no_message_filter_passes_all(self):
        listener = self._listener()
        event = _make_event(message_type=DhcpMessageType.REQUEST)
        assert listener._passes_filters(event)

    def test_message_filter_passes_matching_type(self):
        listener = self._listener(message_types=[DhcpMessageType.DISCOVER])
        assert listener._passes_filters(_make_event(message_type=DhcpMessageType.DISCOVER))

    def test_message_filter_blocks_non_matching_type(self):
        listener = self._listener(message_types=[DhcpMessageType.DISCOVER])
        assert not listener._passes_filters(_make_event(message_type=DhcpMessageType.REQUEST))

    # ── include_server_messages ──

    def test_server_messages_included_by_default(self):
        listener = self._listener()
        event = _make_event(message_type=DhcpMessageType.OFFER)
        assert listener._passes_filters(event)

    def test_server_messages_excluded_when_configured(self):
        listener = self._listener(include_server_messages=False)
        for msg_type in (DhcpMessageType.OFFER, DhcpMessageType.ACK, DhcpMessageType.NAK):
            event = _make_event(message_type=msg_type)
            assert not listener._passes_filters(event), f"Expected {msg_type} to be blocked"

    def test_client_messages_not_affected_by_server_filter(self):
        listener = self._listener(include_server_messages=False)
        event = _make_event(message_type=DhcpMessageType.DISCOVER)
        assert listener._passes_filters(event)

    # ── subnet filter ──

    def test_no_subnet_filter_passes_all(self):
        listener = self._listener()
        event = _make_event(requested_ip="172.16.5.10")
        assert listener._passes_filters(event)

    def test_subnet_filter_passes_ip_in_range(self):
        listener = self._listener(subnet_filter=["192.168.1.0/24"])
        event = _make_event(requested_ip="192.168.1.50")
        assert listener._passes_filters(event)

    def test_subnet_filter_blocks_ip_outside_range(self):
        listener = self._listener(subnet_filter=["192.168.1.0/24"])
        event = _make_event(requested_ip="10.0.0.50")
        assert not listener._passes_filters(event)

    def test_subnet_filter_checks_offered_ip(self):
        listener = self._listener(subnet_filter=["192.168.1.0/24"])
        event = _make_event(
            message_type=DhcpMessageType.OFFER,
            offered_ip="192.168.1.100",
        )
        assert listener._passes_filters(event)

    def test_subnet_filter_checks_client_ip_as_fallback(self):
        listener = self._listener(subnet_filter=["192.168.1.0/24"])
        event = _make_event(
            message_type=DhcpMessageType.REQUEST,
            client_ip="192.168.1.10",
        )
        assert listener._passes_filters(event)

    def test_subnet_filter_blocks_event_with_no_ip(self):
        listener = self._listener(subnet_filter=["192.168.1.0/24"])
        event = _make_event()  # no IPs set
        assert not listener._passes_filters(event)

    # ── combined filters ──

    def test_combined_type_and_subnet_filter(self):
        listener = self._listener(
            subnet_filter=["192.168.1.0/24"],
            message_types=[DhcpMessageType.DISCOVER],
        )
        # Right subnet, right type → pass
        assert listener._passes_filters(
            _make_event(message_type=DhcpMessageType.DISCOVER, requested_ip="192.168.1.5")
        )
        # Right subnet, wrong type → block
        assert not listener._passes_filters(
            _make_event(message_type=DhcpMessageType.REQUEST, requested_ip="192.168.1.5")
        )
        # Wrong subnet, right type → block
        assert not listener._passes_filters(
            _make_event(message_type=DhcpMessageType.DISCOVER, requested_ip="10.0.0.5")
        )


# ═══════════════════════════════════════════════════════════════════
#  DhcpListener lifecycle (mocked AsyncSniffer)
# ═══════════════════════════════════════════════════════════════════

class TestDhcpListenerLifecycle:
    """Tests for DhcpListener start/stop lifecycle."""

    def test_start_creates_sniffer(self):
        mock_sniffer_instance = MagicMock()
        mock_async_sniffer = MagicMock(return_value=mock_sniffer_instance)

        cfg = DhcpListenerConfig()
        events = []
        listener = DhcpListener(cfg, on_event=events.append)

        with patch("lanscape.core.dhcp_listener.AsyncSniffer", mock_async_sniffer):
            listener.start()

        mock_async_sniffer.assert_called_once()
        mock_sniffer_instance.start.assert_called_once()
        assert listener.is_running

        listener.stop()
        mock_sniffer_instance.stop.assert_called_once()
        assert not listener.is_running

    def test_stop_when_not_running_is_safe(self):
        cfg = DhcpListenerConfig()
        listener = DhcpListener(cfg, on_event=lambda e: None)
        listener.stop()  # should not raise

    def test_start_raises_when_already_running(self):
        cfg = DhcpListenerConfig()
        listener = DhcpListener(cfg, on_event=lambda e: None)
        listener._running = True
        with pytest.raises(RuntimeError, match="already running"):
            listener.start()

    def test_context_manager_calls_stop(self):
        cfg = DhcpListenerConfig()
        listener = DhcpListener(cfg, on_event=lambda e: None)
        mock_sniffer = MagicMock()

        # Patch start() so it just marks us as running without touching scapy
        def fake_start():
            listener._sniffer = mock_sniffer
            listener._running = True

        with patch.object(listener, "start", side_effect=fake_start):
            with listener:
                assert listener.is_running

        mock_sniffer.stop.assert_called_once()
        assert not listener.is_running

    def test_context_manager_interface_filter(self):
        cfg = DhcpListenerConfig(interface="eth0")
        listener = DhcpListener(cfg, on_event=lambda e: None)
        assert listener._config.interface == "eth0"


# ═══════════════════════════════════════════════════════════════════
#  DhcpListenerConfig validation
# ═══════════════════════════════════════════════════════════════════

class TestDhcpListenerConfig:
    """Tests for DhcpListenerConfig validation."""
    def test_defaults(self):
        cfg = DhcpListenerConfig()
        assert cfg.subnet_filter is None
        assert cfg.message_types is None
        assert cfg.include_server_messages is True
        assert cfg.interface is None

    def test_subnet_filter_list(self):
        cfg = DhcpListenerConfig(subnet_filter=["192.168.0.0/16", "10.0.0.0/8"])
        assert len(cfg.subnet_filter) == 2

    def test_message_types_list(self):
        cfg = DhcpListenerConfig(message_types=[DhcpMessageType.DISCOVER, DhcpMessageType.REQUEST])
        assert DhcpMessageType.DISCOVER in cfg.message_types
