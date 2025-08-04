import unittest
from lanscape.libraries.ip_parser import parse_ip_input
from lanscape.libraries.errors import SubnetTooLargeError
import ipaddress
from lanscape.libraries import ip_parser
from lanscape.libraries.port_manager import PortManager
from lanscape.libraries.decorators import timeout_enforcer
import time


class IPParserTests(unittest.TestCase):
    def test_parse_cidr(self):
        ips = parse_ip_input('192.168.0.0/30')
        self.assertEqual([str(ip) for ip in ips], [
                         '192.168.0.1', '192.168.0.2'])

    def test_parse_range(self):
        ips = parse_ip_input('10.0.0.1-10.0.0.3')
        self.assertEqual(len(ips), 3)
        self.assertEqual(str(ips[0]), '10.0.0.1')
        self.assertEqual(str(ips[-1]), '10.0.0.3')

    def test_parse_shorthand_range(self):
        ips = parse_ip_input('10.0.0.1-3')
        self.assertEqual([str(ip) for ip in ips], [
                         '10.0.0.1', '10.0.0.2', '10.0.0.3'])

    def test_parse_too_large_subnet(self):
        with self.assertRaises(SubnetTooLargeError):
            parse_ip_input('10.0.0.0/8')

    def test_parse_ip_input_mixed(self):
        ip_input = "10.0.0.1/30, 10.0.0.10-10.0.0.12, 10.0.0.20-22, 10.0.0.50"
        result = ip_parser.parse_ip_input(ip_input)
        expected = [
            ipaddress.IPv4Address("10.0.0.1"),
            ipaddress.IPv4Address("10.0.0.2"),
            ipaddress.IPv4Address("10.0.0.10"),
            ipaddress.IPv4Address("10.0.0.11"),
            ipaddress.IPv4Address("10.0.0.12"),
            ipaddress.IPv4Address("10.0.0.20"),
            ipaddress.IPv4Address("10.0.0.21"),
            ipaddress.IPv4Address("10.0.0.22"),
            ipaddress.IPv4Address("10.0.0.50"),
        ]
        self.assertEqual(result, expected)


class PortManagerValidateTests(unittest.TestCase):
    def setUp(self):
        # Avoid running __init__ which touches the filesystem
        self.pm = PortManager.__new__(PortManager)

    def test_validate_port_data_valid(self):
        valid = {"80": "http", "443": "https"}
        self.assertTrue(self.pm.validate_port_data(valid))

    def test_validate_port_data_invalid(self):
        invalid_cases = [
            {"-1": "neg"},  # negative port
            {"70000": "too_high"},  # port out of range
            {"abc": "not_int"},  # non-integer port
            {"80": 123},  # service not a string
        ]
        for case in invalid_cases:
            with self.subTest(case=case):
                self.assertFalse(self.pm.validate_port_data(case))


class DecoratorTimeoutTests(unittest.TestCase):
    def test_timeout_enforcer(self):
        @timeout_enforcer(0.1, raise_on_timeout=False)
        def slow_return():
            time.sleep(0.5)
            return "done"

        self.assertIsNone(slow_return())

        @timeout_enforcer(0.1, raise_on_timeout=True)
        def slow_raise():
            time.sleep(0.2)
            return "done"

        with self.assertRaises(TimeoutError):
            slow_raise()
