import errno
import unittest

from scanner import PortInputError, _status_from_connection_code, parse_ports


class PortParserTests(unittest.TestCase):
    def test_individual_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_port_range(self):
        self.assertEqual(parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_duplicates_are_removed_and_sorted(self):
        self.assertEqual(parse_ports("80,22,80,22-23"), [22, 23, 80])

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(PortInputError):
            parse_ports("0,80")

    def test_reversed_range_is_rejected(self):
        with self.assertRaises(PortInputError):
            parse_ports("100-1")

    def test_connection_codes_are_classified(self):
        self.assertEqual(_status_from_connection_code(0), "open")
        self.assertEqual(_status_from_connection_code(errno.ECONNREFUSED), "closed")
        self.assertEqual(_status_from_connection_code(10060), "timeout")
        self.assertEqual(_status_from_connection_code(10035), "timeout")
        self.assertEqual(_status_from_connection_code(10065), "timeout")
        self.assertEqual(_status_from_connection_code(10013), "error")


if __name__ == "__main__":
    unittest.main()
