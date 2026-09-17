import unittest

from validators import validate_target


class ValidatorTests(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")

    def test_invalid_ip_address(self):
        with self.assertRaises(ValueError):
            validate_target("999.1.1.1")

    def test_valid_hostname(self):
        self.assertEqual(validate_target("localhost"), "localhost")

    def test_invalid_empty_target(self):
        with self.assertRaises(ValueError):
            validate_target("   ")


if __name__ == "__main__":
    unittest.main()
