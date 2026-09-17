import tempfile
import unittest
from pathlib import Path

from database import get_results_by_target, get_scan_history, initialize_database, save_results


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_directory.name) / "test.db"
        self.results = [{
            "target": "127.0.0.1",
            "port": 80,
            "protocol": "tcp",
            "status": "closed",
            "service": "http",
            "scan_time": "2026-09-17T12:00:00",
        }]

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_database_initialization(self):
        initialize_database(self.database_path)
        self.assertTrue(self.database_path.exists())

    def test_save_and_read_history(self):
        self.assertEqual(save_results(self.results, self.database_path), 1)
        history = get_scan_history(self.database_path)
        self.assertEqual(history[0]["port"], 80)

    def test_read_results_by_target(self):
        save_results(self.results, self.database_path)
        matching = get_results_by_target("127.0.0.1", self.database_path)
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["target"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
