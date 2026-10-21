import sqlite3
import tempfile
import unittest
from pathlib import Path

from cdn_proxy_server import CDNServer, Config


class AnalyticsPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db_path = Config.db_path
        self.old_log_client_ip = Config.log_client_ip
        Config.db_path = str(Path(self.temp.name) / "analytics.db")
        with sqlite3.connect(Config.db_path) as conn:
            conn.execute("""CREATE TABLE requests (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, client_ip TEXT,
                target_host TEXT NOT NULL, cache_status TEXT NOT NULL,
                response_size INTEGER NOT NULL, response_time_ms REAL NOT NULL)""")

    def tearDown(self):
        Config.db_path = self.old_db_path
        Config.log_client_ip = self.old_log_client_ip
        self.temp.cleanup()

    def read_client_ip(self):
        with sqlite3.connect(Config.db_path) as conn:
            return conn.execute("SELECT client_ip FROM requests").fetchone()[0]

    def test_client_ip_is_not_persisted_by_default(self):
        Config.log_client_ip = False
        CDNServer._log_sync("192.0.2.10", "example.com", "MISS", 10, 2.0)
        self.assertIsNone(self.read_client_ip())

    def test_client_ip_can_be_enabled_explicitly(self):
        Config.log_client_ip = True
        CDNServer._log_sync("192.0.2.10", "example.com", "MISS", 10, 2.0)
        self.assertEqual(self.read_client_ip(), "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
