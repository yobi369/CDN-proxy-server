import unittest
from collections import defaultdict, deque
from unittest.mock import patch

from cdn_proxy_server import CDNServer


class RateLimitBoundTests(unittest.TestCase):
    def test_expired_client_buckets_are_pruned_before_capacity_rejection(self):
        server = object.__new__(CDNServer)
        server.rate_events = defaultdict(deque)
        for index in range(10000):
            server.rate_events[f"client-{index}"].append(0.0)
        with patch("cdn_proxy_server.time.monotonic", return_value=100.0):
            self.assertFalse(server._rate_limited("new-client"))
        self.assertEqual(len(server.rate_events), 1)
        self.assertIn("new-client", server.rate_events)


if __name__ == "__main__":
    unittest.main()
