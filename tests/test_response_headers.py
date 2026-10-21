import unittest
from cdn_proxy_server import CDNServer


class ResponseHeaderTests(unittest.TestCase):
    def test_case_insensitive_header_merge_replaces_old_value(self):
        headers = {"Cache-Control": "max-age=10", "ETag": '"old"'}
        CDNServer._merge_response_headers(headers, {"cache-control": "max-age=60", "ETag": '"new"'})
        self.assertEqual(headers["cache-control"], "max-age=60")
        self.assertEqual(headers["ETag"], '"new"')
        self.assertNotIn("Cache-Control", headers)
    def test_removes_hop_by_hop_and_connection_nominated_headers(self):
        headers = {
            "Connection": "keep-alive, X-Private-Hop",
            "Keep-Alive": "timeout=5",
            "X-Private-Hop": "do-not-forward",
            "Content-Length": "123",
            "Content-Type": "text/plain",
            "Content-Encoding": "gzip",
        }
        CDNServer._safe_headers(headers)
        self.assertNotIn("Connection", headers)
        self.assertNotIn("Keep-Alive", headers)
        self.assertNotIn("X-Private-Hop", headers)
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(headers["Content-Type"], "text/plain")
        self.assertEqual(headers["Content-Encoding"], "gzip")


if __name__ == "__main__":
    unittest.main()
