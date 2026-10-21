import unittest
from cdn_proxy_server import CDNServer


class OriginRequestHeaderTests(unittest.TestCase):
    def test_forwards_selected_headers_without_host_or_hop_by_hop(self):
        request = type("Request", (), {"headers": {
            "Accept": "text/css",
            "Authorization": "Bearer origin-token",
            "X-Proxy-Token": "proxy-secret",
            "Cookie": "session=value",
            "Host": "attacker.invalid",
            "Connection": "keep-alive",
            "X-Internal": "drop-me",
        }})()
        headers = CDNServer._origin_request_headers(request)
        self.assertEqual(headers["Accept"], "text/css")
        self.assertEqual(headers["Authorization"], "Bearer origin-token")
        self.assertNotIn("X-Proxy-Token", headers)
        self.assertEqual(headers["Cookie"], "session=value")
        self.assertNotIn("Host", headers)
        self.assertNotIn("Connection", headers)
        self.assertNotIn("X-Internal", headers)
        self.assertEqual(headers["Accept-Encoding"], "identity")

    def test_preserves_client_accept_encoding_when_present(self):
        request = type("Request", (), {"headers": {"Accept-Encoding": "gzip"}})()
        headers = CDNServer._origin_request_headers(request)
        self.assertEqual(headers["Accept-Encoding"], "gzip")


if __name__ == "__main__":
    unittest.main()
