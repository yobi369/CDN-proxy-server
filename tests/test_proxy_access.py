import unittest

from cdn_proxy_server import CDNServer, Config


class ProxyAccessTests(unittest.TestCase):
    def setUp(self):
        self.old_token = Config.access_token
        self.old_host = Config.host

    def tearDown(self):
        Config.access_token = self.old_token
        Config.host = self.old_host

    def request(self, headers):
        return type("Request", (), {"headers": headers})()

    def test_accepts_correct_proxy_token(self):
        Config.access_token = "test-secret"
        self.assertTrue(CDNServer._proxy_authorized(object.__new__(CDNServer), self.request({"X-Proxy-Token": "test-secret"})))

    def test_rejects_wrong_proxy_token(self):
        Config.access_token = "test-secret"
        self.assertFalse(CDNServer._proxy_authorized(object.__new__(CDNServer), self.request({"X-Proxy-Token": "wrong"})))

    def test_tokenless_mode_only_allows_loopback_binding(self):
        Config.access_token = ""
        Config.host = "127.0.0.1"
        server = object.__new__(CDNServer)
        self.assertTrue(server._proxy_authorized(self.request({})))
        Config.host = "0.0.0.0"
        self.assertFalse(server._proxy_authorized(self.request({})))


if __name__ == "__main__":
    unittest.main()
