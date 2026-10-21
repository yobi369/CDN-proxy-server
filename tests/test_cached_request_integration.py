import tempfile
import unittest
from pathlib import Path

from cdn_proxy_server import CDNServer, Config


class CachedRequestIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old = {
            "cache_dir": Config.cache_dir,
            "db_path": Config.db_path,
            "allowed_hosts": Config.allowed_hosts,
            "access_token": Config.access_token,
            "host": Config.host,
            "max_cache_bytes": Config.max_cache_bytes,
            "max_object_bytes": Config.max_object_bytes,
        }
        Config.cache_dir = Path(self.temp.name) / "cache"
        Config.db_path = str(Path(self.temp.name) / "analytics.db")
        Config.allowed_hosts = frozenset({"example.com"})
        Config.access_token = ""
        Config.host = "127.0.0.1"
        Config.max_cache_bytes = 10000
        Config.max_object_bytes = 1000
        self.server = CDNServer()
        self.target = "https://example.com/asset.js"
        self.cached_body = b"0123456789"
        self.cached_headers = {
            "ETag": '"v1"',
            "Last-Modified": "Wed, 21 Oct 2026 08:00:00 GMT",
            "Cache-Control": "max-age=300",
            "Content-Type": "application/octet-stream",
        }
        self.assertTrue(await self.server._write_cache(self.target, self.cached_body, self.cached_headers, 300))

    async def asyncTearDown(self):
        for key, value in self.old.items():
            setattr(Config, key, value)
        self.temp.cleanup()

    def request(self, headers):
        return type("Request", (), {
            "remote": "127.0.0.1",
            "headers": headers,
            "query": {"url": self.target},
            "method": "GET",
        })()

    async def test_handler_returns_not_modified_from_fresh_cache(self):
        response = await self.server.handle_request(self.request({"If-None-Match": '"v1"'}))
        self.assertEqual(response.status, 304)
        self.assertEqual(response.headers["X-CDN-Cache"], "HIT")

    async def test_handler_returns_partial_body_from_fresh_cache(self):
        response = await self.server.handle_request(self.request({"Range": "bytes=3-5"}))
        self.assertEqual(response.status, 206)
        self.assertEqual(response.body, b"345")
        self.assertEqual(response.headers["Content-Range"], "bytes 3-5/10")
        self.assertEqual(response.headers["X-CDN-Cache"], "HIT")


if __name__ == "__main__":
    unittest.main()
