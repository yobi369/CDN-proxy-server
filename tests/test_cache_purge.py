import json
import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from cdn_proxy_server import CDNServer, Config


class CachePurgeTests(unittest.IsolatedAsyncioTestCase):
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

    async def asyncTearDown(self):
        for key, value in self.old.items():
            setattr(Config, key, value)
        self.temp.cleanup()

    def request(self, headers=None):
        return type("Request", (), {
            "remote": "127.0.0.1",
            "headers": headers or {},
            "query": {"url": "https://example.com/file.js"},
        })()

    async def test_purge_removes_cached_representation(self):
        target = "https://example.com/file.js"
        self.assertTrue(await self.server._write_cache(target, b"payload", {"ETag": '"v1"'}, 60))
        response = await self.server.purge_handler(self.request())
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(response.text)["purged"])
        self.assertIsNone(await self.server._read_stale_cache(target))
        self.assertEqual(self.server.stats["purges"], 1)

    async def test_purge_requires_token_when_configured(self):
        Config.access_token = "secret"
        with self.assertRaises(web.HTTPUnauthorized):
            await self.server.purge_handler(self.request())


if __name__ == "__main__":
    unittest.main()
