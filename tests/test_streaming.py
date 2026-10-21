import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from cdn_proxy_server import CDNServer, Config


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks
    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class FakeOriginResponse:
    def __init__(self, body_chunks, headers=None, status=200):
        self.status = status
        self.headers = headers or {}
        self.content = FakeStream(body_chunks)


class FakeContext:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, response):
        self.response = response
    def get(self, target, headers, allow_redirects):
        return FakeContext(self.response)


class StreamingResponseTests(unittest.IsolatedAsyncioTestCase):
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
        Config.max_object_bytes = 5
        self.server = CDNServer()
        self.app = web.Application()
        self.app.router.add_get("/proxy", self.server.handle_request, allow_head=False)
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        for key, value in self.old.items():
            setattr(Config, key, value)
        self.temp.cleanup()

    async def fetch_with(self, target, fake_origin):
        self.server.session = FakeSession(fake_origin)
        response = await self.client.get("/proxy", params={"url": target})
        body = await response.read()
        return response, body

    async def test_known_large_response_streams_without_caching(self):
        target = "https://example.com/large-known"
        origin = FakeOriginResponse([b"abc", b"def", b"ghi"], {"Content-Length": "9"})
        response, body = await self.fetch_with(target, origin)
        self.assertEqual(response.status, 200)
        self.assertEqual(body, b"abcdefghi")
        self.assertEqual(response.headers["X-CDN-Cache"], "BYPASS")
        self.assertIsNone(await self.server._read_cache(target))

    async def test_unknown_length_overflow_streams_buffered_prefix_and_remainder(self):
        target = "https://example.com/large-unknown"
        origin = FakeOriginResponse([b"abc", b"def", b"ghi"])
        response, body = await self.fetch_with(target, origin)
        self.assertEqual(response.status, 200)
        self.assertEqual(body, b"abcdefghi")
        self.assertEqual(response.headers["X-CDN-Cache"], "BYPASS")
        self.assertIsNone(await self.server._read_cache(target))


if __name__ == "__main__":
    unittest.main()
