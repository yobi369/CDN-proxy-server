import tempfile
import time
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path

from cdn_proxy_server import CDNServer, Config


class EmptyStream:
    async def iter_chunked(self, size):
        if False:
            yield b""


class FakeOriginResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers
        self.content = EmptyStream()


class FakeResponseContext:
    def __init__(self, response):
        self.response = response
    async def __aenter__(self):
        return self.response
    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.request_headers = None
    def get(self, target, headers, allow_redirects):
        self.request_headers = headers
        return FakeResponseContext(self.response)


class RevalidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old = {
            "cache_dir": Config.cache_dir,
            "db_path": Config.db_path,
            "max_cache_bytes": Config.max_cache_bytes,
            "max_object_bytes": Config.max_object_bytes,
            "allowed_hosts": Config.allowed_hosts,
        }
        Config.cache_dir = Path(self.temp.name) / "cache"
        Config.db_path = str(Path(self.temp.name) / "analytics.db")
        Config.max_cache_bytes = 10000
        Config.max_object_bytes = 1000
        Config.allowed_hosts = frozenset({"example.com"})
        self.server = CDNServer()

    async def asyncTearDown(self):
        for key, value in self.old.items():
            setattr(Config, key, value)
        self.temp.cleanup()

    async def test_expired_etag_entry_is_revalidated_and_served(self):
        target = "https://example.com/asset.js"
        original_headers = {
            "ETag": '"v1"',
            "Cache-Control": "max-age=1",
            "Content-Type": "text/plain",
        }
        self.assertTrue(await self.server._write_cache(target, b"cached-body", original_headers, 1))
        _, meta_path = self.server._paths(target)
        import json
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["stored_at"] = time.time() - 10
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        response_date = format_datetime(datetime.now(timezone.utc), usegmt=True)
        fake_session = FakeSession(FakeOriginResponse(304, {
            "ETag": '"v1"',
            "Cache-Control": "max-age=60",
            "Date": response_date,
        }))
        self.server.session = fake_session
        request = type("Request", (), {
            "remote": "127.0.0.1",
            "headers": {},
            "query": {"url": target},
            "method": "GET",
        })()

        response = await self.server.handle_request(request)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"cached-body")
        self.assertEqual(response.headers["X-CDN-Cache"], "REVALIDATED")
        self.assertEqual(fake_session.request_headers["If-None-Match"], '"v1"')
        self.assertEqual(self.server.stats["revalidations"], 1)
        self.assertIsNotNone(await self.server._read_cache(target))


if __name__ == "__main__":
    unittest.main()
