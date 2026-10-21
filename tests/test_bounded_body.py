import unittest

from aiohttp import web
from cdn_proxy_server import CDNServer, Config


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks
    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class BoundedBodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_all_chunks_until_eof(self):
        old_limit = Config.max_object_bytes
        Config.max_object_bytes = 20
        try:
            server = object.__new__(CDNServer)
            body = await server._read_bounded_body(FakeStream([b"abc", b"def", b"ghi"]))
            self.assertEqual(body, b"abcdefghi")
        finally:
            Config.max_object_bytes = old_limit

    async def test_rejects_body_that_exceeds_limit_across_chunks(self):
        old_limit = Config.max_object_bytes
        Config.max_object_bytes = 5
        try:
            server = object.__new__(CDNServer)
            with self.assertRaises(web.HTTPBadGateway):
                await server._read_bounded_body(FakeStream([b"abc", b"def"]))
        finally:
            Config.max_object_bytes = old_limit


if __name__ == "__main__":
    unittest.main()
