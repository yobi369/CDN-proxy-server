import unittest

from cdn_proxy_server import CDNServer, Config


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks
    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class BoundedBodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_buffers_small_body_until_eof(self):
        old_limit = Config.max_object_bytes
        Config.max_object_bytes = 20
        try:
            server = object.__new__(CDNServer)
            body, overflow = await server._collect_cacheable_body(FakeStream([b"abc", b"def", b"ghi"]))
            self.assertEqual(body, b"abcdefghi")
            self.assertIsNone(overflow)
        finally:
            Config.max_object_bytes = old_limit

    async def test_large_body_returns_bounded_prefix_and_remaining_iterator(self):
        old_limit = Config.max_object_bytes
        Config.max_object_bytes = 5
        try:
            server = object.__new__(CDNServer)
            body, overflow = await server._collect_cacheable_body(FakeStream([b"abc", b"def", b"ghi"]))
            self.assertIsNone(body)
            initial_chunks, iterator = overflow
            remaining = [chunk async for chunk in iterator]
            self.assertEqual(b"".join(initial_chunks + remaining), b"abcdefghi")
            self.assertLessEqual(sum(map(len, initial_chunks)), 5 + 64 * 1024)
        finally:
            Config.max_object_bytes = old_limit


if __name__ == "__main__":
    unittest.main()
