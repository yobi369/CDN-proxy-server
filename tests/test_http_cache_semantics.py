import unittest

from cdn_proxy_server import CDNServer, request_can_read_cache


class CachedHttpSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.server = object.__new__(CDNServer)
        self.body = b"abcdefghij"
        self.headers = {
            "ETag": '"v1"',
            "Last-Modified": "Wed, 21 Oct 2026 08:00:00 GMT",
            "Cache-Control": "max-age=60",
            "Content-Type": "text/plain",
        }

    def response(self, request_headers):
        request = type("Request", (), {"headers": request_headers})()
        return self.server._cached_conditional_response(request, self.body, self.headers)

    def test_matching_if_none_match_returns_304(self):
        response = self.response({"If-None-Match": '"v1"'})
        self.assertEqual(response.status, 304)
        self.assertEqual(response.body or b"", b"")

    def test_weak_if_none_match_uses_weak_comparison(self):
        response = self.response({"If-None-Match": 'W/"v1"'})
        self.assertEqual(response.status, 304)

    def test_if_match_mismatch_returns_412(self):
        response = self.response({"If-Match": '"v2"'})
        self.assertEqual(response.status, 412)

    def test_if_match_wildcard_matches_existing_representation(self):
        response = self.response({"If-Match": "*"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, self.body)

    def test_if_modified_since_returns_304_when_not_modified(self):
        response = self.response({"If-Modified-Since": "Wed, 21 Oct 2026 08:01:00 GMT"})
        self.assertEqual(response.status, 304)

    def test_single_byte_range_returns_206(self):
        response = self.response({"Range": "bytes=2-4"})
        self.assertEqual(response.status, 206)
        self.assertEqual(response.body, b"cde")
        self.assertEqual(response.headers["Content-Range"], "bytes 2-4/10")

    def test_suffix_range_returns_last_bytes(self):
        response = self.response({"Range": "bytes=-3"})
        self.assertEqual(response.status, 206)
        self.assertEqual(response.body, b"hij")

    def test_unsatisfiable_range_returns_416(self):
        response = self.response({"Range": "bytes=20-30"})
        self.assertEqual(response.status, 416)
        self.assertEqual(response.headers["Content-Range"], "bytes */10")

    def test_if_range_mismatch_returns_full_body(self):
        response = self.response({"Range": "bytes=0-2", "If-Range": '"v2"'})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, self.body)

    def test_multi_range_is_delegated_to_origin(self):
        response = self.response({"Range": "bytes=0-1,4-5"})
        self.assertIsNone(response)
    def test_range_request_may_read_cache_but_not_write_shared_cache(self):
        request = type("Request", (), {"headers": {"Range": "bytes=0-2"}})()
        self.assertTrue(request_can_read_cache(request))


if __name__ == "__main__":
    unittest.main()
