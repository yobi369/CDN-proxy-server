import unittest
from aiohttp import web
from cdn_proxy_server import AdaptivePolicy, cache_policy, validate_target

class TargetValidationTests(unittest.TestCase):
    def setUp(self):
        self.allowed = frozenset({"example.com", "cdn.example.com"})
    def test_allows_exact_allowlisted_https_host(self):
        self.assertEqual(validate_target("https://example.com/assets.js", self.allowed), "https://example.com/assets.js")
    def test_rejects_unlisted_host(self):
        with self.assertRaises(web.HTTPForbidden):
            validate_target("https://evil.example/path", self.allowed)
    def test_rejects_localhost_when_not_allowlisted(self):
        with self.assertRaises(web.HTTPForbidden):
            validate_target("http://127.0.0.1/admin", self.allowed)
    def test_rejects_credentials(self):
        with self.assertRaises(web.HTTPBadRequest):
            validate_target("https://user:pass@example.com/", self.allowed)
    def test_rejects_non_http_scheme(self):
        with self.assertRaises(web.HTTPBadRequest):
            validate_target("file:///etc/passwd", self.allowed)
    def test_rejects_nonstandard_port(self):
        with self.assertRaises(web.HTTPBadRequest):
            validate_target("https://example.com:8443/", self.allowed)
    def test_empty_allowlist_fails_closed(self):
        with self.assertRaises(web.HTTPForbidden):
            validate_target("https://example.com/", frozenset())

class CachePolicyTests(unittest.TestCase):
    def test_no_store(self):
        self.assertEqual(cache_policy({"Cache-Control": "public, no-store"}, 300, 3600), 0)
    def test_private(self):
        self.assertEqual(cache_policy({"Cache-Control": "private, max-age=600"}, 300, 3600), 0)
    def test_no_cache(self):
        self.assertEqual(cache_policy({"Cache-Control": "no-cache"}, 300, 3600), 0)
    def test_set_cookie(self):
        self.assertEqual(cache_policy({"Set-Cookie": "session=abc"}, 300, 3600), 0)
    def test_caps_ttl(self):
        self.assertEqual(cache_policy({"Cache-Control": "max-age=9000"}, 300, 3600), 3600)
    def test_origin_max_age(self):
        self.assertEqual(cache_policy({"Cache-Control": "public, max-age=120"}, 300, 3600), 120)
    def test_fallback_ttl(self):
        self.assertEqual(cache_policy({}, 300, 3600), 300)

class AdaptivePolicyTests(unittest.TestCase):
    def test_never_extends_origin_ttl(self):
        policy = AdaptivePolicy()
        for _ in range(5):
            policy.record("asset", True)
        self.assertLessEqual(policy.adjust_ttl("asset", 120), 120)
    def test_zero_ttl_stays_zero(self):
        self.assertEqual(AdaptivePolicy().adjust_ttl("asset", 0), 0)
    def test_cold_object_gets_shorter_ttl(self):
        self.assertEqual(AdaptivePolicy().adjust_ttl("cold", 120), 60)

if __name__ == "__main__":
    unittest.main()
