import unittest
from aiohttp import web
from cdn_proxy_server import AdaptivePolicy, cache_policy, is_public_ip, request_may_use_cache, validate_target

class PublicAddressTests(unittest.TestCase):
    def test_public_ipv4_is_allowed(self):
        self.assertTrue(is_public_ip("8.8.8.8"))
    def test_loopback_is_rejected(self):
        self.assertFalse(is_public_ip("127.0.0.1"))
    def test_link_local_metadata_range_is_rejected(self):
        self.assertFalse(is_public_ip("169.254.169.254"))
    def test_ipv6_loopback_is_rejected(self):
        self.assertFalse(is_public_ip("::1"))
    def test_invalid_ip_is_rejected(self):
        self.assertFalse(is_public_ip("not-an-ip"))

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
    def test_rejects_wrong_default_port_for_scheme(self):
        with self.assertRaises(web.HTTPBadRequest):
            validate_target("https://example.com:80/", self.allowed)
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
    def test_vary_response_is_not_cached_without_vary_aware_key(self):
        self.assertEqual(cache_policy({"Vary": "Accept-Language", "Cache-Control": "max-age=60"}, 300, 3600), 0)
    def test_lowercase_set_cookie_is_not_cached(self):
        self.assertEqual(cache_policy({"set-cookie": "session=abc"}, 300, 3600), 0)
    def test_caps_ttl(self):
        self.assertEqual(cache_policy({"Cache-Control": "max-age=9000"}, 300, 3600), 3600)
    def test_origin_max_age(self):
        self.assertEqual(cache_policy({"Cache-Control": "public, max-age=120"}, 300, 3600), 120)
    def test_fallback_ttl(self):
        self.assertEqual(cache_policy({}, 300, 3600), 300)
    def test_expires_header_sets_freshness(self):
        headers = {"Date": "Wed, 21 Oct 2026 08:00:00 GMT", "Expires": "Wed, 21 Oct 2026 08:01:00 GMT"}
        self.assertEqual(cache_policy(headers, 300, 3600), 60)
    def test_age_reduces_remaining_freshness(self):
        headers = {"Cache-Control": "max-age=60", "Age": "20"}
        self.assertEqual(cache_policy(headers, 300, 3600), 40)
    def test_expired_expires_is_not_cached(self):
        headers = {"Date": "Wed, 21 Oct 2026 08:00:00 GMT", "Expires": "Wed, 21 Oct 2026 07:59:00 GMT"}
        self.assertEqual(cache_policy(headers, 300, 3600), 0)
    def test_pragma_no_cache_is_not_cached(self):
        self.assertEqual(cache_policy({"Pragma": "no-cache"}, 300, 3600), 0)

class RequestCacheSafetyTests(unittest.TestCase):
    def test_authorized_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Authorization": "Bearer private"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_cookie_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Cookie": "session=private"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_no_cache_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Cache-Control": "no-cache"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_pragma_no_cache_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Pragma": "no-cache"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_max_age_zero_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Cache-Control": "max-age=0"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_public_request_can_use_cache(self):
        request = type("Request", (), {"headers": {}})()
        self.assertTrue(request_may_use_cache(request))
    def test_range_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"Range": "bytes=0-10"}})()
        self.assertFalse(request_may_use_cache(request))
    def test_conditional_request_bypasses_shared_cache(self):
        request = type("Request", (), {"headers": {"If-None-Match": '"v1"'}})()
        self.assertFalse(request_may_use_cache(request))

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
    def test_history_is_bounded(self):
        policy = AdaptivePolicy(max_keys=2)
        policy.record("a", False)
        policy.record("b", False)
        policy.record("c", False)
        self.assertEqual(len(policy.counts), 2)
        self.assertNotIn("a", policy.counts)

if __name__ == "__main__":
    unittest.main()
