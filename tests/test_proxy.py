import os
import tempfile
import unittest
from unittest.mock import patch

from cdn_proxy_server import CDNServer, SlidingWindowLimiter, allowed_target


class URLValidationTests(unittest.TestCase):
    def test_allows_public_https_url(self):
        self.assertEqual(allowed_target('https://example.com/assets/app.js'), (True, ''))

    def test_rejects_unsupported_scheme(self):
        self.assertFalse(allowed_target('file:///etc/passwd')[0])

    def test_rejects_loopback_and_private_addresses(self):
        for url in ('http://127.0.0.1/', 'http://10.0.0.1/', 'http://192.168.1.1/', 'http://[::1]/'):
            with self.subTest(url=url):
                self.assertFalse(allowed_target(url)[0])

    def test_rejects_credentials_and_unusual_ports(self):
        self.assertFalse(allowed_target('https://user:pass@example.com/')[0])
        self.assertFalse(allowed_target('http://example.com:8080/')[0])

    def test_rejects_localhost_names(self):
        self.assertFalse(allowed_target('http://localhost/')[0])
        self.assertFalse(allowed_target('http://service.localhost/')[0])


class LimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_enforces_limit_and_expires_events(self):
        limiter = SlidingWindowLimiter(limit=2, window_seconds=60)
        self.assertTrue(await limiter.allow('client'))
        self.assertTrue(await limiter.allow('client'))
        self.assertFalse(await limiter.allow('client'))
        self.assertLessEqual(len(limiter.events), limiter.max_clients)


class CacheKeyTests(unittest.TestCase):
    def test_cache_key_is_stable_and_not_md5(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'CACHE_DIR': tmp, 'ANALYTICS_DB': os.path.join(tmp, 'analytics.db')}):
            server = CDNServer()
            self.assertEqual(server.cache_key('https://example.com/a'), server.cache_key('https://example.com/a'))
            self.assertNotEqual(server.cache_key('https://example.com/a'), server.cache_key('https://example.com/b'))
            self.assertEqual(len(server.cache_key('https://example.com/a')), 64)


if __name__ == '__main__':
    unittest.main()
