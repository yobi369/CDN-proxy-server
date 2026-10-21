import unittest

from experiments.load_test import percentile, validate_urls


class LoadTestValidationTests(unittest.TestCase):
    def test_loopback_proxy_can_use_local_http(self):
        validate_urls("http://127.0.0.1:8080/proxy", "https://example.com/asset.js", None)

    def test_remote_proxy_requires_token(self):
        with self.assertRaises(ValueError):
            validate_urls("https://proxy.example.com/proxy", "https://example.com/", None)

    def test_remote_proxy_requires_https(self):
        with self.assertRaises(ValueError):
            validate_urls("http://proxy.example.com/proxy", "https://example.com/", "secret")

    def test_rejects_target_credentials(self):
        with self.assertRaises(ValueError):
            validate_urls("http://127.0.0.1:8080/proxy", "https://user:pass@example.com/", None)

    def test_percentile_handles_empty_and_sorted_values(self):
        self.assertEqual(percentile([], 0.95), 0.0)
        self.assertEqual(percentile([1, 2, 3, 4, 5], 0.95), 4)


if __name__ == "__main__":
    unittest.main()
