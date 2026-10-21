import json
import tempfile
import time
import unittest
from pathlib import Path

from cdn_proxy_server import CDNServer, Config


class CacheStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_cache_dir = Config.cache_dir
        self.old_db_path = Config.db_path
        self.old_max_cache_bytes = Config.max_cache_bytes
        self.old_max_object_bytes = Config.max_object_bytes
        Config.cache_dir = Path(self.temp.name) / "cache"
        Config.db_path = str(Path(self.temp.name) / "analytics.db")
        Config.max_cache_bytes = 300
        Config.max_object_bytes = 100
        self.server = CDNServer()

    async def asyncTearDown(self):
        Config.cache_dir = self.old_cache_dir
        Config.db_path = self.old_db_path
        Config.max_cache_bytes = self.old_max_cache_bytes
        Config.max_object_bytes = self.old_max_object_bytes
        self.temp.cleanup()

    async def test_cache_storage_stays_within_budget(self):
        self.assertTrue(await self.server._write_cache("https://example.com/a", b"a" * 40, {}, 60))
        self.assertTrue(await self.server._write_cache("https://example.com/b", b"b" * 40, {}, 60))
        self.assertLessEqual(self.server._cache_size(), Config.max_cache_bytes)
        self.assertIsNone(await self.server._read_cache("https://example.com/a"))
        self.assertNotIn(self.server._base_key("https://example.com/a"), self.server.cache_index)
        cached = await self.server._read_cache("https://example.com/b")
        self.assertIsNotNone(cached)
        self.assertEqual(cached[0], b"b" * 40)

    async def test_oversized_object_is_not_cached(self):
        self.assertFalse(await self.server._write_cache("https://example.com/large", b"x" * 101, {}, 60))
    async def test_vary_variants_are_isolated_and_purge_together(self):
        old_budget = Config.max_cache_bytes
        Config.max_cache_bytes = 10000
        try:
            target = "https://example.com/localized"
            headers = {"Cache-Control": "max-age=60", "Vary": "Accept-Language"}
            self.assertTrue(await self.server._write_cache(target, b"hello-en", headers, 60, {"Accept-Language": "en"}))
            self.assertTrue(await self.server._write_cache(target, b"bonjour-fr", headers, 60, {"Accept-Language": "fr"}))
            english = await self.server._read_cache(target, {"Accept-Language": "en"})
            french = await self.server._read_cache(target, {"Accept-Language": "fr"})
            absent = await self.server._read_cache(target, {"Accept-Language": "de"})
            self.assertEqual(english[0], b"hello-en")
            self.assertEqual(french[0], b"bonjour-fr")
            self.assertIsNone(absent)
            self.assertTrue(await self.server._delete_cache(target))
            self.assertNotIn(self.server._base_key(target), self.server.cache_index)
            self.assertIsNone(await self.server._read_cache(target, {"Accept-Language": "en"}))
            self.assertIsNone(await self.server._read_cache(target, {"Accept-Language": "fr"}))
        finally:
            Config.max_cache_bytes = old_budget

    async def test_variant_index_rebuilds_after_restart(self):
        old_budget = Config.max_cache_bytes
        Config.max_cache_bytes = 10000
        try:
            target = "https://example.com/restart"
            headers = {"Cache-Control": "max-age=60", "Vary": "Accept-Language"}
            self.assertTrue(await self.server._write_cache(target, b"english", headers, 60, {"Accept-Language": "en"}))
            restarted = CDNServer()
            cached = await restarted._read_cache(target, {"Accept-Language": "en"})
            self.assertEqual(cached[0], b"english")
        finally:
            Config.max_cache_bytes = old_budget

    async def test_origin_vary_shape_change_invalidates_old_variants(self):
        old_budget = Config.max_cache_bytes
        Config.max_cache_bytes = 10000
        try:
            target = "https://example.com/changing-vary"
            self.assertTrue(await self.server._write_cache(
                target, b"english", {"Cache-Control": "max-age=60", "Vary": "Accept-Language"},
                60, {"Accept-Language": "en"}))
            self.assertTrue(await self.server._write_cache(
                target, b"common", {"Cache-Control": "max-age=60"}, 60, {"Accept-Language": "en"}))
            cached = await self.server._read_cache(target, {"Accept-Language": "en"})
            self.assertEqual(cached[0], b"common")
            base_key = self.server._base_key(target)
            self.assertEqual(len(list(Config.cache_dir.glob(f"{base_key}-*.json"))), 0)
        finally:
            Config.max_cache_bytes = old_budget

    async def test_expired_entry_can_be_loaded_for_revalidation(self):
        target = "https://example.com/revalidate"
        self.assertTrue(await self.server._write_cache(target, b"cached", {"ETag": '"v1"'}, 1))
        _, meta_path = self.server._paths(target)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["stored_at"] = time.time() - 10
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        self.assertIsNone(await self.server._read_cache(target))
        stale = await self.server._read_stale_cache(target)
        self.assertIsNotNone(stale)
        self.assertEqual(stale[0], b"cached")


if __name__ == "__main__":
    unittest.main()
