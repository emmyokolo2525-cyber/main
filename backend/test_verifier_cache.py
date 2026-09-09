import time
import unittest
from verifier_cache import VerifierCache
from metrics import collector


class TestVerifierCache(unittest.TestCase):
    def setUp(self):
        collector.reset()
        self.cache = VerifierCache(
            max_size=3,
            positive_ttl_seconds=1.0,
            negative_ttl_seconds=0.1,
        )

    def test_cache_key_determinism(self):
        key1 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        key2 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        self.assertEqual(key1, key2)

    def test_cache_key_collision(self):
        key1 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        key2 = self.cache._get_cache_key("d", "n2", "c", "v", "p", "pi")
        self.assertNotEqual(key1, key2)

    def test_positive_ttl(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", True)
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p", "pi"))

    def test_negative_ttl_expiration(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", False)
        # Should be valid initially
        self.assertFalse(self.cache.get("d", "n", "c", "v", "p", "pi"))
        time.sleep(0.15)
        # Should be expired now
        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p", "pi"))

    def test_lru_eviction(self):
        self.cache.set("d", "n", "c", "v", "p1", "pi", True)
        self.cache.set("d", "n", "c", "v", "p2", "pi", True)
        self.cache.set("d", "n", "c", "v", "p3", "pi", True)
        # max_size is 3, access p1 to make it recent
        self.cache.get("d", "n", "c", "v", "p1", "pi")
        
        # Add a 4th item, should evict p2 (least recently used)
        self.cache.set("d", "n", "c", "v", "p4", "pi", True)
        
        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p2", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p1", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p3", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p4", "pi"))

    def test_invalidate(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", True)
        self.cache.invalidate("d", "n", "c", "v", "p", "pi")
        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p", "pi"))


if __name__ == "__main__":
    unittest.main()
