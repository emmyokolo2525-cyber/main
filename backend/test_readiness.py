import time
import unittest
from readiness import ReadinessManager, Dependency

class TestReadinessManager(unittest.TestCase):
    def test_all_healthy(self):
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=1.0)
        manager.add_dependency("db", lambda: True, critical=True)
        manager.add_dependency("api", lambda: True, critical=False)
        
        status = manager.check()
        self.assertTrue(status["ok"])
        self.assertEqual(status["db"], "connected")
        self.assertEqual(status["api"], "connected")

    def test_critical_failure(self):
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=1.0)
        manager.add_dependency("db", lambda: False, critical=True)
        
        status = manager.check()
        self.assertFalse(status["ok"])
        self.assertEqual(status["db"], "disconnected")

    def test_non_critical_failure(self):
        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=1.0)
        manager.add_dependency("db", lambda: True, critical=True)
        manager.add_dependency("api", lambda: False, critical=False)
        
        status = manager.check()
        self.assertTrue(status["ok"]) # overall ok is True because api is non-critical
        self.assertEqual(status["db"], "connected")
        self.assertEqual(status["api"], "disconnected")

    def test_timeout(self):
        def slow_check():
            time.sleep(1.0)
            return True

        manager = ReadinessManager(timeout_seconds=0.2, cache_ttl_seconds=1.0)
        manager.add_dependency("slow", slow_check, critical=True)
        
        start = time.time()
        status = manager.check()
        duration = time.time() - start
        
        # Should timeout around 0.2s, definitely < 1.0s
        self.assertLess(duration, 0.8)
        self.assertFalse(status["ok"])
        self.assertEqual(status["slow"], "initializing") # the default cache status because no successful response yet

    def test_cache(self):
        counter = {"count": 0}
        
        def count_check():
            counter["count"] += 1
            return True

        manager = ReadinessManager(timeout_seconds=0.5, cache_ttl_seconds=1.0)
        manager.add_dependency("counter", count_check, critical=True)
        
        # First check
        status = manager.check()
        self.assertTrue(status["ok"])
        self.assertEqual(counter["count"], 1)
        
        # Second check immediately should use cache
        status = manager.check()
        self.assertTrue(status["ok"])
        self.assertEqual(counter["count"], 1)
        
        # Wait for TTL to expire
        time.sleep(1.1)
        
        # Third check should run again
        status = manager.check()
        self.assertTrue(status["ok"])
        self.assertEqual(counter["count"], 2)

if __name__ == "__main__":
    unittest.main()
