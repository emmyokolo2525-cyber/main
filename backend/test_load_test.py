"""Unit tests for the privacy-safe load and soak testing framework."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from load_test import (
    LoadConfig,
    LoadResult,
    LoadTestRunner,
    SyntheticCorpus,
    Tier,
)


class TestLoadConfig(unittest.TestCase):
    """Test configuration dataclass and defaults."""

    def test_default_values(self) -> None:
        config = LoadConfig()
        self.assertEqual(config.base_url, "http://127.0.0.1:5050")
        self.assertEqual(config.concurrency, 4)
        self.assertEqual(config.total_operations, 100)
        self.assertEqual(config.ramp_up_seconds, 10.0)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.backpressure_threshold_ms, 5000.0)
        self.assertEqual(config.soak_duration_minutes, 10)

    def test_custom_values(self) -> None:
        config = LoadConfig(
            base_url="http://localhost:9999",
            concurrency=8,
            total_operations=500,
            ramp_up_seconds=30.0,
            backpressure_threshold_ms=10000.0,
            soak_duration_minutes=60,
        )
        self.assertEqual(config.base_url, "http://localhost:9999")
        self.assertEqual(config.concurrency, 8)
        self.assertEqual(config.total_operations, 500)
        self.assertEqual(config.soak_duration_minutes, 60)


class TestTier(unittest.TestCase):
    """Test the Tier enum."""

    def test_tier_values(self) -> None:
        self.assertEqual(Tier.SILENT.value, "silent")
        self.assertEqual(Tier.SOURCE.value, "source")
        self.assertEqual(Tier.SEAL.value, "seal")


class TestLoadResult(unittest.TestCase):
    """Test the LoadResult dataclass and its properties."""

    def setUp(self) -> None:
        self.result = LoadResult(
            operation="embed",
            total_ops=100,
            succeeded=95,
            failed=5,
            latencies_ms=[10.0, 20.0, 30.0, 40.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0],
            errors=["error1", "error2"],
            start_time=1000.0,
            end_time=1100.0,
        )

    def test_throughput(self) -> None:
        expected = 100 / 100  # 100 ops in 100 seconds
        self.assertAlmostEqual(self.result.throughput, expected)

    def test_success_rate(self) -> None:
        self.assertAlmostEqual(self.result.success_rate, 95.0)

    def test_zero_operations(self) -> None:
        empty = LoadResult(
            operation="empty", total_ops=0, succeeded=0, failed=0,
            latencies_ms=[], start_time=0, end_time=0,
        )
        self.assertEqual(empty.throughput, 0.0)
        self.assertEqual(empty.success_rate, 0.0)
        self.assertEqual(empty.percentile(50), 0.0)

    def test_percentile(self) -> None:
        self.assertAlmostEqual(self.result.percentile(50), 50.0)
        self.assertAlmostEqual(self.result.percentile(90), 1000.0)
        self.assertAlmostEqual(self.result.percentile(95), 2000.0)
        self.assertAlmostEqual(self.result.percentile(99), 2000.0)

    def test_summary_structure(self) -> None:
        summary = self.result.summary()
        self.assertIn("operation", summary)
        self.assertIn("success_rate_pct", summary)
        self.assertIn("throughput_ops_per_sec", summary)
        self.assertIn("latency_ms", summary)
        self.assertIn("errors", summary)
        self.assertEqual(summary["operation"], "embed")
        self.assertAlmostEqual(summary["success_rate_pct"], 95.0)


class TestSyntheticCorpus(unittest.TestCase):
    """Test the synthetic corpus generator."""

    def setUp(self) -> None:
        self.config = LoadConfig()
        self.corpus = SyntheticCorpus(self.config)

    def tearDown(self) -> None:
        self.corpus.cleanup()

    def test_create_synthetic_metadata_silent(self) -> None:
        metadata = self.corpus.create_synthetic_metadata(Tier.SILENT)
        self.assertEqual(metadata["protocol"], "harpocrates")
        self.assertEqual(metadata["tier"], "silent")
        self.assertEqual(metadata["version"], 1)
        self.assertIn("sourceHash", metadata)
        self.assertIn("proofId", metadata)
        self.assertIn("timestamp", metadata)
        self.assertTrue(metadata.get("synthetic"))

    def test_create_synthetic_metadata_source(self) -> None:
        metadata = self.corpus.create_synthetic_metadata(Tier.SOURCE)
        self.assertEqual(metadata["tier"], "source")

    def test_create_synthetic_metadata_seal(self) -> None:
        metadata = self.corpus.create_synthetic_metadata(Tier.SEAL)
        self.assertEqual(metadata["tier"], "seal")

    def test_create_synthetic_metadata_unique_proof_ids(self) -> None:
        ids = set()
        for _ in range(10):
            metadata = self.corpus.create_synthetic_metadata()
            ids.add(metadata["proofId"])
        self.assertEqual(len(ids), 10)

    def test_create_synthetic_registration_payload(self) -> None:
        payload = self.corpus.create_synthetic_registration_payload(Tier.SILENT)
        self.assertIn("videoHash", payload)
        self.assertIn("metadataHash", payload)
        self.assertIn("proofId", payload)
        self.assertEqual(payload["tier"], "silent")
        self.assertEqual(payload["txStatus"], "SYNTHETIC")
        self.assertTrue(payload.get("synthetic"))

    def test_registration_payload_hex_length(self) -> None:
        payload = self.corpus.create_synthetic_registration_payload()
        self.assertEqual(len(payload["videoHash"]), 64)
        self.assertEqual(len(payload["metadataHash"]), 64)
        self.assertEqual(len(payload["proofId"]), 64)

    def test_cleanup_removes_temp_dir(self) -> None:
        tmp_dir = self.corpus._tmp_dir
        self.assertTrue(Path(tmp_dir).exists())
        self.corpus.cleanup()
        self.assertFalse(Path(tmp_dir).exists())


class TestLoadTestRunner(unittest.TestCase):
    """Test the LoadTestRunner (unit-level, without backend)."""

    def setUp(self) -> None:
        self.config = LoadConfig(total_operations=10, soak_duration_minutes=0)
        self.runner = LoadTestRunner(self.config)

    def tearDown(self) -> None:
        self.runner.cleanup()

    def test_check_thresholds_no_violations(self) -> None:
        """No violations when all results are clean."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=10,
            failed=0,
            latencies_ms=[100.0] * 10,
            start_time=0,
            end_time=10,
        )
        violations = self.runner.check_thresholds()
        self.assertEqual(violations, [])

    def test_check_thresholds_success_rate(self) -> None:
        """Violation when success rate is too low."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=5,
            failed=5,
            latencies_ms=[100.0] * 10,
            start_time=0,
            end_time=10,
        )
        violations = self.runner.check_thresholds()
        self.assertTrue(any("success rate" in v for v in violations))

    def test_check_thresholds_memory_leak(self) -> None:
        """Violation when memory delta exceeds threshold."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=10,
            failed=0,
            latencies_ms=[100.0] * 10,
            peak_memory_mb=200.0,  # Above 100 MB threshold
            start_time=0,
            end_time=10,
        )
        violations = self.runner.check_thresholds()
        self.assertTrue(any("memory" in v for v in violations))

    def test_check_thresholds_disk_leak(self) -> None:
        """Violation when disk delta exceeds threshold."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=10,
            failed=0,
            latencies_ms=[100.0] * 10,
            disk_delta_mb=1000.0,  # Above 500 MB threshold
            start_time=0,
            end_time=10,
        )
        violations = self.runner.check_thresholds()
        self.assertTrue(any("disk" in v for v in violations))

    def test_generate_report(self) -> None:
        """Report is valid JSON with expected structure."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=10,
            failed=0,
            latencies_ms=[100.0] * 10,
            start_time=0,
            end_time=10,
        )
        report = self.runner.generate_report()
        parsed = json.loads(report)
        self.assertIn("config", parsed)
        self.assertIn("results", parsed)
        self.assertIn("violations", parsed)
        self.assertIn("passed", parsed)
        self.assertIn("timestamp", parsed)
        self.assertTrue(parsed["passed"])

    def test_generate_report_to_file(self) -> None:
        """Report is written to file when output_path is specified."""
        self.runner.results["embed"] = LoadResult(
            operation="embed",
            total_ops=10,
            succeeded=10,
            failed=0,
            latencies_ms=[100.0] * 10,
            start_time=0,
            end_time=10,
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            self.runner.generate_report(report_path)
            saved = json.loads(Path(report_path).read_text())
            self.assertIn("results", saved)
        finally:
            Path(report_path).unlink(missing_ok=True)


class TestNegativePaths(unittest.TestCase):
    """Test negative/failure paths in the load testing framework."""

    def test_empty_latencies(self) -> None:
        result = LoadResult(
            operation="test", total_ops=0, succeeded=0, failed=0,
            latencies_ms=[], start_time=0, end_time=0,
        )
        self.assertEqual(result.percentile(50), 0.0)

    def test_single_latency(self) -> None:
        result = LoadResult(
            operation="test", total_ops=1, succeeded=1, failed=0,
            latencies_ms=[42.0], start_time=0, end_time=1,
        )
        self.assertEqual(result.percentile(50), 42.0)
        self.assertEqual(result.percentile(99), 42.0)

    def test_large_error_count_truncation(self) -> None:
        """Errors list should not grow unbounded in LoadResult."""
        errors = [f"error_{i}" for i in range(1000)]
        result = LoadResult(
            operation="test", total_ops=1000, succeeded=500, failed=500,
            latencies_ms=[100.0] * 1000, errors=errors,
            start_time=0, end_time=100,
        )
        summary = result.summary()
        self.assertLessEqual(len(summary["errors"]), 10)


if __name__ == "__main__":
    unittest.main()
