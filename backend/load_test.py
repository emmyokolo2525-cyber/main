"""
Privacy-safe load and soak testing framework for Harpocrates.

Validates sustained uploads, processing, proof registration, event queries,
and verification without using real evidence. All test data is synthetic
and contains no real media, credentials, or proof material.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import requests


class Tier(Enum):
    SILENT = "silent"
    SOURCE = "source"
    SEAL = "seal"


@dataclass(frozen=True)
class LoadConfig:
    """Typed configuration for load/soak test runs."""

    base_url: str = "http://127.0.0.1:5050"
    concurrency: int = 4
    total_operations: int = 100
    ramp_up_seconds: float = 10.0
    max_retries: int = 3
    backpressure_threshold_ms: float = 5000.0
    synthetic_video_resolution: str = "320x240"
    synthetic_video_duration: int = 3
    payload_sizes: list[int] = field(default_factory=lambda: [100, 1000, 10000])
    soak_duration_minutes: int = 10
    latency_percentiles: list[float] = field(default_factory=lambda: [50, 75, 90, 95, 99])
    memory_leak_threshold_mb: float = 100.0
    disk_leak_threshold_mb: float = 500.0


@dataclass
class LoadResult:
    """Collected metrics from a load test run."""

    operation: str
    total_ops: int
    succeeded: int
    failed: int
    latencies_ms: list[float]
    errors: list[str] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    peak_memory_mb: float = 0.0
    disk_delta_mb: float = 0.0

    @property
    def throughput(self) -> float:
        elapsed = self.end_time - self.start_time
        return self.total_ops / elapsed if elapsed > 0 else 0.0

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total_ops * 100 if self.total_ops > 0 else 0.0

    def percentile(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_lats = sorted(self.latencies_ms)
        idx = max(0, min(len(sorted_lats) - 1, int(len(sorted_lats) * p / 100)))
        return sorted_lats[idx]

    def summary(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "total_ops": self.total_ops,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "success_rate_pct": round(self.success_rate, 2),
            "throughput_ops_per_sec": round(self.throughput, 2),
            "latency_ms": {
                "min": round(min(self.latencies_ms), 2) if self.latencies_ms else 0,
                "max": round(max(self.latencies_ms), 2) if self.latencies_ms else 0,
                "mean": round(statistics.mean(self.latencies_ms), 2) if self.latencies_ms else 0,
                "p50": round(self.percentile(50), 2),
                "p75": round(self.percentile(75), 2),
                "p90": round(self.percentile(90), 2),
                "p95": round(self.percentile(95), 2),
                "p99": round(self.percentile(99), 2),
            },
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "disk_delta_mb": round(self.disk_delta_mb, 2),
            "errors": self.errors[:10],
        }


class SyntheticCorpus:
    """Generates synthetic test data without real evidence."""

    def __init__(self, config: LoadConfig):
        self.config = config
        self._tmp_dir = tempfile.mkdtemp(prefix="harpocrates-loadtest-")

    def create_synthetic_video(self) -> Path:
        """Create a synthetic test video using ffmpeg (no real content)."""
        output_path = Path(self._tmp_dir) / f"synth-{uuid.uuid4().hex}.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-v", "error",
                "-f", "lavfi",
                "-i", f"testsrc=size={self.config.synthetic_video_resolution}:rate=30",
                "-t", str(self.config.synthetic_video_duration),
                "-pix_fmt", "yuv420p",
                str(output_path),
            ],
            check=True,
            capture_output=True,
        )
        return output_path

    def create_synthetic_metadata(self, tier: Tier = Tier.SILENT) -> dict[str, Any]:
        """Create synthetic metadata with no real credentials."""
        source_hash = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        proof_id = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        return {
            "protocol": "harpocrates",
            "version": 1,
            "tier": tier.value,
            "sourceHash": source_hash,
            "proofId": proof_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fileName": f"synth-{uuid.uuid4().hex}.mp4",
            "loadTestRun": uuid.uuid4().hex,
            "synthetic": True,
        }

    def create_synthetic_registration_payload(
        self, tier: Tier = Tier.SILENT
    ) -> dict[str, Any]:
        """Create a synthetic proof registration payload."""
        video_hash = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        metadata_hash = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        proof_id = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        return {
            "videoHash": video_hash,
            "metadataHash": metadata_hash,
            "proofId": proof_id,
            "tier": tier.value,
            "txStatus": "SYNTHETIC",
            # Generate valid Stellar StrKeys for synthetic load tests.
            # Omit sourceAddress and contractId to avoid StrKey validation
            # overhead during load testing — these fields are nullable.
            "sourceAddress": None,
            "contractId": None,
            "loadTestRun": uuid.uuid4().hex,
            "synthetic": True,
        }

    def cleanup(self) -> None:
        """Remove all synthetic test artifacts."""
        import shutil
        shutil.rmtree(self._tmp_dir, ignore_errors=True)


class LoadWorker:
    """Executes a single load test operation with instrumentation."""

    def __init__(self, config: LoadConfig, corpus: SyntheticCorpus):
        self.config = config
        self.corpus = corpus
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Harpocrates-LoadTest/1.0"})

    def embed_operation(self) -> tuple[float, bool, str]:
        """Run a synthetic embed operation."""
        start = time.perf_counter()
        try:
            video_path = self.corpus.create_synthetic_video()
            metadata = self.corpus.create_synthetic_metadata()
            metadata_json = json.dumps(metadata, separators=(",", ":"))

            with open(video_path, "rb") as f:
                response = self.session.post(
                    f"{self.config.base_url}/api/stego/embed",
                    files={"video": ("synthetic.mp4", f, "video/mp4")},
                    data={"metadata": metadata_json},
                    timeout=30,
                )

            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code == 200:
                return elapsed, True, ""
            return elapsed, False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def extract_operation(self) -> tuple[float, bool, str]:
        """Run a synthetic extract operation."""
        start = time.perf_counter()
        try:
            video_path = self.corpus.create_synthetic_video()

            with open(video_path, "rb") as f:
                response = self.session.post(
                    f"{self.config.base_url}/api/stego/extract",
                    files={"video": ("synthetic.mp4", f, "video/mp4")},
                    timeout=30,
                )

            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code == 200:
                return elapsed, True, ""
            return elapsed, False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def register_operation(self) -> tuple[float, bool, str]:
        """Run a synthetic registration operation."""
        start = time.perf_counter()
        try:
            payload = self.corpus.create_synthetic_registration_payload()
            response = self.session.post(
                f"{self.config.base_url}/api/proofs/register",
                json=payload,
                timeout=30,
            )

            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code == 200:
                return elapsed, True, ""
            return elapsed, False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def lookup_operation(self) -> tuple[float, bool, str]:
        """Run a synthetic lookup operation."""
        start = time.perf_counter()
        try:
            video_hash = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
            response = self.session.get(
                f"{self.config.base_url}/api/proofs/by-video/{video_hash}",
                timeout=30,
            )

            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code == 200:
                return elapsed, True, ""
            return elapsed, False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def list_operation(self) -> tuple[float, bool, str]:
        """Run a synthetic list operation."""
        start = time.perf_counter()
        try:
            response = self.session.get(
                f"{self.config.base_url}/api/proofs?limit=25",
                timeout=30,
            )

            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code == 200:
                return elapsed, True, ""
            return elapsed, False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def negative_test_operation(self) -> tuple[float, bool, str]:
        """Run a negative test (invalid input should fail)."""
        start = time.perf_counter()
        try:
            response = self.session.get(
                f"{self.config.base_url}/api/proofs/by-video/invalid",
                timeout=30,
            )

            elapsed = (time.perf_counter() - start) * 1000
            # Expect 400 (bad request) for invalid hex
            if response.status_code == 400:
                return elapsed, True, ""
            return elapsed, True, f"Expected 400, got {response.status_code}"
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, False, str(e)

    def close(self) -> None:
        self.session.close()


class LoadTestRunner:
    """Orchestrates load and soak test execution with backpressure."""

    def __init__(self, config: LoadConfig):
        self.config = config
        self.corpus = SyntheticCorpus(config)
        self.results: dict[str, LoadResult] = {}
        self._start_memory = self._get_memory_usage()
        self._start_disk = self._get_disk_usage()

    def _get_memory_usage(self) -> float:
        """Get current process memory usage in MB."""
        try:
            import psutil
            return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
        except ImportError:
            return 0.0

    def _get_disk_usage(self) -> float:
        """Get disk usage of relevant paths in MB."""
        try:
            total = 0.0
            for path in [Path(tempfile.gettempdir()), Path.cwd()]:
                if path.exists():
                    for f in path.rglob("*"):
                        if f.is_file():
                            try:
                                total += f.stat().st_size / (1024 * 1024)
                            except OSError:
                                pass
            return total
        except Exception:
            return 0.0

    def run_operation_batch(
        self,
        name: str,
        operation_fn: Callable[[], tuple[float, bool, str]],
        count: int,
        ramp_up: float = 0,
    ) -> LoadResult:
        """Run a batch of operations with concurrency and ramp-up."""
        result = LoadResult(
            operation=name,
            total_ops=count,
            succeeded=0,
            failed=0,
            latencies_ms=[],
            start_time=time.time(),
        )

        delay = ramp_up / count if count > 0 and ramp_up > 0 else 0
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = []
            for i in range(count):
                if delay > 0:
                    time.sleep(delay)
                futures.append(executor.submit(operation_fn))

            for future in as_completed(futures):
                latency, success, error = future.result()
                result.latencies_ms.append(latency)

                if success:
                    result.succeeded += 1
                else:
                    result.failed += 1
                    if error and len(errors) < self.config.total_operations:
                        errors.append(error)

                # Backpressure detection
                if latency > self.config.backpressure_threshold_ms:
                    if len(errors) < self.config.total_operations:
                        errors.append(f"Backpressure triggered: {latency:.0f}ms > {self.config.backpressure_threshold_ms:.0f}ms")

        result.end_time = time.time()
        result.errors = errors[:10]
        result.peak_memory_mb = self._get_memory_usage() - self._start_memory
        result.disk_delta_mb = self._get_disk_usage() - self._start_disk
        self.results[name] = result
        return result

    def run_load_test(self) -> dict[str, LoadResult]:
        """Execute a full load test across all operations."""
        print(f"\n{'='*60}")
        print(f"LOAD TEST - {self.config.total_operations} ops @ {self.config.concurrency} workers")
        print(f"{'='*60}\n")

        workers = LoadWorker(self.config, self.corpus)
        try:
            # Embed operations
            result = self.run_operation_batch(
                "embed", workers.embed_operation,
                self.config.total_operations,
                self.config.ramp_up_seconds,
            )
            self._print_result(result)

            # Register operations
            result = self.run_operation_batch(
                "register", workers.register_operation,
                self.config.total_operations,
                self.config.ramp_up_seconds,
            )
            self._print_result(result)

            # Lookup operations
            result = self.run_operation_batch(
                "lookup", workers.lookup_operation,
                self.config.total_operations,
                self.config.ramp_up_seconds,
            )
            self._print_result(result)

            # List operations
            result = self.run_operation_batch(
                "list", workers.list_operation,
                min(self.config.total_operations, 50),
                0,
            )
            self._print_result(result)

            # Negative tests
            result = self.run_operation_batch(
                "negative_tests", workers.negative_test_operation,
                min(self.config.total_operations, 25),
                0,
            )
            self._print_result(result)

        finally:
            workers.close()

        return self.results

    def run_soak_test(self) -> dict[str, LoadResult]:
        """Execute a sustained soak test over time."""
        print(f"\n{'='*60}")
        print(f"SOAK TEST - {self.config.soak_duration_minutes} minutes")
        print(f"{'='*60}\n")

        workers = LoadWorker(self.config, self.corpus)
        result = LoadResult(
            operation="soak",
            total_ops=0,
            succeeded=0,
            failed=0,
            latencies_ms=[],
            start_time=time.time(),
        )

        end_time = time.time() + (self.config.soak_duration_minutes * 60)
        last_report = time.time()
        report_interval = 30  # Report every 30 seconds
        errors: list[str] = []
        ops_count = 0

        try:
            while time.time() < end_time:
                # Rotate through different operations
                for op_fn in [
                    workers.embed_operation,
                    workers.register_operation,
                    workers.lookup_operation,
                    workers.list_operation,
                    workers.negative_test_operation,
                ]:
                    if time.time() >= end_time:
                        break

                    latency, success, error = op_fn()
                    result.latencies_ms.append(latency)
                    ops_count += 1
                    result.total_ops = ops_count

                    if success:
                        result.succeeded += 1
                    else:
                        result.failed += 1
                        if error and len(errors) < 100:
                            errors.append(error)

                    # Periodic reporting
                    now = time.time()
                    if now - last_report >= report_interval:
                        elapsed = now - result.start_time
                        throughput = ops_count / elapsed if elapsed > 0 else 0
                        print(
                            f"  [{elapsed:6.0f}s] {ops_count:5d} ops | "
                            f"throughput: {throughput:4.1f} ops/s | "
                            f"failures: {result.failed}"
                        )
                        last_report = now

        finally:
            workers.close()

        result.end_time = time.time()
        result.errors = errors[:10]
        result.peak_memory_mb = self._get_memory_usage() - self._start_memory
        result.disk_delta_mb = self._get_disk_usage() - self._start_disk
        self.results["soak"] = result
        self._print_result(result)
        return self.results

    def _print_result(self, result: LoadResult) -> None:
        """Print a formatted result summary."""
        s = result.summary()
        print(f"\n--- {result.operation.upper()} ---")
        print(f"  Success rate: {s['success_rate_pct']}% ({result.succeeded}/{result.total_ops})")
        print(f"  Throughput:   {s['throughput_ops_per_sec']} ops/s")
        print(f"  Latency p50:  {s['latency_ms']['p50']}ms")
        print(f"  Latency p95:  {s['latency_ms']['p95']}ms")
        print(f"  Latency p99:  {s['latency_ms']['p99']}ms")
        print(f"  Memory delta: {s['peak_memory_mb']} MB")
        print(f"  Disk delta:   {s['disk_delta_mb']} MB")
        if result.errors:
            print(f"  Errors (first 3): {result.errors[:3]}")

    def check_thresholds(self) -> list[str]:
        """Check results against defined thresholds. Returns list of violations."""
        violations: list[str] = []

        for name, result in self.results.items():
            s = result.summary()

            # Success rate threshold
            if s["success_rate_pct"] < 95:
                violations.append(
                    f"{name}: success rate {s['success_rate_pct']}% < 95% threshold"
                )

            # P99 latency threshold
            if s["latency_ms"]["p99"] > self.config.backpressure_threshold_ms:
                violations.append(
                    f"{name}: p99 latency {s['latency_ms']['p99']}ms > "
                    f"{self.config.backpressure_threshold_ms:.0f}ms threshold"
                )

            # Memory leak detection
            if s["peak_memory_mb"] > self.config.memory_leak_threshold_mb:
                violations.append(
                    f"{name}: memory delta {s['peak_memory_mb']}MB > "
                    f"{self.config.memory_leak_threshold_mb:.0f}MB threshold (possible leak)"
                )

            # Disk leak detection
            if s["disk_delta_mb"] > self.config.disk_leak_threshold_mb:
                violations.append(
                    f"{name}: disk delta {s['disk_delta_mb']}MB > "
                    f"{self.config.disk_leak_threshold_mb:.0f}MB threshold (possible leak)"
                )

        return violations

    def generate_report(self, output_path: str | None = None) -> str:
        """Generate a JSON report of all results."""
        report = {
            "config": {
                "base_url": self.config.base_url,
                "concurrency": self.config.concurrency,
                "total_operations": self.config.total_operations,
                "ramp_up_seconds": self.config.ramp_up_seconds,
                "soak_duration_minutes": self.config.soak_duration_minutes,
            },
            "results": {
                name: result.summary() for name, result in self.results.items()
            },
            "violations": self.check_thresholds(),
            "passed": len(self.check_thresholds()) == 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        report_json = json.dumps(report, indent=2)

        if output_path:
            Path(output_path).write_text(report_json)

        return report_json

    def cleanup(self) -> None:
        """Clean up all synthetic test artifacts."""
        self.corpus.cleanup()


def main() -> int:
    """Entry point for the load/soak test runner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Privacy-safe load and soak testing for Harpocrates"
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5050",
        help="Backend base URL (default: http://127.0.0.1:5050)",
    )
    parser.add_argument(
        "--mode",
        choices=["load", "soak", "both"],
        default="both",
        help="Test mode (default: both)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent workers (default: 4)",
    )
    parser.add_argument(
        "--total-ops",
        type=int,
        default=100,
        help="Total operations per test type (default: 100)",
    )
    parser.add_argument(
        "--soak-minutes",
        type=int,
        default=10,
        help="Soak test duration in minutes (default: 10)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path for JSON report",
    )
    parser.add_argument(
        "--threshold-memory-mb",
        type=float,
        default=100.0,
        help="Memory leak threshold in MB (default: 100)",
    )
    parser.add_argument(
        "--threshold-disk-mb",
        type=float,
        default=500.0,
        help="Disk leak threshold in MB (default: 500)",
    )

    args = parser.parse_args()

    config = LoadConfig(
        base_url=args.base_url,
        concurrency=args.concurrency,
        total_operations=args.total_ops,
        soak_duration_minutes=args.soak_minutes,
        memory_leak_threshold_mb=args.threshold_memory_mb,
        disk_leak_threshold_mb=args.threshold_disk_mb,
    )

    runner = LoadTestRunner(config)
    try:
        if args.mode in ("load", "both"):
            runner.run_load_test()

        if args.mode in ("soak", "both"):
            runner.run_soak_test()

        # Check thresholds
        violations = runner.check_thresholds()
        if violations:
            print(f"\n{'!'*60}")
            print("THRESHOLD VIOLATIONS:")
            for v in violations:
                print(f"  ! {v}")
            print(f"{'!'*60}\n")

        # Generate report
        report = runner.generate_report(args.output)
        if args.output:
            print(f"\nReport written to: {args.output}")

        print(f"\n{'='*60}")
        print(f"OVERALL: {'PASSED' if not violations else 'FAILED'}")
        print(f"{'='*60}")

        return 0 if not violations else 1

    finally:
        runner.cleanup()


if __name__ == "__main__":
    sys.exit(main())
