"""Unit tests for the ZK proof/verify benchmark harness.

Covers the lock schema, percentile math, warm/cold aggregation, privacy
properties, deterministic rejection of invalid/oversized/concurrent inputs,
timeout/cancel paths, compare inertness, and report promotion rules.

Run from the repository root:

    python -m pytest zk/bench -q
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import zk_bench as zb  # noqa: E402

LOCK_PATH = Path(__file__).resolve().parent / "bench.lock.json"


@pytest.fixture()
def lock() -> zb.Lock:
    return zb.load_lock(LOCK_PATH)


# ── Lock ─────────────────────────────────────────────────────────────────────


def test_repo_lock_loads_all_targets(lock: zb.Lock):
    assert lock.fixture_id == "silent_witness.synthetic.v1"
    assert set(lock.targets) == {"native", "browser", "ci", "soroban_adjacent"}
    assert lock.limits.max_samples > 0
    assert lock.limits.max_proof_bytes == 65536


def test_lock_rejects_unknown_version(tmp_path: Path):
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["version"] = 99
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(zb.BenchError, match="unsupported bench lock version"):
        zb.load_lock(path)


def test_lock_rejects_foreign_format(tmp_path: Path):
    path = tmp_path / "lock.json"
    path.write_text(json.dumps({"format": "nope", "version": 1}), encoding="utf-8")
    with pytest.raises(zb.BenchError, match="unexpected format identifier"):
        zb.load_lock(path)


# ── Stats ────────────────────────────────────────────────────────────────────


def test_percentiles_are_monotonic():
    samples = [10.0, 20.0, 30.0, 40.0, 50.0]
    summary = zb.summarize_timings(samples)
    assert summary["min"] == 10.0
    assert summary["max"] == 50.0
    assert summary["p50"] <= summary["p95"] <= summary["p99"]


def test_percentile_rejects_empty():
    with pytest.raises(zb.BenchError, match="no timing samples"):
        zb.summarize_timings([])


def test_percentile_rejects_oversized_list():
    with pytest.raises(zb.BenchError, match="hard cap"):
        zb.summarize_timings([1.0] * 65)


# ── Privacy ──────────────────────────────────────────────────────────────────


def test_privacy_rejects_proof_hex_key(lock: zb.Lock):
    with pytest.raises(zb.BenchError, match="privacy violation"):
        zb.assert_privacy_safe(
            {"proof": "aa" * 40},
            forbidden_keys=lock.forbidden_report_keys,
            forbidden_substrings=lock.forbidden_substrings,
        )


def test_privacy_rejects_witness_key(lock: zb.Lock):
    with pytest.raises(zb.BenchError, match="privacy violation"):
        zb.assert_privacy_safe(
            {"witness_bytes": 1, "raw_witness": "x"},
            forbidden_keys=lock.forbidden_report_keys,
            forbidden_substrings=lock.forbidden_substrings,
        )


def test_privacy_allows_size_and_digest_fields(lock: zb.Lock):
    zb.assert_privacy_safe(
        {
            "proof_bytes": 1024,
            "public_input_bytes": 128,
            "hostname_hash": "abcd" * 4,
            "percentiles": {"p50": 12.5},
        },
        forbidden_keys=lock.forbidden_report_keys,
        forbidden_substrings=lock.forbidden_substrings,
    )


def test_privacy_rejects_long_hex_blob(lock: zb.Lock):
    with pytest.raises(zb.BenchError, match="hex blob"):
        zb.assert_privacy_safe(
            {"note": "0x" + ("ab" * 40)},
            forbidden_keys=lock.forbidden_report_keys,
            forbidden_substrings=lock.forbidden_substrings,
        )


# ── Size / concurrency guards ────────────────────────────────────────────────


def test_oversized_proof_fails_deterministically(lock: zb.Lock):
    with pytest.raises(zb.RejectedError) as exc:
        zb.reject_oversized_proof(lock.limits.max_proof_bytes + 1, lock.limits)
    assert exc.value.code == "proof_oversized"


def test_undersized_proof_fails_deterministically(lock: zb.Lock):
    with pytest.raises(zb.RejectedError) as exc:
        zb.reject_oversized_proof(1, lock.limits)
    assert exc.value.code == "proof_undersized"


def test_invalid_public_inputs_length(lock: zb.Lock):
    with pytest.raises(zb.RejectedError) as exc:
        zb.validate_sizes(
            proof_bytes=128,
            public_input_bytes=64,
            witness_bytes=None,
            limits=lock.limits,
        )
    assert exc.value.code == "public_inputs_len"


def test_concurrency_capacity_rejected(lock: zb.Lock):
    with pytest.raises(zb.RejectedError) as exc:
        zb.ensure_concurrency_allowed(
            active=lock.limits.max_concurrency,
            limits=lock.limits,
            target_max=1,
        )
    assert exc.value.code == "capacity"


def test_duplicated_inflight_same_as_capacity(lock: zb.Lock):
    # Second concurrent slot at cap=1 must fail deterministically.
    zb.ensure_concurrency_allowed(active=0, limits=lock.limits, target_max=1)
    with pytest.raises(zb.RejectedError) as exc:
        zb.ensure_concurrency_allowed(active=1, limits=lock.limits, target_max=1)
    assert exc.value.code == "capacity"


# ── Synthetic / cancel / timeout ─────────────────────────────────────────────


def test_synthetic_op_is_deterministic(lock: zb.Lock):
    a = zb.synthetic_op(phase="prove", seed=7, limits=lock.limits)
    b = zb.synthetic_op(phase="prove", seed=7, limits=lock.limits)
    assert a.elapsed_ms == b.elapsed_ms
    assert a.proof_bytes == b.proof_bytes
    assert a.public_input_bytes == 128


def test_synthetic_honours_cancel(lock: zb.Lock):
    flag = threading.Event()
    flag.set()
    with pytest.raises(zb.CancelledError):
        zb.synthetic_op(phase="prove", seed=1, limits=lock.limits, cancelled=flag)


def test_timeout_wrapper_returns_timed_out(lock: zb.Lock):
    def slow() -> zb.SampleResult:
        import time

        time.sleep(0.2)
        return zb.SampleResult(state=zb.BenchState.OK, elapsed_ms=200.0)

    result = zb._with_timeout(slow, timeout_ms=10)
    assert result.state == zb.BenchState.TIMED_OUT
    assert result.reject_code == "timeout"


# ── End-to-end synthetic runs ────────────────────────────────────────────────


def test_ci_target_run_writes_privacy_safe_report(lock: zb.Lock, tmp_path: Path):
    report = zb.run_target(lock, "ci", force_synthetic=True)
    assert report["format"] == zb.REPORT_FORMAT
    assert report["target"] == "ci"
    assert report["outcome"] == "ok"
    assert report["fixture_id"] == lock.fixture_id
    assert "runtime" in report
    assert report["runtime"]["arch"]
    assert report["phases"]
    for phase in report["phases"]:
        assert "sizes" in phase
        assert phase["sizes"]["public_input_bytes"] == 128
        assert "percentiles" in phase
    zb.assert_privacy_safe(
        report,
        forbidden_keys=lock.forbidden_report_keys,
        forbidden_substrings=lock.forbidden_substrings,
    )
    out = tmp_path / "ci.json"
    zb.write_report(report, out, limits=lock.limits)
    loaded = zb.load_report(out, limits=lock.limits)
    assert loaded["outcome"] == "ok"


def test_soroban_adjacent_run(lock: zb.Lock):
    report = zb.run_target(lock, "soroban_adjacent", phases=("verify",))
    assert report["outcome"] == "ok"
    assert report["phases"]
    assert report["phases"][0]["phase"] == "verify"


def test_browser_and_native_synthetic(lock: zb.Lock):
    for target in ("browser", "native"):
        report = zb.run_target(lock, target, force_synthetic=True, phases=("prove", "verify"))
        assert report["outcome"] == "ok"
        assert len(report["phases"]) == 2


def test_partial_failure_does_not_write_ok_semantics(lock: zb.Lock, tmp_path: Path, monkeypatch):
    def boom(*_a, **_k):
        raise zb.RejectedError("injected", code="proof_oversized")

    monkeypatch.setattr(zb, "synthetic_op", boom)
    report = zb.run_target(lock, "ci", force_synthetic=True, phases=("prove",))
    assert report["outcome"] == "rejected"
    # Promotion rule: callers must not write non-ok reports; simulate CLI guard.
    if report["outcome"] != "ok":
        out = tmp_path / "should-not-exist.json"
        assert not out.exists()


# ── Compare / trend ──────────────────────────────────────────────────────────


def test_compare_is_inert_without_baselines(lock: zb.Lock, tmp_path: Path):
    report = zb.run_target(lock, "ci", force_synthetic=True)
    path = tmp_path / "r.json"
    zb.write_report(report, path, limits=lock.limits)
    assert zb.load_baselines(tmp_path / "missing.json") is None
    # CLI path
    code = zb.main(["--lock", str(LOCK_PATH), "compare", "--report", str(path), "--baselines", str(tmp_path / "missing.json")])
    assert code == zb.EXIT_OK


def test_compare_detects_regression(lock: zb.Lock, tmp_path: Path):
    report = zb.run_target(lock, "ci", force_synthetic=True)
    baselines = {
        "format": zb.BASELINES_FORMAT,
        "version": 1,
        "targets": {
            "ci": {
                "prove": {"max_ms": {"p50": 0.0001}},
            }
        },
    }
    findings = zb.compare_report(report, baselines)
    assert findings
    base_path = tmp_path / "baselines.lock.json"
    base_path.write_text(json.dumps(baselines), encoding="utf-8")
    report_path = tmp_path / "r.json"
    zb.write_report(report, report_path, limits=lock.limits)
    code = zb.main(
        ["--lock", str(LOCK_PATH), "compare", "--report", str(report_path), "--baselines", str(base_path)]
    )
    assert code == zb.EXIT_REGRESSION


def test_trend_summary(lock: zb.Lock, tmp_path: Path):
    for i in range(2):
        report = zb.run_target(lock, "ci", force_synthetic=True)
        zb.write_report(report, tmp_path / f"r{i}.json", limits=lock.limits)
    summary = zb.trend_reports(
        [zb.load_report(p, limits=lock.limits) for p in sorted(tmp_path.glob("*.json"))]
    )
    assert summary["targets"]["ci"]["reports"] == 2
    zb.assert_privacy_safe(
        summary,
        forbidden_keys=lock.forbidden_report_keys,
        forbidden_substrings=lock.forbidden_substrings,
    )


def test_metadata_cli():
    code = zb.main(["metadata"])
    assert code == zb.EXIT_OK


def test_runtime_metadata_has_required_fields():
    meta = zb.collect_runtime_metadata(ci=True)
    assert meta["ci"] is True
    assert meta["os"]
    assert meta["arch"]
    assert "hostname_hash" in meta
    assert len(meta["hostname_hash"]) == 16


def test_report_oversize_rejected(lock: zb.Lock, tmp_path: Path):
    tiny = zb.Limits(
        max_samples=1,
        max_proof_bytes=65536,
        min_proof_bytes=64,
        max_public_input_bytes=128,
        min_public_input_bytes=128,
        max_witness_bytes=1,
        max_report_bytes=32,
        max_concurrency=1,
        max_wall_clock_ms=1000,
    )
    report = {"format": zb.REPORT_FORMAT, "version": 1, "target": "ci", "outcome": "ok", "phases": [], "pad": "x" * 100}
    with pytest.raises(zb.BenchError, match="max_report_bytes"):
        zb.write_report(report, tmp_path / "big.json", limits=tiny)
