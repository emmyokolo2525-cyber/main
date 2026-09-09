from __future__ import annotations

import re
import threading
import time
from typing import Any, Dict, List, Optional


class MetricDomain:
    PROGRESS = "progress"
    FAILURE = "failure"
    SATURATION = "saturation"
    RECOVERY = "recovery"
    ERROR = "error"
    ANALYTICS = "analytics"
    EXPORT = "export"
    CONSENT = "consent"
    SESSION = "session"
    SAMPLING = "sampling"
    ALLOWLIST = "allowlist"
    REDACTION = "redaction"


_METRIC_DOMAIN_SET = {
    MetricDomain.PROGRESS,
    MetricDomain.FAILURE,
    MetricDomain.SATURATION,
    MetricDomain.RECOVERY,
    MetricDomain.ERROR,
    MetricDomain.ANALYTICS,
    MetricDomain.EXPORT,
    MetricDomain.CONSENT,
    MetricDomain.SESSION,
    MetricDomain.SAMPLING,
    MetricDomain.ALLOWLIST,
    MetricDomain.REDACTION,
}


class SaturationSignal:
    QUEUE_DEPTH_HIGH = "queue_depth_high"
    MEMORY_HIGH = "memory_high"
    CPU_HIGH = "cpu_high"
    EVENT_RATE_HIGH = "event_rate_high"
    EXPORT_BUFFER_FULL = "export_buffer_full"
    NONCE_STORE_FULL = "nonce_store_full"
    LOG_ENTRIES_LIMIT_HIT = "log_entries_limit_hit"
    CONCURRENCY_LIMIT_HIT = "concurrency_limit_hit"
    LATENCY_P99_HIGH = "latency_p99_high"


_SATURATION_SIGNAL_SET = {
    SaturationSignal.QUEUE_DEPTH_HIGH,
    SaturationSignal.MEMORY_HIGH,
    SaturationSignal.CPU_HIGH,
    SaturationSignal.EVENT_RATE_HIGH,
    SaturationSignal.EXPORT_BUFFER_FULL,
    SaturationSignal.NONCE_STORE_FULL,
    SaturationSignal.LOG_ENTRIES_LIMIT_HIT,
    SaturationSignal.CONCURRENCY_LIMIT_HIT,
    SaturationSignal.LATENCY_P99_HIGH,
}


class RecoverySignal:
    QUEUE_DEPTH_OK = "queue_depth_ok"
    MEMORY_OK = "memory_ok"
    CPU_OK = "cpu_ok"
    EVENT_RATE_OK = "event_rate_ok"
    EXPORT_BUFFER_DRAINED = "export_buffer_drained"
    NONCE_STORE_PRUNED = "nonce_store_pruned"
    EXPORT_SAFETY_OK = "export_safety_ok"
    LATENCY_P99_OK = "latency_p99_ok"
    CONSISTENCY_RESTORED = "consistency_restored"


_RECOVERY_SIGNAL_SET = {
    RecoverySignal.QUEUE_DEPTH_OK,
    RecoverySignal.MEMORY_OK,
    RecoverySignal.CPU_OK,
    RecoverySignal.EVENT_RATE_OK,
    RecoverySignal.EXPORT_BUFFER_DRAINED,
    RecoverySignal.NONCE_STORE_PRUNED,
    RecoverySignal.EXPORT_SAFETY_OK,
    RecoverySignal.LATENCY_P99_OK,
    RecoverySignal.CONSISTENCY_RESTORED,
}


_METRIC_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,47}$")


def _cap_str_bytes(value: str, cap: int) -> str:
    if not isinstance(value, str):
        value = str(value)
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= cap:
        return value
    truncated_bytes = encoded[:cap]
    try:
        return truncated_bytes.decode("utf-8", "ignore")
    except Exception:
        return truncated_bytes.decode("latin-1", "replace")


def _validate_domain(domain: str) -> str:
    if domain in _METRIC_DOMAIN_SET:
        return domain
    return MetricDomain.ANALYTICS


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        name = str(name)
    if _METRIC_NAME_PATTERN.match(name):
        return name
    cleaned_parts = []
    for ch in name.lower():
        if ch.isalnum() or ch == "_":
            cleaned_parts.append(ch)
        else:
            cleaned_parts.append("_")
    cleaned = "".join(cleaned_parts)
    if not cleaned:
        cleaned = "unnamed"
    if not cleaned[0].isalpha() and cleaned[0] != "_":
        cleaned = "m_" + cleaned
    if len(cleaned) > 48:
        cleaned = cleaned[:48]
    if not _METRIC_NAME_PATTERN.match(cleaned):
        cleaned = re.sub(r"[^a-z0-9_]", "_", cleaned)
        cleaned = cleaned[:48]
        if not cleaned:
            cleaned = "unnamed"
    return cleaned


def _clamp_int(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _top_n(d: Dict[str, int], n: int) -> Dict[str, int]:
    items = sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return {k: v for k, v in items}


class AnalyticsOperationalMetrics:
    def __init__(self) -> None:
        self._lock: threading.RLock = threading.RLock()
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._events_seen: Dict[str, int] = {}
        self._saturation_signals: Dict[str, int] = {}
        self._recovery_signals: Dict[str, int] = {}
        self._failure_errors: Dict[str, int] = {}
        self._progress_tick_total: int = 0
        self._last_recovery_epoch: float = 0.0
        self._last_saturation_epoch: float = 0.0

    def increment_counter(self, domain: str, name: str, value: int = 1) -> int:
        valid_domain = _validate_domain(domain)
        valid_name = _validate_name(name)
        key = f"{valid_domain}:{valid_name}"
        try:
            v = int(value)
        except Exception:
            v = 0
        clamped = _clamp_int(v, 0, 1_000_000)
        with self._lock:
            current = self._counters.get(key, 0)
            new_val = current + clamped
            self._counters[key] = new_val
            return new_val

    def set_gauge(self, domain: str, name: str, value: float) -> float:
        valid_domain = _validate_domain(domain)
        valid_name = _validate_name(name)
        key = f"{valid_domain}:{valid_name}"
        try:
            v = float(value)
        except Exception:
            v = 0.0
        with self._lock:
            self._gauges[key] = v
            return v

    def record_event_seen(self, event_name: str) -> int:
        capped = _cap_str_bytes(str(event_name) if event_name is not None else "", 128)
        with self._lock:
            current = self._events_seen.get(capped, 0)
            new_val = current + 1
            self._events_seen[capped] = new_val
            return new_val

    def record_saturation_signal(self, signal: str, detail: Optional[str] = None) -> int:
        if signal in _SATURATION_SIGNAL_SET:
            valid_signal = signal
        else:
            valid_signal = "other"
        with self._lock:
            current = self._saturation_signals.get(valid_signal, 0)
            new_val = current + 1
            self._saturation_signals[valid_signal] = new_val
            self._last_saturation_epoch = time.time()
            self.set_gauge(MetricDomain.SATURATION, "saturation_signal_count", float(sum(self._saturation_signals.values())))
            self.increment_counter(MetricDomain.SATURATION, "signal_total", 1)
            return new_val

    def record_recovery_signal(self, signal: str, detail: Optional[str] = None) -> int:
        if signal in _RECOVERY_SIGNAL_SET:
            valid_signal = signal
        else:
            valid_signal = "other"
        with self._lock:
            current = self._recovery_signals.get(valid_signal, 0)
            new_val = current + 1
            self._recovery_signals[valid_signal] = new_val
            self._last_recovery_epoch = time.time()
            self.set_gauge(MetricDomain.RECOVERY, "recovery_signal_count", float(sum(self._recovery_signals.values())))
            self.increment_counter(MetricDomain.RECOVERY, "recovery_total", 1)
            return new_val

    def record_failure(self, error_code: str, category: str = "failure", detail: Optional[str] = None) -> int:
        capped_code = _cap_str_bytes(str(error_code) if error_code is not None else "", 128)
        category_str = _cap_str_bytes(str(category) if category is not None else "failure", 64)
        with self._lock:
            current = self._failure_errors.get(capped_code, 0)
            new_val = current + 1
            self._failure_errors[capped_code] = new_val
            counter_name = f"err_{category_str}"
            valid_counter_name = _validate_name(counter_name)
            self.increment_counter(MetricDomain.FAILURE, valid_counter_name, 1)
            return new_val

    def progress_tick(self, domain: str = "progress", operation: str = "tick") -> None:
        op_str = _cap_str_bytes(str(operation) if operation is not None else "tick", 64)
        with self._lock:
            self.increment_counter(MetricDomain.PROGRESS, op_str, 1)
            self._progress_tick_total += 1

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._events_seen.clear()
            self._saturation_signals.clear()
            self._recovery_signals.clear()
            self._failure_errors.clear()
            self._progress_tick_total = 0
            self._last_recovery_epoch = 0.0
            self._last_saturation_epoch = 0.0

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "event_counts": _top_n(self._events_seen, 64),
                "saturation_signals": _top_n(self._saturation_signals, 64),
                "recovery_signals": _top_n(self._recovery_signals, 64),
                "failure_errors": _top_n(self._failure_errors, 64),
                "progress_ticks": self._progress_tick_total,
                "last_saturation_epoch": self._last_saturation_epoch,
                "last_recovery_epoch": self._last_recovery_epoch,
                "generated_at_epoch": time.time(),
            }


operational_collector: AnalyticsOperationalMetrics = AnalyticsOperationalMetrics()
