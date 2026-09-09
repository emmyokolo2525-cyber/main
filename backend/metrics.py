from __future__ import annotations

import threading
from typing import Dict, List, Tuple


# Default latency histogram buckets in seconds
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))

# Bounded upload size histogram buckets in bytes (1KB, 64KB, 1MB, 10MB, 100MB, 256MB, +Inf)
UPLOAD_SIZE_BUCKETS = (1024, 65536, 1048576, 10485760, 104857600, 262144000, float("inf"))


class MetricsCollector:
    """Thread-safe collector for privacy-safe HTTP service metrics in Prometheus format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests_total: Dict[Tuple[str, str, str], int] = {}
        self._latency_histogram: Dict[Tuple[str, str, str], Dict[str, float]] = {}
        self._upload_histogram: Dict[Tuple[str, str], Dict[str, float]] = {}
        self._rejections_total: Dict[Tuple[str, str], int] = {}
        
        # Verifier cache metrics
        self._cache_hits = 0
        self._cache_misses = 0
        self._cache_evictions = 0

    def reset(self) -> None:
        """Reset all metrics to clean state (primarily for unit testing)."""
        with self._lock:
            self._requests_total.clear()
            self._latency_histogram.clear()
            self._upload_histogram.clear()
            self._rejections_total.clear()
            self._cache_hits = 0
            self._cache_misses = 0
            self._cache_evictions = 0

    def record_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        duration_seconds: float,
        upload_bytes: int | None = None,
    ) -> None:
        """Record request count, duration, and optional upload size.

        Guarantees: All labels are limited to HTTP method, URL rule/endpoint pattern,
        and HTTP status code. No filenames, hashes, addresses, proof data, or secrets are recorded.
        """
        clean_method = (method or "UNKNOWN").upper()
        clean_endpoint = endpoint if endpoint else "unmatched"
        status_str = str(status)

        with self._lock:
            # Update request total counter
            counter_key = (clean_method, clean_endpoint, status_str)
            self._requests_total[counter_key] = self._requests_total.get(counter_key, 0) + 1

            # Update latency histogram
            lat_key = counter_key
            if lat_key not in self._latency_histogram:
                lat_entry = {f"le_{b}": 0.0 for b in LATENCY_BUCKETS}
                lat_entry["sum"] = 0.0
                lat_entry["count"] = 0.0
                self._latency_histogram[lat_key] = lat_entry

            lat_stats = self._latency_histogram[lat_key]
            lat_stats["sum"] += max(0.0, float(duration_seconds))
            lat_stats["count"] += 1.0
            for bucket in LATENCY_BUCKETS:
                if duration_seconds <= bucket:
                    lat_stats[f"le_{bucket}"] += 1.0

            # Update upload size histogram if content is uploaded
            if upload_bytes is not None and upload_bytes > 0:
                upload_key = (clean_method, clean_endpoint)
                if upload_key not in self._upload_histogram:
                    up_entry = {f"le_{b}": 0.0 for b in UPLOAD_SIZE_BUCKETS}
                    up_entry["sum"] = 0.0
                    up_entry["count"] = 0.0
                    self._upload_histogram[upload_key] = up_entry

                up_stats = self._upload_histogram[upload_key]
                up_stats["sum"] += float(upload_bytes)
                up_stats["count"] += 1.0
                for bucket in UPLOAD_SIZE_BUCKETS:
                    if upload_bytes <= bucket:
                        up_stats[f"le_{bucket}"] += 1.0

    def record_rejection(self, reason: str, endpoint: str) -> None:
        """Record a rejected request due to admission control."""
        clean_endpoint = endpoint if endpoint else "unmatched"
        clean_reason = reason or "unknown"
        with self._lock:
            key = (clean_reason, clean_endpoint)
            self._rejections_total[key] = self._rejections_total.get(key, 0) + 1

    def record_cache_hit(self) -> None:
        """Record a verifier cache hit."""
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a verifier cache miss."""
        with self._lock:
            self._cache_misses += 1

    def record_cache_eviction(self) -> None:
        """Record a verifier cache eviction."""
        with self._lock:
            self._cache_evictions += 1

    def generate_prometheus_metrics(self) -> str:
        """Format metrics into Prometheus text format (version 0.0.4)."""
        lines: List[str] = []

        with self._lock:
            # 1. Request total counter
            lines.append("# HELP harpocrates_requests_total Total count of HTTP requests processed.")
            lines.append("# TYPE harpocrates_requests_total counter")
            for (method, endpoint, status), count in sorted(self._requests_total.items()):
                lines.append(
                    f'harpocrates_requests_total{{endpoint="{_escape_label(endpoint)}",'
                    f'method="{_escape_label(method)}",status="{_escape_label(status)}"}} {count}'
                )

            # 2. Latency histogram
            lines.append("")
            lines.append("# HELP harpocrates_request_duration_seconds HTTP request latency in seconds.")
            lines.append("# TYPE harpocrates_request_duration_seconds histogram")
            for (method, endpoint, status), stats in sorted(self._latency_histogram.items()):
                esc_endpoint = _escape_label(endpoint)
                esc_method = _escape_label(method)
                esc_status = _escape_label(status)
                label_prefix = f'endpoint="{esc_endpoint}",method="{esc_method}",status="{esc_status}"'

                for bucket in LATENCY_BUCKETS:
                    le_str = "+Inf" if bucket == float("inf") else _format_float(bucket)
                    bucket_count = int(stats[f"le_{bucket}"])
                    lines.append(f'harpocrates_request_duration_seconds_bucket{{{label_prefix},le="{le_str}"}} {bucket_count}')

                lines.append(f'harpocrates_request_duration_seconds_sum{{{label_prefix}}} {_format_float(stats["sum"])}')
                lines.append(f'harpocrates_request_duration_seconds_count{{{label_prefix}}} {int(stats["count"])}')

            # 3. Upload size histogram
            lines.append("")
            lines.append("# HELP harpocrates_upload_bytes_total Bounded request upload size in bytes.")
            lines.append("# TYPE harpocrates_upload_bytes_total histogram")
            for (method, endpoint), stats in sorted(self._upload_histogram.items()):
                esc_endpoint = _escape_label(endpoint)
                esc_method = _escape_label(method)
                label_prefix = f'endpoint="{esc_endpoint}",method="{esc_method}"'

                for bucket in UPLOAD_SIZE_BUCKETS:
                    le_str = "+Inf" if bucket == float("inf") else _format_float(bucket)
                    bucket_count = int(stats[f"le_{bucket}"])
                    lines.append(f'harpocrates_upload_bytes_total_bucket{{{label_prefix},le="{le_str}"}} {bucket_count}')

                lines.append(f'harpocrates_upload_bytes_total_sum{{{label_prefix}}} {_format_float(stats["sum"])}')
                lines.append(f'harpocrates_upload_bytes_total_count{{{label_prefix}}} {int(stats["count"])}')

            # 4. Rejections total counter
            if self._rejections_total:
                lines.append("")
                lines.append("# HELP harpocrates_admission_rejected_total Total count of requests rejected by admission control.")
                lines.append("# TYPE harpocrates_admission_rejected_total counter")
                for (reason, endpoint), count in sorted(self._rejections_total.items()):
                    lines.append(
                        f'harpocrates_admission_rejected_total{{endpoint="{_escape_label(endpoint)}",'
                        f'reason="{_escape_label(reason)}"}} {count}'
                    )

            # 5. Verifier cache metrics
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_hits_total Total count of verifier cache hits.")
            lines.append("# TYPE harpocrates_verifier_cache_hits_total counter")
            lines.append(f"harpocrates_verifier_cache_hits_total {self._cache_hits}")
            
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_misses_total Total count of verifier cache misses.")
            lines.append("# TYPE harpocrates_verifier_cache_misses_total counter")
            lines.append(f"harpocrates_verifier_cache_misses_total {self._cache_misses}")
            
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_evictions_total Total count of verifier cache evictions.")
            lines.append("# TYPE harpocrates_verifier_cache_evictions_total counter")
            lines.append(f"harpocrates_verifier_cache_evictions_total {self._cache_evictions}")

        lines.append("")
        return "\n".join(lines)


def _escape_label(val: str) -> str:
    return val.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_float(val: float) -> str:
    if val == float("inf"):
        return "+Inf"
    if val == int(val):
        return str(int(val))
    return f"{val:.6g}"


# Global singleton instance
collector = MetricsCollector()
