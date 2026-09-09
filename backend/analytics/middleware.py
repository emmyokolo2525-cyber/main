from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Iterable, Optional, Set

try:
    from analytics.analytics_engine import AnalyticsEngine, RequestContext, get_engine
except Exception:
    AnalyticsEngine = None
    RequestContext = None
    get_engine = None

try:
    from analytics.redaction import versioned_domain_tag
except Exception:
    versioned_domain_tag = None

try:
    from analytics.metrics_collector import MetricDomain, operational_collector
except Exception:
    MetricDomain = None
    operational_collector = None


_DEFAULT_EXCLUDED_PATHS: Set[str] = {
    "/favicon.ico",
    "/health",
    "/healthz",
    "/ready",
    "/readiness",
    "/metrics",
}


class AnalyticsMiddleware:
    def __init__(
        self,
        app: Any = None,
        engine: Optional[AnalyticsEngine] = None,
        auto_instrument: bool = True,
        excluded_paths: Optional[Set[str]] = None,
    ) -> None:
        if engine is not None:
            self.engine = engine
        elif get_engine is not None:
            self.engine = get_engine()
        else:
            self.engine = None
        self._app = app
        self._auto_instrument = auto_instrument
        self._excluded_paths: Set[str] = set(excluded_paths) if excluded_paths is not None else set(_DEFAULT_EXCLUDED_PATHS)
        if app is not None and callable(app):
            self._wsgi_app: Optional[Callable[..., Any]] = app
        else:
            self._wsgi_app = None

    def _versioned_tag(self, tag_input: Optional[str]) -> Optional[str]:
        if not tag_input:
            return None
        if versioned_domain_tag is not None:
            return versioned_domain_tag(tag_input)
        if isinstance(tag_input, str):
            data = tag_input.encode("utf-8", "replace")
        elif isinstance(tag_input, bytes):
            data = tag_input
        else:
            data = str(tag_input).encode("utf-8", "replace")
        digest = hashlib.sha256(data).hexdigest()
        return "v1:" + digest[:16]

    def build_context_from_environ(self, environ: dict) -> RequestContext:
        rid = environ.get("HTTP_X_REQUEST_ID")
        if not rid:
            random_hex = hashlib.sha256((str(time.time_ns()) + str(environ)).encode("utf-8")).hexdigest()[:16]
            rid = "req-v1:" + random_hex
        request_id_tag = self._versioned_tag(rid)

        raw_account = environ.get("HTTP_X_USER_TAG")
        account_id_tag = self._versioned_tag(raw_account) if raw_account else None

        raw_session = environ.get("HTTP_X_SESSION_TAG")
        session_id_tag = self._versioned_tag(raw_session) if raw_session else None

        raw_ip = environ.get("REMOTE_ADDR")
        ip_tag = self._versioned_tag(raw_ip) if raw_ip else None

        raw_ua = environ.get("HTTP_USER_AGENT")
        user_agent_tag = self._versioned_tag(raw_ua) if raw_ua else None

        raw_path = environ.get("PATH_INFO") or ""
        redaction = getattr(self.engine, "redaction", None) if self.engine is not None else None
        if redaction is not None and hasattr(redaction, "sanitize_endpoint_pattern"):
            try:
                endpoint_pattern = redaction.sanitize_endpoint_pattern(raw_path)
            except Exception:
                endpoint_pattern = raw_path[:256]
        else:
            endpoint_pattern = raw_path[:256]

        method = environ.get("REQUEST_METHOD", "GET") or "GET"

        if RequestContext is not None:
            return RequestContext(
                request_id_tag=request_id_tag,
                account_id_tag=account_id_tag,
                session_id_tag=session_id_tag,
                ip_tag=ip_tag,
                user_agent_tag=user_agent_tag,
                endpoint_pattern=endpoint_pattern,
                method=method,
            )
        else:
            class _Ctx:
                def __init__(self, **kw):
                    for k, v in kw.items():
                        setattr(self, k, v)
            return _Ctx(
                request_id_tag=request_id_tag,
                account_id_tag=account_id_tag,
                session_id_tag=session_id_tag,
                ip_tag=ip_tag,
                user_agent_tag=user_agent_tag,
                endpoint_pattern=endpoint_pattern,
                method=method,
                status_code=None,
                duration_seconds=None,
            )

    def record_post_response(
        self,
        context: Any,
        status_code: int,
        duration_seconds: float,
        bytes_sent: int = 0,
    ) -> None:
        try:
            context.status_code = status_code
        except Exception:
            pass
        try:
            context.duration_seconds = duration_seconds
        except Exception:
            pass

        metrics = getattr(self.engine, "metrics", None) if self.engine is not None else None
        if metrics is None:
            metrics = operational_collector

        if metrics is not None and hasattr(metrics, "increment_counter"):
            method = getattr(context, "method", "") or ""
            endpoint = getattr(context, "endpoint_pattern", "") or ""
            domain = MetricDomain.ANALYTICS if MetricDomain is not None else "analytics"
            metrics.increment_counter(domain, "request_total", 1)
            status_bucket = str(status_code)[:1] + "xx" if isinstance(status_code, int) else "unknown"
            metrics.increment_counter(domain, "status_" + status_bucket, 1)

        if metrics is not None and hasattr(metrics, "set_gauge"):
            method = getattr(context, "method", "") or ""
            endpoint = getattr(context, "endpoint_pattern", "") or ""
            domain = MetricDomain.ANALYTICS if MetricDomain is not None else "analytics"
            try:
                metrics.set_gauge(domain, "request_duration_seconds", float(duration_seconds))
            except Exception:
                pass

        if metrics is not None and hasattr(metrics, "progress_tick"):
            metrics.progress_tick("network", "rpc_completed")

        if self.engine is not None and hasattr(self.engine, "record_progress"):
            try:
                self.engine.record_progress("network", "rpc_completed", context)
            except Exception:
                pass

    def wrap_wsgi(
        self,
        environ: dict,
        start_response: Callable[..., Any],
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO") or ""
        if path in self._excluded_paths:
            if self._wsgi_app is not None:
                return self._wsgi_app(environ, start_response)
            return iter([])

        start_time = time.time()
        context = self.build_context_from_environ(environ)

        captured_status: list = [None]
        captured_bytes: list = [0]

        def _tracking_start_response(status, response_headers, exc_info=None):
            captured_status[0] = status
            try:
                parts = status.split(" ", 1)
                status_code = int(parts[0]) if parts else 0
            except Exception:
                status_code = 0

            original_write = start_response(status, response_headers, exc_info)

            def _tracking_write(body_chunk):
                try:
                    if isinstance(body_chunk, (bytes, bytearray)):
                        captured_bytes[0] += len(body_chunk)
                    elif isinstance(body_chunk, str):
                        captured_bytes[0] += len(body_chunk.encode("utf-8"))
                except Exception:
                    pass
                return original_write(body_chunk)

            return _tracking_write

        if self._wsgi_app is None:
            return iter([])

        try:
            response_iter = self._wsgi_app(environ, _tracking_start_response)
        except Exception as e:
            duration = time.time() - start_time
            self.record_post_response(context, 500, duration, 0)
            if self.engine is not None and hasattr(self.engine, "record_error"):
                try:
                    self.engine.record_error(e, context)
                except Exception:
                    pass
            raise

        def _tracking_generator():
            total_bytes = 0
            try:
                for chunk in response_iter:
                    try:
                        if isinstance(chunk, (bytes, bytearray)):
                            total_bytes += len(chunk)
                        elif isinstance(chunk, str):
                            total_bytes += len(chunk.encode("utf-8"))
                    except Exception:
                        pass
                    yield chunk
            finally:
                duration = time.time() - start_time
                status_val = captured_status[0]
                status_code = 0
                if isinstance(status_val, str):
                    try:
                        parts = status_val.split(" ", 1)
                        status_code = int(parts[0]) if parts else 0
                    except Exception:
                        status_code = 0
                elif isinstance(status_val, int):
                    status_code = status_val
                total = max(total_bytes, captured_bytes[0])
                self.record_post_response(context, status_code, duration, total)
                if hasattr(response_iter, "close"):
                    try:
                        response_iter.close()
                    except Exception:
                        pass

        return _tracking_generator()

    def __call__(self, environ: dict, start_response: Callable[..., Any]) -> Iterable[bytes]:
        return self.wrap_wsgi(environ, start_response)
