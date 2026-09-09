import threading
from functools import wraps
from typing import Dict, Tuple

from flask import request, jsonify


class AdmissionController:
    """
    Manages capacity and queue limits, providing backpressure via admission control.
    """

    def __init__(
        self,
        max_concurrent: int,
        max_queue: int,
        max_per_identity: int,
        timeout_seconds: float,
    ):
        self.max_concurrent = max_concurrent
        self.max_queue = max_queue
        self.max_per_identity = max_per_identity
        self.timeout_seconds = timeout_seconds

        self._lock = threading.Lock()
        self._current_queue = 0
        self._identity_counts: Dict[str, int] = {}
        self._semaphore = threading.Semaphore(max_concurrent)

    def acquire(self, identity: str) -> Tuple[bool, str]:
        """
        Attempt to acquire a concurrency slot.
        Returns (True, "ok") if successful, or (False, reason) if rejected.
        """
        with self._lock:
            # 1. Per-identity fairness
            if self._identity_counts.get(identity, 0) >= self.max_per_identity:
                return False, "identity_limit"

            # Take an immediately available execution slot without consuming
            # queue capacity. This keeps max_queue=0 useful as "no waiting".
            if self._semaphore.acquire(blocking=False):
                self._identity_counts[identity] = (
                    self._identity_counts.get(identity, 0) + 1
                )
                return True, "ok"

            # 2. Queue limits apply only when all execution slots are busy.
            if self._current_queue >= self.max_queue:
                return False, "queue_full"

            # Join the queue
            self._current_queue += 1
            self._identity_counts[identity] = self._identity_counts.get(identity, 0) + 1

        # 3. Wait for global concurrency
        acquired = self._semaphore.acquire(timeout=self.timeout_seconds)

        with self._lock:
            # Leave the queue
            self._current_queue -= 1
            
            if not acquired:
                # Timed out waiting
                self._identity_counts[identity] -= 1
                if self._identity_counts[identity] == 0:
                    del self._identity_counts[identity]
                return False, "timeout"

        return True, "ok"

    def release(self, identity: str) -> None:
        """
        Release a previously acquired concurrency slot.
        """
        with self._lock:
            self._identity_counts[identity] -= 1
            if self._identity_counts[identity] == 0:
                del self._identity_counts[identity]
        
        self._semaphore.release()


def _get_client_identity() -> str:
    """Extract a stable identity string for the client."""
    # Note: In a real production deployment behind a load balancer, 
    # this should securely parse X-Forwarded-For or use a more robust token.
    # We take the first IP in X-Forwarded-For to avoid spoofing if possible,
    # but for this scope we just safely read it.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def require_capacity(controller: AdmissionController):
    """
    Flask decorator to enforce admission control on a route.
    Returns 429 or 503 with a Retry-After header on rejection.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            identity = _get_client_identity()
            acquired, reason = controller.acquire(identity)
            
            if not acquired:
                # Import here to avoid circular imports if needed
                from metrics import collector as metrics_collector
                
                # Record the rejection metric
                endpoint = request.url_rule.rule if request.url_rule else request.path
                metrics_collector.record_rejection(reason, endpoint)
                
                status_code = 429 if reason == "identity_limit" else 503
                response = jsonify({
                    "error": "service overloaded", 
                    "reason": reason
                })
                response.status_code = status_code
                response.headers["Retry-After"] = str(int(controller.timeout_seconds * 2) or 5)
                return response
                
            try:
                return f(*args, **kwargs)
            finally:
                controller.release(identity)
        return wrapped
    return decorator
