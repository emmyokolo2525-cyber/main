from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, Optional

from metrics import collector


class VerifierCache:
    """Bounded, thread-safe cache for Noir verifier results with positive and negative TTLs."""

    def __init__(
        self,
        max_size: int = 10000,
        positive_ttl_seconds: float = 86400.0,
        negative_ttl_seconds: float = 300.0,
    ) -> None:
        self.max_size = max_size
        self.positive_ttl_seconds = positive_ttl_seconds
        self.negative_ttl_seconds = negative_ttl_seconds
        
        self._lock = threading.Lock()
        self._cache: Dict[str, tuple[bool, float]] = {}

    def _get_cache_key(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> str:
        """Deterministically generates a cache key."""
        payload = f"{domain}|{network}|{circuit_version}|{verifier_version}|{proof_hex}|{public_inputs_hex}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> Optional[bool]:
        """Fetch verifier result from cache, evaluating TTL. Emits metrics."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        now = time.monotonic()

        with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                result, expires_at = entry
                if now < expires_at:
                    collector.record_cache_hit()
                    # Refresh LRU by re-inserting
                    self._cache.pop(key)
                    self._cache[key] = entry
                    return result
                else:
                    # Expired
                    self._cache.pop(key)

            collector.record_cache_miss()
            return None

    def set(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
        is_valid: bool,
    ) -> None:
        """Store verifier result in cache with appropriate TTL. Bounded by max_size."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        now = time.monotonic()
        ttl = self.positive_ttl_seconds if is_valid else self.negative_ttl_seconds
        expires_at = now + ttl

        with self._lock:
            if key in self._cache:
                self._cache.pop(key)
            elif len(self._cache) >= self.max_size:
                self._cache.pop(next(iter(self._cache)))
                collector.record_cache_eviction()

            self._cache[key] = (is_valid, expires_at)

    def invalidate(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> None:
        """Remove specific result from cache."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        with self._lock:
            if key in self._cache:
                self._cache.pop(key)

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._cache.clear()
