from __future__ import annotations

import hashlib
import os
import string
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


REPLAY_PROTECTION_VERSION = "1.0.0"
MAX_REPLAY_WINDOW_SECONDS = 600
NONCE_TTL_SECONDS = 900


class SessionReplayOutcome:
    NEW = "new"
    DUPLICATE = "duplicate"
    EXPIRED = "expired"
    OVERSIZED_NONCE = "oversized_nonce"
    SESSION_TOO_LONG = "session_too_long"
    INVALID_NONCE = "invalid_nonce"
    MAX_BUCKETS_EXCEEDED = "max_buckets_exceeded"
    STORAGE_FULL = "storage_full"


_VALID_OUTCOMES_FOR_PERMIT = {
    SessionReplayOutcome.NEW,
    SessionReplayOutcome.EXPIRED,
    SessionReplayOutcome.SESSION_TOO_LONG,
}


class SessionReplayError(Exception):
    def __init__(self, message: str, outcome: str) -> None:
        super().__init__(message)
        self.outcome = outcome


_PRINTABLE = set(string.printable)


class SessionReplayGuard:
    _nonces: Dict[str, float]
    _session_timestamps: Dict[str, float]
    _session_counts: Dict[str, int]
    _lock: threading.RLock
    max_replay_window: float
    nonce_ttl: float
    max_nonces: int
    max_session_events: int
    max_nonce_length: int

    def __init__(
        self,
        max_replay_window: float = MAX_REPLAY_WINDOW_SECONDS,
        nonce_ttl: float = NONCE_TTL_SECONDS,
        max_nonces: int = 16_384,
        max_session_events: int = 512,
        max_nonce_length: int = 256,
    ) -> None:
        self.max_replay_window = float(max_replay_window)
        self.nonce_ttl = float(nonce_ttl)
        self.max_nonces = int(max_nonces)
        self.max_session_events = int(max_session_events)
        self.max_nonce_length = int(max_nonce_length)
        self._lock = threading.RLock()
        self._nonces = {}
        self._session_timestamps = {}
        self._session_counts = {}

    def _prune(self, now: float, max_prune: int = 5000) -> None:
        with self._lock:
            pruned = 0
            max_prune_n = max_prune
            nonce_keys = list(self._nonces.keys())
            for key in nonce_keys:
                if pruned >= max_prune_n:
                    break
                if now - self._nonces[key] > self.nonce_ttl:
                    del self._nonces[key]
                    pruned += 1
            session_keys = list(self._session_timestamps.keys())
            for key in session_keys:
                if pruned >= max_prune_n:
                    break
                if now - self._session_timestamps[key] > self.max_replay_window:
                    del self._session_timestamps[key]
                    self._session_counts.pop(key, None)
                    pruned += 1

    def generate_nonce(self, session_tag: Optional[str] = None) -> str:
        random_bytes = os.urandom(16)
        epoch = str(time.time()).encode("utf-8")
        raw = random_bytes + epoch
        hashed = hashlib.sha256(raw).hexdigest()[:16]
        return "n-v1:" + hashed

    def verify_and_record(
        self,
        nonce: str,
        session_tag: Optional[str] = None,
        account_tag: Optional[str] = None,
        now_epoch: Optional[float] = None,
        context_hint: Optional[str] = None,
    ) -> str:
        if not isinstance(nonce, str) or len(nonce) == 0:
            return SessionReplayOutcome.INVALID_NONCE
        if len(nonce) > self.max_nonce_length:
            return SessionReplayOutcome.OVERSIZED_NONCE
        for ch in nonce:
            if ch not in _PRINTABLE:
                return SessionReplayOutcome.INVALID_NONCE
        now = now_epoch if now_epoch is not None else time.time()
        self._prune(now, 5000)
        with self._lock:
            if len(self._nonces) >= self.max_nonces:
                return SessionReplayOutcome.STORAGE_FULL
            if nonce in self._nonces:
                age = now - self._nonces[nonce]
                if age < self.nonce_ttl:
                    return SessionReplayOutcome.DUPLICATE
                else:
                    return SessionReplayOutcome.EXPIRED
            self._nonces[nonce] = now
            if session_tag is not None:
                session_len = len(session_tag.encode("utf-8"))
                if session_len > self.max_nonce_length * 2:
                    return SessionReplayOutcome.SESSION_TOO_LONG
                if session_tag not in self._session_timestamps:
                    self._session_timestamps[session_tag] = now
                    self._session_counts[session_tag] = 0
                age = now - self._session_timestamps[session_tag]
                if age > self.max_replay_window:
                    return SessionReplayOutcome.EXPIRED
                count = self._session_counts[session_tag] + 1
                self._session_counts[session_tag] = count
                if count > self.max_session_events:
                    return SessionReplayOutcome.SESSION_TOO_LONG
            return SessionReplayOutcome.NEW

    def is_valid_outcome(self, outcome: str | str) -> bool:
        return outcome in _VALID_OUTCOMES_FOR_PERMIT

    def stats(self) -> Dict[str, int]:
        with self._lock:
            total_processed = sum(self._session_counts.values())
            return {
                "nonce_count": len(self._nonces),
                "session_count": len(self._session_timestamps),
                "total_processed": total_processed,
            }

    def reset(self) -> None:
        with self._lock:
            self._nonces.clear()
            self._session_timestamps.clear()
            self._session_counts.clear()
