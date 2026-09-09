from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


CONSENT_SCHEMA_VERSION = "1.0.0"
CONSENT_GRACE_PERIOD_SECONDS = 1800


class ConsentStatus:
    UNKNOWN = "unknown"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    INVALID = "invalid"
    GRACE = "grace"


_VALID_STATUSES = {
    ConsentStatus.UNKNOWN,
    ConsentStatus.GRANTED,
    ConsentStatus.DENIED,
    ConsentStatus.EXPIRED,
    ConsentStatus.WITHDRAWN,
    ConsentStatus.INVALID,
    ConsentStatus.GRACE,
}


class ConsentSource:
    USER_EXPLICIT = "user_explicit"
    USER_IMPLICIT = "user_implicit"
    LEGAL = "legal_basis"
    SYSTEM_DEFAULT = "system_default"
    TOKEN = "consent_token"
    API_REQUEST = "api_request"
    UNKNOWN_SOURCE = "unknown"


_VALID_SOURCES = {
    ConsentSource.USER_EXPLICIT,
    ConsentSource.USER_IMPLICIT,
    ConsentSource.LEGAL,
    ConsentSource.SYSTEM_DEFAULT,
    ConsentSource.TOKEN,
    ConsentSource.API_REQUEST,
    ConsentSource.UNKNOWN_SOURCE,
}


@dataclass
class ConsentDecision:
    status: str
    source: str
    scope: List[str]
    expires_at_epoch_seconds: float
    granted_at_epoch_seconds: float
    version: str = CONSENT_SCHEMA_VERSION
    consent_token: Optional[str] = None
    withdrawal_epoch_seconds: Optional[float] = None
    reason: Optional[str] = None
    stable_account_tag: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid consent status: {self.status}")
        if self.source not in _VALID_SOURCES:
            raise ValueError(f"invalid consent source: {self.source}")


@dataclass
class ConsentState:
    account_tag: Optional[str] = None
    status: str = ConsentStatus.UNKNOWN
    source: str = ConsentSource.UNKNOWN_SOURCE
    granted_at_epoch_seconds: float = 0.0
    expires_at_epoch_seconds: float = 0.0
    withdrawal_epoch_seconds: Optional[float] = None
    granted_scopes: List[str] = field(default_factory=list)
    denied_scopes: List[str] = field(default_factory=list)
    consent_token: Optional[str] = None
    last_modified_epoch_seconds: float = 0.0
    version: str = CONSENT_SCHEMA_VERSION

    def is_active(self, now_epoch_seconds: float | None = None) -> bool:
        if self.status in {ConsentStatus.GRANTED, ConsentStatus.GRACE}:
            return True
        return False

    def requires_scope(self, scope: str) -> bool:
        if self.status == ConsentStatus.GRANTED:
            if scope in self.granted_scopes or "*" in self.granted_scopes:
                return True
        return False

    def to_decision(self) -> ConsentDecision:
        return ConsentDecision(
            status=self.status,
            source=self.source,
            scope=list(self.granted_scopes),
            expires_at_epoch_seconds=self.expires_at_epoch_seconds,
            granted_at_epoch_seconds=self.granted_at_epoch_seconds,
            version=self.version,
            consent_token=self.consent_token,
            withdrawal_epoch_seconds=self.withdrawal_epoch_seconds,
            stable_account_tag=self.account_tag,
        )


DEFAULT_CONSENT_STATE = ConsentState(
    status=ConsentStatus.UNKNOWN,
    source=ConsentSource.SYSTEM_DEFAULT,
    granted_at_epoch_seconds=0,
    expires_at_epoch_seconds=0,
    consent_token=None,
)


class ConsentManager:
    _consent_states: Dict[str, ConsentState]
    _grace_period: float
    _lock: threading.Lock

    def __init__(self, grace_period_seconds: float = CONSENT_GRACE_PERIOD_SECONDS) -> None:
        self._grace_period = float(grace_period_seconds)
        self._lock = threading.Lock()
        self._consent_states = {}

    def check_consent(
        self,
        account_tag: Optional[str],
        scope: Optional[str],
        now_epoch_seconds: float | None = None,
    ) -> Tuple[bool, ConsentState]:
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()
        if account_tag is None:
            temp = ConsentState(
                account_tag=None,
                status=ConsentStatus.GRACE,
                source=ConsentSource.SYSTEM_DEFAULT,
                granted_at_epoch_seconds=now,
                expires_at_epoch_seconds=now + self._grace_period,
                last_modified_epoch_seconds=now,
            )
            return (True, temp)
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                new_state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.GRACE,
                    source=ConsentSource.SYSTEM_DEFAULT,
                    granted_at_epoch_seconds=now,
                    expires_at_epoch_seconds=now + self._grace_period,
                    last_modified_epoch_seconds=now,
                )
                self._consent_states[account_tag] = new_state
                return (False, new_state)
            effective_status = state.status
            if state.status == ConsentStatus.GRANTED and state.expires_at_epoch_seconds > 0:
                if now > state.expires_at_epoch_seconds:
                    effective_status = ConsentStatus.EXPIRED
            if effective_status in {ConsentStatus.EXPIRED, ConsentStatus.WITHDRAWN, ConsentStatus.INVALID}:
                return (False, state)
            if scope is not None:
                if scope not in state.granted_scopes and "*" not in state.granted_scopes:
                    return (False, state)
            return (True, state)

    def set_consent(self, account_tag: str, decision: ConsentDecision) -> ConsentState:
        now = time.time()
        with self._lock:
            existing = self._consent_states.get(account_tag)
            new_state = ConsentState(
                account_tag=account_tag,
                status=decision.status,
                source=decision.source,
                granted_at_epoch_seconds=decision.granted_at_epoch_seconds,
                expires_at_epoch_seconds=decision.expires_at_epoch_seconds,
                withdrawal_epoch_seconds=decision.withdrawal_epoch_seconds,
                granted_scopes=list(decision.scope),
                consent_token=decision.consent_token,
                last_modified_epoch_seconds=now,
                version=decision.version,
            )
            if existing is not None:
                same = (
                    existing.status == new_state.status
                    and existing.source == new_state.source
                    and existing.granted_scopes == new_state.granted_scopes
                    and existing.expires_at_epoch_seconds == new_state.expires_at_epoch_seconds
                    and existing.consent_token == new_state.consent_token
                    and existing.withdrawal_epoch_seconds == new_state.withdrawal_epoch_seconds
                )
                if same:
                    existing.last_modified_epoch_seconds = now
                    return existing
            self._consent_states[account_tag] = new_state
            return new_state

    def withdraw_consent(self, account_tag: str, reason: Optional[str] = None) -> ConsentState:
        now = time.time()
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.WITHDRAWN,
                    source=ConsentSource.USER_EXPLICIT,
                    last_modified_epoch_seconds=now,
                )
                self._consent_states[account_tag] = state
            state.status = ConsentStatus.WITHDRAWN
            state.withdrawal_epoch_seconds = now
            state.last_modified_epoch_seconds = now
            return state

    def invalidate_consent(self, account_tag: str, reason: Optional[str] = None) -> ConsentState:
        now = time.time()
        with self._lock:
            state = self._consent_states.get(account_tag)
            if state is None:
                state = ConsentState(
                    account_tag=account_tag,
                    status=ConsentStatus.INVALID,
                    source=ConsentSource.SYSTEM_DEFAULT,
                    last_modified_epoch_seconds=now,
                )
                self._consent_states[account_tag] = state
            state.status = ConsentStatus.INVALID
            state.last_modified_epoch_seconds = now
            return state

    def prune_expired(self, now_epoch_seconds: float | None = None, max_to_prune: int = 1000) -> int:
        now = now_epoch_seconds if now_epoch_seconds is not None else time.time()
        removed = 0
        with self._lock:
            to_remove: List[str] = []
            for tag, state in self._consent_states.items():
                if len(to_remove) >= max_to_prune:
                    break
                if state.status in {ConsentStatus.EXPIRED, ConsentStatus.WITHDRAWN, ConsentStatus.INVALID}:
                    age = now - state.last_modified_epoch_seconds
                    if age > self._grace_period:
                        to_remove.append(tag)
            for tag in to_remove:
                del self._consent_states[tag]
                removed += 1
        return removed

    def generate_consent_token(self, account_tag: str, status: str, scopes: List[str]) -> str:
        sorted_scopes = sorted(scopes)
        scopes_str = ",".join(sorted_scopes)
        random_bytes = os.urandom(8)
        raw = (account_tag + status + scopes_str).encode("utf-8") + random_bytes
        hashed = hashlib.sha256(raw).hexdigest()[:24]
        return "cst-v1:" + hashed
