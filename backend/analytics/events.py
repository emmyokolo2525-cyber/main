from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Set, List, Union
import time
import hashlib
import os
import uuid


ANALYTICS_EVENT_SCHEMA_VERSION = "1.0.0"


class EventCategory:
    SYSTEM_INTERNAL = "system.internal"
    USER_ACTION = "user.action"
    PROOF_OPERATION = "proof.operation"
    MEDIA_OPERATION = "media.operation"
    NETWORK_OPERATION = "network.operation"
    ERROR_OBSERVED = "error.observed"
    OP_SIGNAL = "ops.signal"
    PRIVACY_VIOLATION = "privacy.violation"
    EXPORT_OPERATION = "export.operation"
    UNKNOWN = "unknown"


EVENT_CATEGORIES: Dict[str, str] = {
    "SYSTEM_INTERNAL": EventCategory.SYSTEM_INTERNAL,
    "USER_ACTION": EventCategory.USER_ACTION,
    "PROOF_OPERATION": EventCategory.PROOF_OPERATION,
    "MEDIA_OPERATION": EventCategory.MEDIA_OPERATION,
    "NETWORK_OPERATION": EventCategory.NETWORK_OPERATION,
    "ERROR_OBSERVED": EventCategory.ERROR_OBSERVED,
    "OP_SIGNAL": EventCategory.OP_SIGNAL,
    "PRIVACY_VIOLATION": EventCategory.PRIVACY_VIOLATION,
    "EXPORT_OPERATION": EventCategory.EXPORT_OPERATION,
    "UNKNOWN": EventCategory.UNKNOWN,
}


class EventLifecycleState:
    CREATED = "created"
    ALLOWLISTED = "allowlisted"
    CONSENT_PENDING = "consent_pending"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_DENIED = "consent_denied"
    SAMPLED_IN = "sampled_in"
    SAMPLED_OUT = "sampled_out"
    REPLAY_REJECTED = "replay_rejected"
    REDACTED = "redacted"
    DROPPED = "dropped"
    INGESTED = "ingested"
    EXPORTED = "exported"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED_STABLE = "failed_stable"


class EventOperationStatus:
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PARTIALLY_COMPLETED = "partially_completed"
    COMPLETED = "completed"
    INVALID = "invalid"
    OVERSIZED = "oversized"
    DUPLICATE = "duplicate"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED_SAFE = "failed_safe"
    FAILED_UNSAFE = "failed_unsafe"
    RECOVERED = "recovered"


EVENT_ALLOWLIST: Set[str] = {
    "system.startup",
    "system.shutdown",
    "system.health_check",
    "system.config_loaded",
    "system.config_reload_requested",
    "system.rollout_phase_changed",
    "system.saturation_signal",
    "system.recovery_signal",
    "user.consent_granted",
    "user.consent_denied",
    "user.consent_updated",
    "user.session_started",
    "user.session_ended",
    "user.authentication_attempted",
    "user.authentication_succeeded",
    "user.authentication_failed",
    "user.authorization_denied",
    "user.rate_limited",
    "proof.workflow_started",
    "proof.workflow_queued",
    "proof.workflow_completed",
    "proof.workflow_failed",
    "proof.workflow_cancelled",
    "proof.workflow_timed_out",
    "proof.workflow_invalid",
    "proof.circuit_compilation_requested",
    "proof.circuit_compilation_completed",
    "proof.circuit_compilation_failed",
    "proof.generate_requested",
    "proof.generate_completed",
    "proof.generate_failed",
    "proof.verify_requested",
    "proof.verify_completed",
    "proof.verify_failed",
    "media.upload_started",
    "media.upload_completed",
    "media.upload_failed",
    "media.upload_cancelled",
    "media.upload_oversized",
    "media.metadata_extracted",
    "media.metadata_parse_failed",
    "media.embed_requested",
    "media.embed_completed",
    "media.embed_failed",
    "media.extract_requested",
    "media.extract_completed",
    "media.extract_failed",
    "network.rpc_requested",
    "network.rpc_completed",
    "network.rpc_failed",
    "network.stellar_tx_submitted",
    "network.stellar_tx_confirmed",
    "network.stellar_tx_failed",
    "network.stellar_tx_timed_out",
    "error.error_observed",
    "error.validation_failed",
    "error.resource_limit_exceeded",
    "error.export_safety_violation_detected",
    "error.redaction_engine_fallback_triggered",
    "ops.progress_tick",
    "ops.saturation_detected",
    "ops.recovery_triggered",
    "ops.recovery_completed",
    "privacy.consent_missing",
    "privacy.replay_attempt_detected",
    "privacy.allowlist_violation_attempted",
    "privacy.sensitive_field_detected_in_event",
    "export.export_requested",
    "export.export_completed",
    "export.export_failed",
    "export.export_safety_validated",
    "export.import_completed",
}


@dataclass
class EventAllowlist:
    extra_allowed: Optional[Set[str]] = None
    blocklist: Set[str] = field(default_factory=set)

    def is_allowed(self, event_name: str) -> bool:
        combined = EVENT_ALLOWLIST | (self.extra_allowed or set())
        return event_name in (combined - self.blocklist)

    def all_allowed(self) -> Set[str]:
        combined = EVENT_ALLOWLIST | (self.extra_allowed or set())
        return combined - self.blocklist

    def add_allowed(self, event_name: str) -> None:
        if self.extra_allowed is None:
            self.extra_allowed = set()
        self.extra_allowed.add(event_name)

    def block(self, event_name: str) -> None:
        self.blocklist.add(event_name)


def _generate_event_id() -> str:
    random_bytes = os.urandom(16)
    timestamp = str(time.time()).encode("utf-8")
    raw = random_bytes + timestamp
    digest = hashlib.sha256(raw).hexdigest()[:32]
    return f"evt-v1:{digest}"


@dataclass
class TrackedEvent:
    event_name: str
    event_id: str
    category: str
    lifecycle_state: str = EventLifecycleState.CREATED
    operation_status: str = EventOperationStatus.NOT_STARTED
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at_utc: float = field(default_factory=time.time)
    updated_at_utc: float = field(default_factory=time.time)
    correlation_id: Optional[str] = None
    account_id_tag: Optional[str] = None
    session_id_tag: Optional[str] = None
    user_agent_tag: Optional[str] = None
    ip_tag: Optional[str] = None
    schema_version: str = ANALYTICS_EVENT_SCHEMA_VERSION
    redaction_version: Optional[str] = None
    sampling_rate_applied: Optional[float] = None
    rejection_reason: Optional[str] = None
    annotations: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.event_name = str(self.event_name)
        if self.updated_at_utc is None:
            self.updated_at_utc = time.time()


@dataclass
class EventPayload:
    labels: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, Union[float, int]] = field(default_factory=dict)
    duration_seconds: Optional[float] = None
    error_code: Optional[str] = None
    error_safe: bool = True


VALID_TRANSITIONS: Dict[str, Set[str]] = {
    EventLifecycleState.CREATED: {
        EventLifecycleState.ALLOWLISTED,
        EventLifecycleState.DROPPED,
        EventLifecycleState.CANCELLED,
        EventLifecycleState.TIMED_OUT,
        EventLifecycleState.REPLAY_REJECTED,
    },
    EventLifecycleState.ALLOWLISTED: {
        EventLifecycleState.CONSENT_PENDING,
        EventLifecycleState.CONSENT_GRANTED,
        EventLifecycleState.CONSENT_DENIED,
        EventLifecycleState.REPLAY_REJECTED,
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.CONSENT_PENDING: {
        EventLifecycleState.CONSENT_GRANTED,
        EventLifecycleState.CONSENT_DENIED,
        EventLifecycleState.TIMED_OUT,
        EventLifecycleState.DROPPED,
        EventLifecycleState.CANCELLED,
    },
    EventLifecycleState.CONSENT_GRANTED: {
        EventLifecycleState.SAMPLED_IN,
        EventLifecycleState.SAMPLED_OUT,
        EventLifecycleState.DROPPED,
        EventLifecycleState.CANCELLED,
        EventLifecycleState.TIMED_OUT,
        EventLifecycleState.REPLAY_REJECTED,
    },
    EventLifecycleState.CONSENT_DENIED: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.SAMPLED_IN: {
        EventLifecycleState.REDACTED,
        EventLifecycleState.DROPPED,
        EventLifecycleState.CANCELLED,
        EventLifecycleState.TIMED_OUT,
        EventLifecycleState.FAILED_STABLE,
    },
    EventLifecycleState.SAMPLED_OUT: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.REPLAY_REJECTED: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.REDACTED: {
        EventLifecycleState.INGESTED,
        EventLifecycleState.EXPORTED,
        EventLifecycleState.DROPPED,
        EventLifecycleState.FAILED_STABLE,
        EventLifecycleState.CANCELLED,
        EventLifecycleState.TIMED_OUT,
    },
    EventLifecycleState.INGESTED: {
        EventLifecycleState.EXPORTED,
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.EXPORTED: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.CANCELLED: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.TIMED_OUT: {
        EventLifecycleState.DROPPED,
    },
    EventLifecycleState.FAILED_STABLE: {
        EventLifecycleState.DROPPED,
        EventLifecycleState.INGESTED,
    },
    EventLifecycleState.DROPPED: set(),
}


def transition_event_state(
    event: TrackedEvent,
    new_state: str,
    reason: Optional[str] = None,
    new_operation_status: Optional[str] = None,
) -> TrackedEvent:
    current = event.lifecycle_state
    allowed_next = VALID_TRANSITIONS.get(current, set())

    if new_state not in allowed_next:
        actual_new = EventLifecycleState.FAILED_STABLE
        event.rejection_reason = f"invalid_transition_{current}_to_{new_state}"
    else:
        actual_new = new_state
        if reason is not None:
            event.rejection_reason = reason

    event.lifecycle_state = actual_new

    if new_operation_status is not None:
        event.operation_status = new_operation_status

    event.updated_at_utc = time.time()
    return event


def create_event(
    event_name: str,
    category: str,
    payload: Optional[Dict[str, Any]] = None,
    **extra,
) -> TrackedEvent:
    event_id = _generate_event_id()
    actual_payload: Dict[str, Any] = payload if payload is not None else {}
    ev = TrackedEvent(
        event_name=event_name,
        event_id=event_id,
        category=category,
        payload=actual_payload,
        **extra,
    )
    return ev


def event_is_allowed(
    event_name: str,
    allowlist: Optional[EventAllowlist] = None,
) -> bool:
    a = allowlist if allowlist is not None else EventAllowlist()
    return a.is_allowed(event_name)
