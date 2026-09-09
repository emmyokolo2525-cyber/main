from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from analytics.config import AnalyticsConfig, AnalyticsFeatureFlags, load_analytics_config
except Exception:
    AnalyticsConfig = None
    AnalyticsFeatureFlags = None
    load_analytics_config = None

try:
    from analytics.redaction import RedactionEngine, CRYPTO_DOMAIN_VERSION
except Exception:
    RedactionEngine = None
    CRYPTO_DOMAIN_VERSION = "harpocrates-redaction-v1"

try:
    from analytics.events import (
        EventAllowlist,
        EventLifecycleState,
        EventOperationStatus,
        TrackedEvent,
        create_event,
        event_is_allowed,
        transition_event_state,
    )
except Exception:
    EventAllowlist = None
    EventLifecycleState = None
    EventOperationStatus = None
    TrackedEvent = None
    create_event = None
    event_is_allowed = None
    transition_event_state = None

try:
    from analytics.consent import ConsentManager, ConsentStatus
except Exception:
    ConsentManager = None
    ConsentStatus = None

try:
    from analytics.session_protection import SessionReplayGuard, SessionReplayOutcome
except Exception:
    SessionReplayGuard = None
    SessionReplayOutcome = None

try:
    from analytics.sampling import Sampler, SamplingOutcome
except Exception:
    Sampler = None
    SamplingOutcome = None

try:
    from analytics.log_processor import LogEntry, LogProcessor, sanitize_error_context
except Exception:
    LogEntry = None
    LogProcessor = None
    sanitize_error_context = None

try:
    from analytics.export_manager import ExportManager
except Exception:
    ExportManager = None

try:
    from analytics.metrics_collector import (
        AnalyticsOperationalMetrics,
        MetricDomain,
        RecoverySignal,
        SaturationSignal,
        operational_collector,
    )
except Exception:
    AnalyticsOperationalMetrics = None
    MetricDomain = None
    RecoverySignal = None
    SaturationSignal = None
    operational_collector = None


@dataclass
class RequestContext:
    request_id_tag: Optional[str] = None
    account_id_tag: Optional[str] = None
    session_id_tag: Optional[str] = None
    ip_tag: Optional[str] = None
    user_agent_tag: Optional[str] = None
    endpoint_pattern: str = ""
    method: str = ""
    status_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    rollout_phase: str = "shadow"
    consent_token: Optional[str] = None
    replay_nonce: Optional[str] = None


class AnalyticsError(Exception):
    def __init__(self, message: str, code: str = "analytics_error", safe: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.safe = safe


@dataclass
class EngineHealthSnapshot:
    generated_at_epoch: float
    config_schema_version: str
    rollout_phase: str
    features: Dict[str, bool]
    metrics: Dict[str, Any]
    consent_states_tracked: int
    nonces_tracked: int
    sessions_tracked: int
    log_entries_tracked: int
    artifacts_tracked: int
    engine_version: str = "harpocrates-analytics-engine-v1"
    anomalies: List[str] = field(default_factory=list)


class AnalyticsEngine:
    def __init__(
        self,
        config: Optional[AnalyticsConfig] = None,
        redaction: Optional[RedactionEngine] = None,
        allowlist: Optional[EventAllowlist] = None,
        consent: Optional[ConsentManager] = None,
        replay_guard: Optional[SessionReplayGuard] = None,
        sampler: Optional[Sampler] = None,
        log_processor: Optional[LogProcessor] = None,
        metrics: Optional[AnalyticsOperationalMetrics] = None,
        export_mgr: Optional[ExportManager] = None,
    ) -> None:
        if config is not None:
            self.config = config
        elif load_analytics_config is not None:
            self.config = load_analytics_config()
        elif AnalyticsConfig is not None:
            self.config = AnalyticsConfig()
        else:
            self.config = None

        if redaction is not None:
            self.redaction = redaction
        elif RedactionEngine is not None:
            self.redaction = RedactionEngine()
        else:
            self.redaction = None

        if allowlist is not None:
            self.allowlist = allowlist
        elif EventAllowlist is not None:
            self.allowlist = EventAllowlist()
        else:
            self.allowlist = None

        if consent is not None:
            self.consent = consent
        elif ConsentManager is not None:
            self.consent = ConsentManager()
        else:
            self.consent = None

        if replay_guard is not None:
            self.replay_guard = replay_guard
        elif SessionReplayGuard is not None:
            self.replay_guard = SessionReplayGuard()
        else:
            self.replay_guard = None

        if sampler is not None:
            self.sampler = sampler
        elif Sampler is not None:
            sampling_enabled = True
            default_rate = 1.0
            allowlist_overrides: Dict[str, float] = {}
            if self.config is not None and hasattr(self.config, "sampling"):
                default_rate = getattr(self.config.sampling, "default_rate", 1.0)
                allowlist_overrides = getattr(self.config.sampling, "allowlist_overrides", {}) or {}
            self.sampler = Sampler(
                enabled=sampling_enabled,
                default_rate=default_rate,
                allowlist_overrides=allowlist_overrides,
            )
        else:
            self.sampler = None

        if log_processor is not None:
            self.log_processor = log_processor
        elif LogProcessor is not None:
            self.log_processor = LogProcessor(redaction_engine=self.redaction)
        else:
            self.log_processor = None

        if metrics is not None:
            self.metrics = metrics
        elif operational_collector is not None:
            self.metrics = operational_collector
        elif AnalyticsOperationalMetrics is not None:
            self.metrics = AnalyticsOperationalMetrics()
        else:
            self.metrics = None

        if export_mgr is not None:
            self.export_mgr = export_mgr
        elif ExportManager is not None:
            self.export_mgr = ExportManager(processor=self.log_processor)
        else:
            self.export_mgr = None

        self._lock: threading.RLock = threading.RLock()
        self._requests_seen: int = 0
        self._engine_created_at: float = time.time()

    def process_event(
        self,
        event_name: str,
        category: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[RequestContext] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrackedEvent:
        if context is None:
            context = RequestContext()
        if self.metrics is not None:
            self.metrics.record_event_seen(event_name)

        extra_fields: Dict[str, Any] = {}
        if context.account_id_tag:
            extra_fields["account_id_tag"] = context.account_id_tag
        if context.session_id_tag:
            extra_fields["session_id_tag"] = context.session_id_tag
        if context.request_id_tag:
            extra_fields["correlation_id"] = context.request_id_tag
        if context.user_agent_tag:
            extra_fields["user_agent_tag"] = context.user_agent_tag
        if context.ip_tag:
            extra_fields["ip_tag"] = context.ip_tag
        if extra:
            extra_fields.update(extra)

        event = create_event(event_name, category, payload, **extra_fields)

        features_enabled = True
        if self.config is not None and hasattr(self.config, "features"):
            features_enabled = getattr(self.config.features, "event_allowlist_enabled", True)

        if features_enabled and event_is_allowed is not None:
            allowed = False
            if self.allowlist is not None:
                allowed = self.allowlist.is_allowed(event_name)
            else:
                allowed = event_is_allowed(event_name)
            if not allowed:
                if transition_event_state is not None and EventLifecycleState is not None:
                    event = transition_event_state(
                        event,
                        EventLifecycleState.DROPPED,
                        reason="allowlist_rejected",
                    )
                if self.metrics is not None:
                    self.metrics.record_failure("allowlist_rejected", category=MetricDomain.ALLOWLIST if MetricDomain is not None else "allowlist")
                return event
        if transition_event_state is not None and EventLifecycleState is not None:
            event = transition_event_state(event, EventLifecycleState.ALLOWLISTED)

        consent_check_enabled = True
        if self.config is not None and hasattr(self.config, "features"):
            consent_check_enabled = getattr(self.config.features, "consent_check_enabled", True)

        if consent_check_enabled and self.consent is not None:
            scope = "analytics:" + event_name
            consent_ok, consent_state = self.consent.check_consent(context.account_id_tag, scope)
            status = getattr(consent_state, "status", None) if consent_state is not None else None
            if ConsentStatus is not None:
                if status == ConsentStatus.GRANTED:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(event, EventLifecycleState.CONSENT_GRANTED)
                elif status == ConsentStatus.DENIED:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(
                            event,
                            EventLifecycleState.CONSENT_DENIED,
                            reason="consent_denied",
                        )
                        event = transition_event_state(
                            event,
                            EventLifecycleState.DROPPED,
                            reason="consent_denied",
                        )
                    return event
                elif status == ConsentStatus.GRACE:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(event, EventLifecycleState.CONSENT_PENDING)
                    event.annotations["consent_grace"] = "true"
                else:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(event, EventLifecycleState.CONSENT_PENDING)
                    event.annotations["consent_grace"] = "true"
            else:
                if consent_ok:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(event, EventLifecycleState.CONSENT_GRANTED)
                else:
                    if transition_event_state is not None and EventLifecycleState is not None:
                        event = transition_event_state(event, EventLifecycleState.CONSENT_PENDING)
                    event.annotations["consent_grace"] = "true"

        replay_enabled = True
        if self.config is not None and hasattr(self.config, "features"):
            replay_enabled = getattr(self.config.features, "session_replay_protection_enabled", True)

        if replay_enabled and context.replay_nonce and self.replay_guard is not None:
            outcome = self.replay_guard.verify_and_record(
                nonce=context.replay_nonce,
                session_tag=context.session_id_tag,
                account_tag=context.account_id_tag,
            )
            new_outcome = SessionReplayOutcome.NEW if SessionReplayOutcome is not None else "new"
            if outcome != new_outcome:
                if transition_event_state is not None and EventLifecycleState is not None:
                    event = transition_event_state(
                        event,
                        EventLifecycleState.REPLAY_REJECTED,
                        reason="replay:" + outcome,
                    )
                    event = transition_event_state(
                        event,
                        EventLifecycleState.DROPPED,
                        reason="replay:" + outcome,
                    )
                if self.metrics is not None:
                    self.metrics.record_failure(
                        "replay_" + outcome,
                        category=MetricDomain.SESSION if MetricDomain is not None else "session",
                    )
                return event

        sampling_enabled = True
        if self.config is not None and hasattr(self.config, "features"):
            sampling_enabled = getattr(self.config.features, "sampling_enabled", True)

        if sampling_enabled and self.sampler is not None:
            decision = self.sampler.decide(
                event_name=event_name,
                account_tag=context.account_id_tag,
                session_tag=context.session_id_tag,
            )
            event.sampling_rate_applied = decision.rate_applied
            event.annotations["sampling_outcome"] = decision.outcome
            if not decision.sampled_in:
                if transition_event_state is not None and EventLifecycleState is not None:
                    event = transition_event_state(
                        event,
                        EventLifecycleState.SAMPLED_OUT,
                        reason="sampling:" + decision.outcome,
                    )
                    event = transition_event_state(
                        event,
                        EventLifecycleState.DROPPED,
                        reason="sampling:" + decision.outcome,
                    )
                if self.metrics is not None:
                    self.metrics.increment_counter(
                        MetricDomain.SAMPLING if MetricDomain is not None else "sampling",
                        decision.outcome,
                        1,
                    )
                return event
            if transition_event_state is not None and EventLifecycleState is not None:
                event = transition_event_state(event, EventLifecycleState.SAMPLED_IN)

        redaction_enabled = True
        if self.config is not None and hasattr(self.config, "features"):
            redaction_enabled = getattr(self.config.features, "field_redaction_enabled", True)

        if redaction_enabled and self.redaction is not None and event.payload:
            outcome = self.redaction.sanitize(event.payload, context=event_name)
            event.payload = outcome.data if outcome is not None else event.payload
            event.redaction_version = getattr(outcome, "redaction_version", CRYPTO_DOMAIN_VERSION)
            cats = getattr(outcome, "categories_redacted", []) or []
            if cats:
                event.annotations["categories_redacted"] = ",".join(sorted(set(cats)))
            if transition_event_state is not None and EventLifecycleState is not None:
                event = transition_event_state(event, EventLifecycleState.REDACTED)
            if self.metrics is not None:
                for cat in set(cats):
                    self.metrics.increment_counter(
                        MetricDomain.REDACTION if MetricDomain is not None else "redaction",
                        cat,
                        1,
                    )

        if self.log_processor is not None and LogEntry is not None:
            max_log_entries = 256
            if self.config is not None and hasattr(self.config, "limits"):
                max_log_entries = getattr(self.config.limits, "max_log_entries_per_request", 256)
            with self.log_processor._lock:
                if len(self.log_processor._entries) >= max_log_entries:
                    if self.metrics is not None and SaturationSignal is not None:
                        self.metrics.record_saturation_signal(SaturationSignal.LOG_ENTRIES_LIMIT_HIT)
            extra_labels: Dict[str, str] = {}
            if category:
                extra_labels["category"] = category
            if event.lifecycle_state:
                extra_labels["lifecycle"] = event.lifecycle_state
            log_entry = self.log_processor.sanitize_error_context(
                error=event_name,
                endpoint=context.endpoint_pattern,
                method=context.method,
                status_code=context.status_code,
                operation_status=event.operation_status,
                duration_seconds=context.duration_seconds,
                correlation_tag=context.request_id_tag,
                account_tag=context.account_id_tag,
                session_tag=context.session_id_tag,
                extra_labels=extra_labels,
            )
            log_entry.event_name = event_name
            log_entry.operation_status = event.operation_status
            log_entry.lifecycle_state = event.lifecycle_state
            self.log_processor.ingest(log_entry)

        if transition_event_state is not None and EventLifecycleState is not None:
            if event.lifecycle_state not in {EventLifecycleState.INGESTED, EventLifecycleState.DROPPED}:
                event = transition_event_state(event, EventLifecycleState.INGESTED)

        with self._lock:
            self._requests_seen += 1

        return event

    def record_error(
        self,
        error: Any,
        context: Optional[RequestContext] = None,
        operation_status: Optional[str] = None,
        extra_labels: Optional[Dict[str, str]] = None,
        extra_counters: Optional[Dict[str, int]] = None,
    ) -> LogEntry:
        if context is None:
            context = RequestContext()
        if sanitize_error_context is not None:
            entry = sanitize_error_context(
                error=error,
                endpoint=context.endpoint_pattern,
                method=context.method,
                status_code=context.status_code,
                operation_status=operation_status,
                duration_seconds=context.duration_seconds,
                correlation_tag=context.request_id_tag,
                account_tag=context.account_id_tag,
                session_tag=context.session_id_tag,
                extra_labels=extra_labels,
                extra_counters=extra_counters,
            )
        elif self.log_processor is not None:
            entry = self.log_processor.sanitize_error_context(
                error=error,
                endpoint=context.endpoint_pattern,
                method=context.method,
                status_code=context.status_code,
                operation_status=operation_status,
                duration_seconds=context.duration_seconds,
                correlation_tag=context.request_id_tag,
                account_tag=context.account_id_tag,
                session_tag=context.session_id_tag,
                extra_labels=extra_labels,
                extra_counters=extra_counters,
            )
        else:
            entry = None

        if self.metrics is not None:
            if isinstance(error, BaseException):
                error_type = type(error).__name__
            elif isinstance(error, str):
                error_type = "str_error"
            else:
                error_type = "unknown_error"
            self.metrics.record_failure(error_code=error_type, category="error")

        if entry is not None and self.log_processor is not None:
            self.log_processor.ingest(entry, allow_duplicate=True)
        return entry

    def record_progress(self, domain: str, name: str, context: Optional[RequestContext] = None) -> None:
        if self.metrics is not None:
            self.metrics.progress_tick(domain, name)

    def record_saturation(self, signal: str, detail: Optional[str] = None) -> None:
        if self.metrics is not None:
            self.metrics.record_saturation_signal(signal, detail)

    def record_recovery(self, signal: str, detail: Optional[str] = None) -> None:
        if self.metrics is not None:
            self.metrics.record_recovery_signal(signal, detail)

    def health_snapshot(self, include_metrics: bool = True) -> EngineHealthSnapshot:
        rollout_phase = "shadow"
        schema_version = "1.0.0"
        if self.config is not None:
            if hasattr(self.config, "rollout"):
                rollout_phase = getattr(self.config.rollout, "phase", "shadow")
            schema_version = getattr(self.config, "schema_version", "1.0.0")

        features: Dict[str, bool] = {}
        if self.config is not None and hasattr(self.config, "features"):
            feats = self.config.features
            for attr in dir(feats):
                if attr.startswith("_"):
                    continue
                val = getattr(feats, attr)
                if isinstance(val, bool):
                    features[attr] = val

        metrics_snapshot: Dict[str, Any] = {}
        if include_metrics and self.metrics is not None:
            metrics_snapshot = self.metrics.snapshot()

        consent_states_tracked = 0
        if self.consent is not None:
            try:
                consent_states_tracked = len(self.consent._consent_states)
            except Exception:
                consent_states_tracked = 0

        nonces_tracked = 0
        sessions_tracked = 0
        if self.replay_guard is not None:
            try:
                stats = self.replay_guard.stats()
                nonces_tracked = stats.get("nonce_count", 0)
                sessions_tracked = stats.get("session_count", 0)
            except Exception:
                nonces_tracked = 0
                sessions_tracked = 0

        log_entries_tracked = 0
        if self.log_processor is not None:
            try:
                log_entries_tracked = len(self.log_processor._entries)
            except Exception:
                log_entries_tracked = 0

        artifacts_tracked = 0
        if self.export_mgr is not None:
            try:
                artifacts_tracked = len(self.export_mgr._artifacts)
            except Exception:
                artifacts_tracked = 0

        anomalies: List[str] = []
        try:
            sat_sigs = metrics_snapshot.get("saturation_signals", {}) or {}
            if sat_sigs:
                for sig_name in sat_sigs:
                    anomalies.append("saturation:" + sig_name)
        except Exception:
            pass
        try:
            fail_errs = metrics_snapshot.get("failure_errors", {}) or {}
            if fail_errs:
                for err_name, cnt in fail_errs.items():
                    if cnt > 0:
                        anomalies.append("failure:" + err_name)
                        break
        except Exception:
            pass

        return EngineHealthSnapshot(
            generated_at_epoch=time.time(),
            config_schema_version=schema_version,
            rollout_phase=rollout_phase,
            features=features,
            metrics=metrics_snapshot,
            consent_states_tracked=consent_states_tracked,
            nonces_tracked=nonces_tracked,
            sessions_tracked=sessions_tracked,
            log_entries_tracked=log_entries_tracked,
            artifacts_tracked=artifacts_tracked,
            anomalies=anomalies,
        )

    def reset_all_for_tests(self) -> None:
        if self.metrics is not None and hasattr(self.metrics, "reset"):
            self.metrics.reset()
        if self.replay_guard is not None and hasattr(self.replay_guard, "reset"):
            self.replay_guard.reset()
        if self.consent is not None:
            try:
                with self.consent._lock:
                    self.consent._consent_states.clear()
            except Exception:
                pass
        if self.allowlist is not None:
            try:
                if self.allowlist.extra_allowed is not None:
                    self.allowlist.extra_allowed.clear()
                self.allowlist.blocklist.clear()
            except Exception:
                pass
        if self.log_processor is not None:
            try:
                with self.log_processor._lock:
                    self.log_processor._entries.clear()
                    self.log_processor._total_entries_processed = 0
                    self.log_processor._export_safety_violations = 0
                    self.log_processor._oversized_dropped = 0
            except Exception:
                pass
        if self.export_mgr is not None:
            self.export_mgr.reset()
        with self._lock:
            self._requests_seen = 0


_global_engine: Optional[AnalyticsEngine] = None


def get_engine() -> AnalyticsEngine:
    global _global_engine
    if _global_engine is None:
        _global_engine = set_engine(AnalyticsEngine())
    return _global_engine


def set_engine(engine: AnalyticsEngine) -> AnalyticsEngine:
    global _global_engine
    _global_engine = engine
    return engine
