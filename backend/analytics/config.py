from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class CryptoDomainVersion:
    domain: str
    version: int
    algorithm: str
    introduced_in_schema: str


REDACTION_DOMAIN = CryptoDomainVersion("redaction", 1, "SHA-256/hex-trunc", "v1")
SAMPLING_TOKEN_DOMAIN = CryptoDomainVersion("sampling-token", 1, "SHA-256/hex8", "v1")
EVENT_ID_DOMAIN = CryptoDomainVersion("event-id", 1, "SHA-256/hex32", "v1")
SESSION_REPLAY_NONCE_DOMAIN = CryptoDomainVersion("replay-nonce", 1, "SHA-256/hex16", "v1")
CONSENT_TOKEN_DOMAIN = CryptoDomainVersion("consent-token", 1, "SHA-256/hex24", "v1")

ANALYTICS_CONFIG_SCHEMA_VERSION = "1.0.0"


class RolloutPhase(str):
    OFF = "off"
    SHADOW = "shadow"
    CANARY = "canary"
    FULL = "full"


ANALYTICS_ROLLOUT_PHASE = os.getenv("ANALYTICS_ROLLOUT", RolloutPhase.SHADOW)


@dataclass
class AnalyticsLimits:
    max_event_bytes: int = 8192
    max_log_entries_per_request: int = 256
    max_redaction_depth: int = 16
    max_total_redaction_nodes: int = 16_384
    max_endpoint_segments: int = 32
    max_export_bytes: int = 4_194_304
    max_pending_nonces: int = 16_384
    max_session_id_bytes: int = 256
    max_concurrent_events: int = 512
    max_sampling_bucket: int = 1_000_000

    def __post_init__(self) -> None:
        fields = [
            ("max_event_bytes", self.max_event_bytes),
            ("max_log_entries_per_request", self.max_log_entries_per_request),
            ("max_redaction_depth", self.max_redaction_depth),
            ("max_total_redaction_nodes", self.max_total_redaction_nodes),
            ("max_endpoint_segments", self.max_endpoint_segments),
            ("max_export_bytes", self.max_export_bytes),
            ("max_pending_nonces", self.max_pending_nonces),
            ("max_session_id_bytes", self.max_session_id_bytes),
            ("max_concurrent_events", self.max_concurrent_events),
            ("max_sampling_bucket", self.max_sampling_bucket),
        ]
        for name, value in fields:
            if value <= 0:
                raise ValueError(f"AnalyticsLimits.{name} must be positive, got {value}")


@dataclass
class SamplingConfig:
    default_rate: float = 1.0
    allowlist_overrides: Dict[str, float] = field(
        default_factory=lambda: {
            "proof_completed": 1.0,
            "video_uploaded": 1.0,
            "error_observed": 1.0,
            "saturation_signal": 1.0,
            "recovery_signal": 1.0,
        }
    )

    def __post_init__(self) -> None:
        if not (0.0 <= self.default_rate <= 1.0):
            raise ValueError(f"SamplingConfig.default_rate must be in [0,1], got {self.default_rate}")
        for key, value in self.allowlist_overrides.items():
            if not (0.0 <= value <= 1.0):
                raise ValueError(f"SamplingConfig.allowlist_overrides['{key}'] must be in [0,1], got {value}")


@dataclass
class ExportConfig:
    compress_default: bool = False
    include_debug_fields: bool = False
    include_sampled_out_events: bool = False
    max_artifacts_per_export: int = 64
    export_token_header_name: str = "X-Analytics-Export-Token"
    export_token_required_in_production: bool = True


@dataclass
class AnalyticsPersistenceConfig:
    durable_storage_enabled: bool = False
    durable_log_path: Optional[str] = None
    durable_log_mode: str = "append-only"
    durable_log_rotate_bytes: int = 50_000_000
    durable_log_encrypt_at_rest: bool = True


@dataclass
class AnalyticsFeatureFlags:
    event_allowlist_enabled: bool = True
    field_redaction_enabled: bool = True
    consent_check_enabled: bool = True
    sampling_enabled: bool = True
    session_replay_protection_enabled: bool = True
    export_safety_validation_enabled: bool = True
    operational_signals_enabled: bool = True
    middleware_auto_instrument: bool = True


@dataclass
class AnalyticsRolloutConfig:
    phase: str = ANALYTICS_ROLLOUT_PHASE
    canary_percent: int = 10
    canary_selector_field: str = "account_id"
    rollback_safe_on_error: bool = True
    shadow_drop_on_rollback: bool = True

    def __post_init__(self) -> None:
        if not (0 <= self.canary_percent <= 100):
            raise ValueError(f"AnalyticsRolloutConfig.canary_percent must be in [0,100], got {self.canary_percent}")


@dataclass
class AnalyticsConfig:
    limits: AnalyticsLimits = field(default_factory=AnalyticsLimits)
    sampling: SamplingConfig = field(default_factory=SamplingConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    persistence: AnalyticsPersistenceConfig = field(default_factory=AnalyticsPersistenceConfig)
    features: AnalyticsFeatureFlags = field(default_factory=AnalyticsFeatureFlags)
    rollout: AnalyticsRolloutConfig = field(default_factory=AnalyticsRolloutConfig)
    crypto_domains: Tuple[CryptoDomainVersion, ...] = (
        REDACTION_DOMAIN,
        SAMPLING_TOKEN_DOMAIN,
        EVENT_ID_DOMAIN,
        SESSION_REPLAY_NONCE_DOMAIN,
        CONSENT_TOKEN_DOMAIN,
    )
    schema_version: str = ANALYTICS_CONFIG_SCHEMA_VERSION
    generated_at_utc_epoch_seconds: float = field(default_factory=time.time)
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))


def _safe_int(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_float(value: Optional[str], default: float) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _clamp(value: int, min_val: int, max_val: Optional[int] = None) -> int:
    if value < min_val:
        return min_val
    if max_val is not None and value > max_val:
        return max_val
    return value


def _clamp_float(value: float, min_val: float, max_val: float) -> float:
    if value < min_val:
        return min_val
    if value > max_val:
        return max_val
    return value


def load_analytics_config(**overrides) -> AnalyticsConfig:
    config = AnalyticsConfig()

    env_rollout = os.getenv("ANALYTICS_ROLLOUT")
    if env_rollout is not None:
        config.rollout.phase = env_rollout

    raw_max_event_bytes = _safe_int(os.getenv("ANALYTICS_MAX_EVENT_BYTES"), None)
    if raw_max_event_bytes is not None:
        config.limits.max_event_bytes = _clamp(raw_max_event_bytes, 1)

    raw_max_log_entries = _safe_int(os.getenv("ANALYTICS_MAX_LOG_ENTRIES"), None)
    if raw_max_log_entries is not None:
        config.limits.max_log_entries_per_request = _clamp(raw_max_log_entries, 1)

    raw_sampling_rate = _safe_float(os.getenv("ANALYTICS_SAMPLING_RATE"), None)
    if raw_sampling_rate is not None:
        config.sampling.default_rate = _clamp_float(raw_sampling_rate, 0.0, 1.0)

    raw_consent_enabled = os.getenv("ANALYTICS_CONSENT_ENABLED")
    if raw_consent_enabled is not None:
        config.features.consent_check_enabled = _safe_bool(raw_consent_enabled, config.features.consent_check_enabled)

    raw_session_replay = os.getenv("ANALYTICS_SESSION_REPLAY_PROTECTION")
    if raw_session_replay is not None:
        config.features.session_replay_protection_enabled = _safe_bool(
            raw_session_replay, config.features.session_replay_protection_enabled
        )

    raw_persistence_enabled = os.getenv("ANALYTICS_PERSISTENCE_ENABLED")
    if raw_persistence_enabled is not None:
        config.persistence.durable_storage_enabled = _safe_bool(
            raw_persistence_enabled, config.persistence.durable_storage_enabled
        )

    raw_durable_path = os.getenv("ANALYTICS_DURABLE_PATH")
    if raw_durable_path is not None and raw_durable_path.strip():
        config.persistence.durable_log_path = raw_durable_path.strip()

    raw_export_token_required = os.getenv("ANALYTICS_EXPORT_TOKEN_REQUIRED")
    if raw_export_token_required is not None:
        config.export.export_token_required_in_production = _safe_bool(
            raw_export_token_required, config.export.export_token_required_in_production
        )

    for key, value in overrides.items():
        if key == "limits" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.limits, k):
                    setattr(config.limits, k, v)
        elif key == "sampling" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.sampling, k):
                    setattr(config.sampling, k, v)
        elif key == "export" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.export, k):
                    setattr(config.export, k, v)
        elif key == "persistence" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.persistence, k):
                    setattr(config.persistence, k, v)
        elif key == "features" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.features, k):
                    setattr(config.features, k, v)
        elif key == "rollout" and isinstance(value, dict):
            for k, v in value.items():
                if hasattr(config.rollout, k):
                    setattr(config.rollout, k, v)
        elif hasattr(config, key):
            setattr(config, key, value)

    return config
