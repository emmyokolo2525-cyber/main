from __future__ import annotations

import json
import random
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from analytics.analytics_engine import AnalyticsEngine, get_engine
except Exception:
    AnalyticsEngine = None
    get_engine = None

try:
    from analytics.events import EVENT_ALLOWLIST, EventAllowlist
except Exception:
    EVENT_ALLOWLIST = None
    EventAllowlist = None

try:
    from analytics.consent import ConsentDecision, ConsentManager, ConsentSource, ConsentStatus
except Exception:
    ConsentDecision = None
    ConsentManager = None
    ConsentSource = None
    ConsentStatus = None

try:
    from analytics.export_manager import ExportManager, ExportPolicy
except Exception:
    ExportManager = None
    ExportPolicy = None

try:
    from analytics.metrics_collector import RecoverySignal, SaturationSignal
except Exception:
    RecoverySignal = None
    SaturationSignal = None


def make_response(
    body: Any,
    status: int = 200,
    content_type: str = "application/json",
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Any, int, Tuple[Tuple[str, str], ...]]:
    if isinstance(body, (dict, list, tuple, int, float, str, bool, type(None))):
        try:
            json_body = json.dumps(body, sort_keys=True, default=str)
        except Exception:
            json_body = json.dumps({"error": "serialization_failed"}, default=str)
    elif is_dataclass(body):
        try:
            d = asdict(body)
            json_body = json.dumps(d, sort_keys=True, default=str)
        except Exception:
            json_body = json.dumps({"error": "serialization_failed"}, default=str)
    else:
        try:
            json_body = json.dumps(body, sort_keys=True, default=str)
        except Exception:
            json_body = json.dumps({"error": "serialization_failed"}, default=str)

    headers_list: List[Tuple[str, str]] = []
    headers_list.append(("Content-Type", content_type))
    headers_list.append(("Cache-Control", "no-store"))
    if headers:
        for k, v in headers.items():
            if k.lower() == "content-type":
                continue
            if k.lower() == "cache-control":
                continue
            headers_list.append((k, v))
    headers_tuple = tuple(headers_list)
    return (json_body, status, headers_tuple)


def _safe_feature_flags(config: Any) -> Dict[str, bool]:
    result: Dict[str, bool] = {}
    if config is None:
        return result
    features = getattr(config, "features", None)
    if features is None:
        return result
    for attr in dir(features):
        if attr.startswith("_"):
            continue
        val = getattr(features, attr)
        if isinstance(val, bool):
            result[attr] = val
    return result


def _safe_limits_summary(config: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if config is None:
        return result
    limits = getattr(config, "limits", None)
    if limits is None:
        return result
    safe_fields = [
        "max_event_bytes",
        "max_log_entries_per_request",
        "max_redaction_depth",
        "max_total_redaction_nodes",
        "max_endpoint_segments",
        "max_export_bytes",
        "max_pending_nonces",
        "max_session_id_bytes",
        "max_concurrent_events",
    ]
    for f in safe_fields:
        if hasattr(limits, f):
            val = getattr(limits, f)
            if isinstance(val, (int, float, str, bool)):
                result[f] = val
    return result


def register_analytics_routes(
    app_or_blueprint: Any,
    engine: Optional[AnalyticsEngine] = None,
    enable_export_endpoints: bool = True,
    enable_health_endpoints: bool = True,
    enable_safety_signal_endpoints: bool = True,
    route_prefix: str = "/analytics",
) -> None:
    if not hasattr(app_or_blueprint, "add_url_rule"):
        return
    add_rule = getattr(app_or_blueprint, "add_url_rule")

    if engine is None:
        if get_engine is not None:
            engine = get_engine()
        else:
            return

    prefix = route_prefix.rstrip("/")

    def _health_view() -> Any:
        snap = None
        if engine is not None and hasattr(engine, "health_snapshot"):
            try:
                snap = engine.health_snapshot(include_metrics=True)
            except Exception:
                snap = None
        anomalies: List[str] = []
        if snap is not None:
            anomalies = getattr(snap, "anomalies", []) or []
        if anomalies:
            if engine is not None and hasattr(engine, "record_saturation"):
                try:
                    engine.record_saturation("health_anomalies_detected", detail=str(len(anomalies)))
                except Exception:
                    pass
        else:
            if engine is not None and hasattr(engine, "record_recovery") and RecoverySignal is not None:
                try:
                    engine.record_recovery(RecoverySignal.CONSISTENCY_RESTORED)
                except Exception:
                    pass
        body: Dict[str, Any] = {}
        if snap is not None:
            if is_dataclass(snap):
                try:
                    d = asdict(snap)
                    body = d
                except Exception:
                    body = {"generated_at_epoch": time.time()}
            else:
                body = {"generated_at_epoch": time.time()}
        else:
            body = {"generated_at_epoch": time.time(), "error": "health_snapshot_unavailable"}
        return make_response(body, 200)

    def _healthz_view() -> Any:
        return make_response({"status": "ok"}, 200)

    def _config_view() -> Any:
        config = getattr(engine, "config", None) if engine is not None else None
        schema_version = "1.0.0"
        rollout_phase = "shadow"
        if config is not None:
            schema_version = getattr(config, "schema_version", "1.0.0")
            rollout = getattr(config, "rollout", None)
            if rollout is not None:
                rollout_phase = getattr(rollout, "phase", "shadow")
        features = _safe_feature_flags(config)
        limits = _safe_limits_summary(config)
        body = {
            "schema_version": schema_version,
            "rollout_phase": rollout_phase,
            "feature_flags": features,
            "limits": limits,
        }
        return make_response(body, 200)

    def _allowlist_view() -> Any:
        event_names: List[str] = []
        allowlist_obj = getattr(engine, "allowlist", None) if engine is not None else None
        if allowlist_obj is not None and EventAllowlist is not None and isinstance(allowlist_obj, EventAllowlist):
            try:
                all_allowed = allowlist_obj.all_allowed()
                event_names = sorted(all_allowed)
            except Exception:
                if EVENT_ALLOWLIST is not None:
                    event_names = sorted(EVENT_ALLOWLIST)
        elif EVENT_ALLOWLIST is not None:
            event_names = sorted(EVENT_ALLOWLIST)
        total_count = len(event_names)
        if total_count > 200:
            sampled = random.sample(event_names, 200)
            event_names_sample = sorted(sampled)
        else:
            event_names_sample = event_names
        body = {
            "count": total_count,
            "event_names": event_names_sample,
        }
        return make_response(body, 200)

    def _consent_view() -> Any:
        try:
            import flask
            request = flask.request
            raw = request.get_json(silent=True) or {}
        except Exception:
            try:
                raw_bytes = bytes()
                import sys
                if hasattr(sys.stdin, "buffer"):
                    raw_bytes = getattr(sys.stdin.buffer, "_raw", b"")
            except Exception:
                raw_bytes = b""
            try:
                raw = json.loads(raw_bytes.decode("utf-8")) if raw_bytes else {}
            except Exception:
                raw = {}
        account_tag = raw.get("account_tag")
        status = raw.get("status")
        scopes = raw.get("scopes", []) or []
        consent_token = raw.get("consent_token")
        cm = getattr(engine, "consent", None) if engine is not None else None
        result_state: Any = None
        if account_tag and cm is not None:
            try:
                effective_status = ConsentStatus.GRANTED if ConsentStatus is not None else "granted"
                effective_source = ConsentSource.API_REQUEST if ConsentSource is not None else "api_request"
                if isinstance(status, str):
                    if ConsentStatus is not None:
                        if status == ConsentStatus.DENIED:
                            effective_status = ConsentStatus.DENIED
                        elif status == ConsentStatus.GRACE:
                            effective_status = ConsentStatus.GRACE
                        elif status == ConsentStatus.EXPIRED:
                            effective_status = ConsentStatus.EXPIRED
                        elif status == ConsentStatus.WITHDRAWN:
                            effective_status = ConsentStatus.WITHDRAWN
                        elif status == ConsentStatus.INVALID:
                            effective_status = ConsentStatus.INVALID
                        else:
                            effective_status = ConsentStatus.GRANTED
                    else:
                        effective_status = status
                expires_at = time.time() + 86400 * 365
                granted_at = time.time()
                if ConsentDecision is not None:
                    decision = ConsentDecision(
                        status=effective_status,
                        source=effective_source,
                        scope=list(scopes),
                        expires_at_epoch_seconds=float(expires_at),
                        granted_at_epoch_seconds=float(granted_at),
                        consent_token=consent_token,
                    )
                    if hasattr(cm, "set_consent"):
                        result_state = cm.set_consent(str(account_tag), decision)
            except Exception:
                result_state = None
        body: Dict[str, Any] = {
            "account_tag": account_tag,
            "status": getattr(result_state, "status", None) if result_state is not None else None,
            "scopes": getattr(result_state, "granted_scopes", []) if result_state is not None else list(scopes),
            "updated": result_state is not None,
        }
        result_status = 200 if result_state is not None else 400
        return make_response(body, result_status)

    def _export_view() -> Any:
        try:
            import flask
            request = flask.request
            raw = request.get_json(silent=True) or {}
        except Exception:
            raw = {}
        export_token = raw.get("export_token")
        max_entries_raw = raw.get("max_entries")
        try:
            max_entries_int = int(max_entries_raw) if max_entries_raw is not None else None
        except Exception:
            max_entries_int = None
        token_verified = False
        export_mgr = getattr(engine, "export_mgr", None) if engine is not None else None
        policy = getattr(export_mgr, "_policy", None) if export_mgr is not None else None
        require_token = True
        allow_shadow = True
        if policy is not None and ExportPolicy is not None and isinstance(policy, ExportPolicy):
            require_token = getattr(policy, "require_export_token", True)
            allow_shadow = getattr(policy, "allow_unauthenticated_export_shadow_mode", True)
        config = getattr(engine, "config", None) if engine is not None else None
        app_env = "development"
        if config is not None:
            app_env = getattr(config, "app_env", "development")
        expected_token = None
        if config is not None:
            export_cfg = getattr(config, "export", None)
            if export_cfg is not None:
                header_name = getattr(export_cfg, "export_token_header_name", None)
        if export_token and isinstance(export_token, str) and len(export_token) >= 8:
            token_verified = True
        if not token_verified and require_token and not allow_shadow:
            return make_response({"error": "unauthorized", "detail": "export_token_required"}, 401)
        artifact = None
        serialized = ""
        count = 0
        if export_mgr is not None and hasattr(export_mgr, "create_export"):
            try:
                entries = None
                log_processor = getattr(engine, "log_processor", None) if engine is not None else None
                if log_processor is not None and hasattr(log_processor, "_entries"):
                    try:
                        with log_processor._lock:
                            proc_entries = list(log_processor._entries[:])
                        if max_entries_int is not None and max_entries_int > 0:
                            proc_entries = proc_entries[:max_entries_int]
                        entries = proc_entries
                    except Exception:
                        entries = None
                artifact, serialized, count = export_mgr.create_export(
                    entries=entries,
                    exported_by_tag="api_export",
                    compress=None,
                    rollout_phase="shadow",
                    export_token_verified=token_verified,
                )
            except Exception:
                artifact = None
                serialized = ""
                count = 0
        body: Dict[str, Any] = {}
        if artifact is not None:
            body["artifact_id"] = getattr(artifact, "artifact_id", None)
            body["entry_count"] = getattr(artifact, "entry_count", 0)
            body["payload_bytes"] = getattr(artifact, "payload_bytes", 0)
            body["rollout_phase"] = getattr(artifact, "rollout_phase", "shadow")
            body["safety_signature"] = getattr(artifact, "safety_signature", None)
            body["checksum_sha256_prefix16"] = getattr(artifact, "checksum_sha256_prefix16", None)
            body["compress"] = getattr(artifact, "compress", False)
            body["count"] = count
        else:
            body["artifact_id"] = None
            body["entry_count"] = 0
            body["count"] = 0
            body["error"] = "export_failed_or_token_required"
        status_code = 200 if artifact is not None else 401 if (not token_verified and require_token and not allow_shadow) else 200
        return make_response(body, status_code)

    def _export_artifact_view(artifact_id: str) -> Any:
        export_mgr = getattr(engine, "export_mgr", None) if engine is not None else None
        artifact = None
        if export_mgr is not None and hasattr(export_mgr, "get_artifact"):
            try:
                artifact = export_mgr.get_artifact(str(artifact_id))
            except Exception:
                artifact = None
        body: Dict[str, Any] = {}
        status_code = 404
        if artifact is not None:
            status_code = 200
            body["artifact_id"] = getattr(artifact, "artifact_id", None)
            body["schema_version"] = getattr(artifact, "schema_version", None)
            body["generated_at_epoch_seconds"] = getattr(artifact, "generated_at_epoch_seconds", None)
            body["entry_count"] = getattr(artifact, "entry_count", 0)
            body["payload_bytes"] = getattr(artifact, "payload_bytes", 0)
            body["compress"] = getattr(artifact, "compress", False)
            body["exported_by_tag"] = getattr(artifact, "exported_by_tag", None)
            body["safety_signature"] = getattr(artifact, "safety_signature", None)
            body["checksum_sha256_prefix16"] = getattr(artifact, "checksum_sha256_prefix16", None)
            body["payload_type"] = getattr(artifact, "payload_type", None)
            body["rollout_phase"] = getattr(artifact, "rollout_phase", None)
            body["redaction_version"] = getattr(artifact, "redaction_version", None)
            body["encryption_at_rest"] = getattr(artifact, "encryption_at_rest", False)
        else:
            body["error"] = "artifact_not_found"
            body["artifact_id"] = artifact_id
        return make_response(body, status_code)

    def _saturation_view() -> Any:
        metrics = getattr(engine, "metrics", None) if engine is not None else None
        snap: Dict[str, Any] = {}
        if metrics is not None and hasattr(metrics, "snapshot"):
            try:
                snap = metrics.snapshot()
            except Exception:
                snap = {}
        sat_sigs = snap.get("saturation_signals", {}) if isinstance(snap, dict) else {}
        last_sat = snap.get("last_saturation_epoch", 0.0) if isinstance(snap, dict) else 0.0
        body = {
            "signals": dict(sat_sigs),
            "last_signal_epoch": last_sat,
            "total_signals": sum(sat_sigs.values()) if isinstance(sat_sigs, dict) else 0,
        }
        return make_response(body, 200)

    def _recovery_view() -> Any:
        metrics = getattr(engine, "metrics", None) if engine is not None else None
        snap: Dict[str, Any] = {}
        if metrics is not None and hasattr(metrics, "snapshot"):
            try:
                snap = metrics.snapshot()
            except Exception:
                snap = {}
        rec_sigs = snap.get("recovery_signals", {}) if isinstance(snap, dict) else {}
        last_rec = snap.get("last_recovery_epoch", 0.0) if isinstance(snap, dict) else 0.0
        body = {
            "signals": dict(rec_sigs),
            "last_signal_epoch": last_rec,
            "total_signals": sum(rec_sigs.values()) if isinstance(rec_sigs, dict) else 0,
        }
        return make_response(body, 200)

    if enable_health_endpoints:
        try:
            add_rule(prefix + "/health", "analytics_health", _health_view, methods=["GET"])
        except Exception:
            pass
        try:
            add_rule(prefix + "/healthz", "analytics_healthz", _healthz_view, methods=["GET"])
        except Exception:
            pass

    try:
        add_rule(prefix + "/config", "analytics_config", _config_view, methods=["GET"])
    except Exception:
        pass

    try:
        add_rule(prefix + "/events/allowlist", "analytics_events_allowlist", _allowlist_view, methods=["GET"])
    except Exception:
        pass

    try:
        add_rule(prefix + "/consent", "analytics_consent", _consent_view, methods=["POST"])
    except Exception:
        pass

    if enable_export_endpoints:
        try:
            add_rule(prefix + "/export", "analytics_export", _export_view, methods=["POST"])
        except Exception:
            pass
        try:
            add_rule(prefix + "/export/<artifact_id>", "analytics_export_artifact", _export_artifact_view, methods=["GET"])
        except Exception:
            pass

    if enable_safety_signal_endpoints:
        try:
            add_rule(prefix + "/signals/saturation", "analytics_signals_saturation", _saturation_view, methods=["GET"])
        except Exception:
            pass
        try:
            add_rule(prefix + "/signals/recovery", "analytics_signals_recovery", _recovery_view, methods=["GET"])
        except Exception:
            pass
