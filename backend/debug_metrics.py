from __future__ import annotations

import json
import os
import sys


def _main() -> int:
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(backend_dir)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    try:
        from analytics.config import load_analytics_config
        from analytics.analytics_engine import (
            AnalyticsEngine,
            EngineHealthSnapshot,
            RequestContext,
            get_engine,
            set_engine,
        )
        from analytics.export_manager import (
            EXPORT_POLICY_DEFAULT,
            ExportArtifact,
            ExportManager,
            ExportPolicy,
        )
        from analytics.middleware import AnalyticsMiddleware
        from analytics.redaction import RedactionEngine
        from analytics.events import EventLifecycleState
    except Exception as e:
        print("IMPORT_ERROR:", type(e).__name__, str(e))
        return 2

    try:
        cfg = load_analytics_config()
    except Exception as e:
        print("CONFIG_LOAD_ERROR:", type(e).__name__, str(e))
        cfg = None

    engine = AnalyticsEngine(config=cfg)
    try:
        set_engine(engine)
    except Exception:
        pass

    print("DEBUG: AnalyticsEngine created. rollout_phase =",
          getattr(getattr(engine, "config", None), "rollout", None) and
          getattr(engine.config.rollout, "phase", "unknown") or "unknown")

    event_names = [
        "system.startup",
        "system.config_loaded",
        "user.session_started",
        "user.authentication_succeeded",
        "proof.workflow_started",
        "proof.workflow_queued",
        "proof.circuit_compilation_requested",
        "proof.circuit_compilation_completed",
        "proof.generate_requested",
        "proof.generate_completed",
        "proof.verify_requested",
        "proof.verify_completed",
        "proof.workflow_completed",
        "media.upload_started",
        "media.upload_completed",
        "media.metadata_extracted",
        "network.rpc_requested",
        "network.rpc_completed",
        "ops.progress_tick",
        "export.export_completed",
    ]

    sensitive_payload_samples = [
        {"proof_data": "0x12345abcdef", "witness": ["w1", "w2"], "secret": "supersecret123"},
        {"signature": "0xdeadbeef", "account": "user123"},
        {"proof_data": "xyz", "inner": {"witness": "sensitive-witness", "extra": "data"}},
    ]

    processed_events = []
    failures = 0

    for i, ename in enumerate(event_names):
        ctx = RequestContext(
            request_id_tag="req-" + str(i),
            account_id_tag="acct-" + str(i % 5),
            session_id_tag="sess-" + str(i % 3),
            endpoint_pattern="/api/" + ename.replace(".", "/"),
            method="POST" if i % 2 == 0 else "GET",
            replay_nonce=None,
        )
        if i == 0:
            ctx.replay_nonce = "n-v1:firstnonce0000"
        payload_idx = i % len(sensitive_payload_samples)
        payload = dict(sensitive_payload_samples[payload_idx])
        payload["iteration"] = i
        payload["label"] = "test-event-" + str(i)
        try:
            ev = engine.process_event(ename, "proof.operation" if "proof" in ename else "network.operation", payload, ctx)
            processed_events.append(ev)
            state = getattr(ev, "lifecycle_state", None)
            if state == EventLifecycleState.DROPPED:
                pass
            elif state not in {EventLifecycleState.INGESTED, EventLifecycleState.REDACTED, EventLifecycleState.SAMPLED_IN, EventLifecycleState.CONSENT_PENDING, EventLifecycleState.CONSENT_GRANTED, EventLifecycleState.ALLOWLISTED}:
                print(f"WARN: event {i} ({ename}) ended in state: {state} rejection={getattr(ev, 'rejection_reason', None)}")
        except Exception as e:
            failures += 1
            print(f"FAIL event {i} ({ename}): {type(e).__name__}: {e}")

    print(f"DEBUG: Processed {len(processed_events)} events. failures={failures}")

    if failures > 0:
        print("FAIL: event processing failures detected")
        return 3

    dropped_states = 0
    ingested_states = 0
    for ev in processed_events:
        st = getattr(ev, "lifecycle_state", "")
        if st == EventLifecycleState.DROPPED:
            dropped_states += 1
        if st == EventLifecycleState.INGESTED:
            ingested_states += 1

    print(f"DEBUG: lifecycle states: ingested={ingested_states}, dropped={dropped_states}, total={len(processed_events)}")

    if ingested_states == 0 and dropped_states == len(processed_events):
        print("FAIL: All events dropped, expected some ingested transitions")
        return 4

    re = None
    try:
        re = RedactionEngine()
    except Exception as e:
        print("FAIL: RedactionEngine creation failed:", type(e).__name__, str(e))
        return 5

    ep1 = "/api/proof/0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/upload"
    ep2 = "/api/video/upload/user123"
    try:
        sanitized1 = re.sanitize_endpoint_pattern(ep1)
    except Exception as e:
        print("FAIL: endpoint sanitization 1:", type(e).__name__, str(e))
        return 6
    try:
        sanitized2 = re.sanitize_endpoint_pattern(ep2)
    except Exception as e:
        print("FAIL: endpoint sanitization 2:", type(e).__name__, str(e))
        return 6

    print(f"DEBUG: endpoint1 sanitized: {ep1!r} -> {sanitized1!r}")
    print(f"DEBUG: endpoint2 sanitized: {ep2!r} -> {sanitized2!r}")

    if "0x123456789" in sanitized1:
        print("FAIL: endpoint1 still contains raw hex id")
        return 7
    if "upload" not in sanitized1:
        print("WARN: endpoint1 lost 'upload' segment")
    if "/api/video/upload" not in sanitized2:
        print("WARN: endpoint2 expected /api/video/upload prefix, got", sanitized2)

    try:
        snap = engine.health_snapshot(include_metrics=True)
    except Exception as e:
        print("FAIL: health_snapshot error:", type(e).__name__, str(e))
        return 8

    print("DEBUG: health_snapshot ->")
    print("  generated_at_epoch:", snap.generated_at_epoch)
    print("  config_schema_version:", snap.config_schema_version)
    print("  rollout_phase:", snap.rollout_phase)
    print("  features count:", len(snap.features))
    print("  consent_states_tracked:", snap.consent_states_tracked)
    print("  nonces_tracked:", snap.nonces_tracked)
    print("  sessions_tracked:", snap.sessions_tracked)
    print("  log_entries_tracked:", snap.log_entries_tracked)
    print("  artifacts_tracked:", snap.artifacts_tracked)
    print("  anomalies:", snap.anomalies)

    if snap.log_entries_tracked <= 0:
        print("WARN: no log_entries tracked; expected some after 20 events")

    forbidden_words = ["secret", "witness", "signature", "proof_data"]
    leak_count = 0
    scanned_count = 0

    for ev in processed_events:
        payload = getattr(ev, "payload", None)
        if payload is None:
            continue
        try:
            serialized = json.dumps(payload, sort_keys=True, default=str)
        except Exception:
            serialized = str(payload)
        scanned_count += 1
        lowered = serialized.lower()
        for w in forbidden_words:
            idx = 0
            while True:
                pos = lowered.find(w, idx)
                if pos < 0:
                    break
                window_start = max(0, pos - 20)
                window_end = min(len(serialized), pos + len(w) + 20)
                window = serialized[window_start:window_end]
                if "[REDACTED:" in window or "[redacted:" in window.lower():
                    idx = pos + 1
                    continue
                print(f"LEAK: raw forbidden word {w!r} in event {getattr(ev, 'event_name', '?')} window: {window!r}")
                leak_count += 1
                idx = pos + 1
                break

    print(f"DEBUG: scanned {scanned_count} event payloads, raw-string leaks of forbidden words: {leak_count}")

    if leak_count > 0:
        print("FAIL: forbidden raw strings found in sanitized payloads")
        return 9

    try:
        em = ExportManager(processor=getattr(engine, "log_processor", None))
        art, ser, cnt = em.create_export(
            exported_by_tag="debug-metrics",
            rollout_phase="shadow",
            export_token_verified=True,
        )
    except Exception as e:
        print("FAIL: export_manager.create_export error:", type(e).__name__, str(e))
        return 10

    print(f"DEBUG: export create_export -> artifact_id={getattr(art, 'artifact_id', None)}, count={cnt}, bytes={getattr(art, 'payload_bytes', 0)}")

    if art is None:
        print("FAIL: export artifact was None despite token_verified=True")
        return 11

    art_from_get = em.get_artifact(art.artifact_id)
    if art_from_get is None or art_from_get.artifact_id != art.artifact_id:
        print("FAIL: get_artifact failed to return stored artifact")
        return 12

    listed = em.list_artifacts(limit=10)
    if len(listed) < 1:
        print("FAIL: list_artifacts empty after creating artifact")
        return 13

    mw = AnalyticsMiddleware(app=None)
    try:
        ctx = mw.build_context_from_environ({
            "PATH_INFO": "/api/proof/0x123456789abcdef/verify",
            "REQUEST_METHOD": "POST",
            "HTTP_X_REQUEST_ID": "req1",
            "HTTP_X_USER_TAG": "usr123",
        })
    except Exception as e:
        print("FAIL: middleware.build_context_from_environ error:", type(e).__name__, str(e))
        return 14

    print(f"DEBUG: middleware context: endpoint_pattern={getattr(ctx, 'endpoint_pattern', None)!r}, method={getattr(ctx, 'method', None)!r}")

    if "0x123456789" in getattr(ctx, "endpoint_pattern", ""):
        print("WARN: middleware endpoint pattern still contains raw hex")

    print("SUCCESS: all debug_metrics checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
