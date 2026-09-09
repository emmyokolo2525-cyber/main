from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import json
import re
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from analytics.redaction import RedactionEngine
except Exception:
    RedactionEngine = None


EXPORT_LOG_VERSION = "1.0.0"


VALID_SEVERITIES = {"debug", "info", "warning", "error", "critical", "fatal"}


SAFE_LABEL_KEYS = {
    "endpoint", "method", "status", "error_code", "category", "operation",
    "retry_attempt", "source", "version", "schema", "rollout", "host",
    "service", "error_type",
}


LABEL_KEY_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,31}$")
COUNTER_KEY_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,31}$")


DURABLE_LEAK_WORDS = [
    "video", "media", "upload", "witness", "proof", "secret", "credential",
    "privatekey", "private_key", "privkey", "mnemonic", "seedphrase",
    "signature", "wallet_signature", "xdr", "signedtx", "signed_tx",
    "authsignature", "auth_signature", "ed25519signature", "ed25519_signature",
    "stellaresignature", "stellar_signature", "txsignature", "tx_signature",
    "transactionenvelope", "transaction_envelope", "nullifier", "nullifiers",
    "commitment", "commitments", "verificationkey", "verification_key",
    "provingkey", "proving_key", "password", "passwd", "pwd", "token",
    "apikey", "apisecret", "name", "email", "phone", "dob", "birth",
    "passport", "governmentid", "ssn", "idnumber", "biometric", "ip",
]


SENSITIVE_FIELD_HINTS = {
    "video", "media", "upload", "uploaded_file", "uploadedfile",
    "file_content", "filecontent", "blob", "payload_content",
    "base64_content", "base64content", "binary", "raw_bytes",
    "rawbytes", "image", "audio", "recording", "screenshot",
    "frame", "frames", "clip",
    "witness", "witnessness", "witnessdata", "witness_data",
    "witness_input", "witnessinput", "witnessvars", "witness_vars",
    "assignment", "assignments", "witness_assignment",
    "proof", "proofdata", "proof_data", "proofpayload", "proof_payload",
    "prooffile", "proof_file", "pi", "witnessed_proof", "zkproof",
    "zk_proof", "circuitproof", "circuit_proof", "verificationkey",
    "verification_key", "vk", "provingkey", "proving_key", "pk",
    "public_inputs", "publicinputs", "private_inputs", "privateinputs",
    "commitments", "commitment", "nullifier", "nullifiers",
    "signature", "sig", "wallet_signature", "walletsig",
    "stellaresignature", "stellar_signature", "txsignature",
    "tx_signature", "xdr", "signedtx", "signed_tx",
    "transactionenvelope", "transaction_envelope", "authsignature",
    "auth_signature", "ed25519signature", "ed25519_signature",
    "secret", "credential", "password", "passwd", "pwd", "token",
    "apikey", "apisecret", "privatekey", "private_key", "privkey",
    "mnemonic", "seedphrase", "seed_phrase", "recoveryphrase",
    "recovery_phrase", "access_key", "accesskey",
}


def _cap_bytes(value: str, cap: int) -> str:
    if not isinstance(value, str):
        value = str(value)
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= cap:
        return value
    truncated_bytes = encoded[:cap]
    try:
        truncated_str = truncated_bytes.decode("utf-8", "ignore")
    except Exception:
        truncated_str = truncated_bytes.decode("latin-1", "replace")
    return truncated_str


def _generate_entry_id() -> str:
    raw = str(uuid.uuid4()) + str(time.time_ns())
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"eid-v1:{digest}"


def _classify_severity(error: Any) -> str:
    if isinstance(error, BaseException):
        name = type(error).__name__
        lowered = name.lower()
        if "fatal" in lowered:
            return "fatal"
        if "critical" in lowered:
            return "critical"
        if any(k in lowered for k in ("error", "exception", "fail", "invalid")):
            return "error"
        if any(k in lowered for k in ("warn", "timeout", "unauthorized", "forbidden", "notfound")):
            return "warning"
        return "error"
    return "info"


def _windows_path_repl(match: re.Match) -> str:
    path = match.group(0)
    name = path.rsplit("\\", 1)[-1] if "\\" in path else path
    if "." not in name and "/" not in name and "\\" not in name:
        name = name + ".py" if not name.endswith(".py") else name
    return f"<file:{name}>"


def _posix_path_repl(match: re.Match) -> str:
    path = match.group(0)
    name = path.rsplit("/", 1)[-1] if "/" in path else path
    return f"<file:{name}>"


@dataclass
class LogEntry:
    entry_id: str
    schema_version: str = EXPORT_LOG_VERSION
    event_name: str = ""
    category: str = "unknown"
    severity: str = "info"
    timestamp_epoch_seconds: float = 0.0
    message_summary: str = ""
    endpoint_pattern: str = ""
    method: str = ""
    status_code: Optional[int] = None
    error_type: Optional[str] = None
    error_code: Optional[str] = None
    error_safe: bool = True
    correlation_id_tag: Optional[str] = None
    account_id_tag: Optional[str] = None
    session_id_tag: Optional[str] = None
    duration_seconds: Optional[float] = None
    operation_status: Optional[str] = None
    lifecycle_state: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)
    sanitized: bool = False
    export_safe: bool = False
    export_signature: Optional[str] = None
    source: str = "backend"
    annotations: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            self.severity = "info"
        self.message_summary = _cap_bytes(self.message_summary, 512)


@dataclass
class ErrorTelemetryConfig:
    max_stack_trace_lines_captured: int = 16
    max_stack_trace_line_bytes: int = 256
    max_message_summary_bytes: int = 512
    max_labels_count: int = 32
    max_counters_count: int = 32
    max_total_entries_per_request: int = 256
    allow_original_error_type_names: bool = True
    require_export_safety_validation: bool = True
    sensitive_error_type_names_to_mask: Dict[str, str] = field(default_factory=lambda: {
        "AuthenticationError": "auth_failure",
        "AuthorizationError": "forbidden",
        "CryptoError": "crypto_failure_safe",
        "WalletSignatureError": "wallet_sig_failure_safe",
        "ProofVerificationError": "proof_failure_safe",
        "WitnessDecodeError": "witness_failure_safe",
        "MediaDecodeError": "media_failure_safe",
        "PrivateKeyError": "key_failure_safe",
    })
    crash_on_export_safety_violation: bool = False


class LogProcessor:
    def __init__(
        self,
        config: Optional[ErrorTelemetryConfig] = None,
        redaction_engine: Optional[Any] = None,
    ) -> None:
        self._entries: List[LogEntry] = []
        self._lock: threading.RLock = threading.RLock()
        self._config: ErrorTelemetryConfig = config if config is not None else ErrorTelemetryConfig()
        self._total_entries_processed: int = 0
        self._export_safety_violations: int = 0
        self._oversized_dropped: int = 0
        if redaction_engine is not None:
            self._redaction_engine: Any = redaction_engine
        elif RedactionEngine is not None:
            self._redaction_engine = RedactionEngine()
        else:
            self._redaction_engine = None

    def _sanitize_stack_trace_line(self, line: str) -> str:
        try:
            result = _cap_bytes(line, self._config.max_stack_trace_line_bytes)
        except Exception:
            result = str(line)[:self._config.max_stack_trace_line_bytes]

        try:
            win_pat = re.compile(r"[A-Za-z]:\\[\\S]+")
            result = win_pat.sub(_windows_path_repl, result)
        except re.error:
            pass
        except Exception:
            pass

        try:
            posix_pat = re.compile(r"/[^\s\"':]+")
            result = posix_pat.sub(_posix_path_repl, result)
        except re.error:
            pass
        except Exception:
            pass

        try:
            hex_pat = re.compile(r"0x[0-9a-fA-F]{12,}")
            result = hex_pat.sub("[hex:redacted]", result)
        except re.error:
            pass
        except Exception:
            pass

        try:
            bs_escape_pat = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
            result = bs_escape_pat.sub(".", result)
        except re.error:
            pass
        except Exception:
            pass

        result = _cap_bytes(result, self._config.max_stack_trace_line_bytes)
        return result

    def _filter_labels(self, labels: Dict[str, Any]) -> Dict[str, str]:
        result: Dict[str, str] = {}
        count = 0
        for k, v in labels.items():
            if count >= self._config.max_labels_count:
                break
            if not isinstance(k, str):
                continue
            key_ok = (k in SAFE_LABEL_KEYS) or bool(LABEL_KEY_PATTERN.match(k))
            if not key_ok:
                continue
            if not isinstance(v, str):
                try:
                    v = str(v)
                except Exception:
                    continue
            v_capped = _cap_bytes(v, 256)
            result[k] = v_capped
            count += 1
        return result

    def _filter_counters(self, counters: Dict[str, Any]) -> Dict[str, int]:
        result: Dict[str, int] = {}
        count = 0
        for k, v in counters.items():
            if count >= self._config.max_counters_count:
                break
            if not isinstance(k, str):
                continue
            key_ok = (k in SAFE_LABEL_KEYS) or bool(COUNTER_KEY_PATTERN.match(k))
            if not key_ok:
                continue
            if isinstance(v, bool):
                continue
            if not isinstance(v, int):
                try:
                    v = int(v)
                except Exception:
                    continue
            result[k] = v
            count += 1
        return result

    def sanitize_error_context(
        self,
        error: Any,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        operation_status: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        correlation_tag: Optional[str] = None,
        account_tag: Optional[str] = None,
        session_tag: Optional[str] = None,
        extra_labels: Optional[Dict[str, str]] = None,
        extra_counters: Optional[Dict[str, int]] = None,
    ) -> LogEntry:
        severity = _classify_severity(error)
        error_type_name: Optional[str] = None
        raw_message: str = ""

        if isinstance(error, BaseException):
            type_name = type(error).__name__
            if self._config.allow_original_error_type_names:
                if type_name in self._config.sensitive_error_type_names_to_mask:
                    error_type_name = self._config.sensitive_error_type_names_to_mask[type_name]
                else:
                    error_type_name = type_name
            else:
                if type_name in self._config.sensitive_error_type_names_to_mask:
                    error_type_name = self._config.sensitive_error_type_names_to_mask[type_name]
                else:
                    error_type_name = "error"

            if error.args:
                try:
                    raw_message = str(error.args[0])
                except Exception:
                    raw_message = ""
            if not raw_message:
                try:
                    raw_message = str(error)
                except Exception:
                    raw_message = ""

            tb_lines: List[str] = []
            try:
                formatted = traceback.format_exception(type(error), error, error.__traceback__)
                tb_lines = formatted[:self._config.max_stack_trace_lines_captured]
            except Exception:
                tb_lines = []
            sanitized_tb_lines = [self._sanitize_stack_trace_line(l) for l in tb_lines]
            tb_str = "\n".join(sanitized_tb_lines)
            if tb_str:
                if raw_message:
                    raw_message = raw_message + "\n" + tb_str
                else:
                    raw_message = tb_str

        elif isinstance(error, str):
            raw_message = error
        elif isinstance(error, dict):
            try:
                raw_message = json.dumps(error, sort_keys=True, default=str)
            except Exception:
                raw_message = str(error)
        else:
            try:
                raw_message = str(error)
            except Exception:
                raw_message = ""

        if self._redaction_engine is not None:
            try:
                outcome = self._redaction_engine.sanitize(raw_message)
                sanitized_msg = str(outcome.data) if outcome is not None else raw_message
            except Exception:
                sanitized_msg = raw_message
        else:
            sanitized_msg = raw_message

        capped_msg = _cap_bytes(sanitized_msg, self._config.max_message_summary_bytes)

        endpoint_sanitized: str = ""
        if endpoint is not None:
            if self._redaction_engine is not None and hasattr(self._redaction_engine, "sanitize_endpoint_pattern"):
                try:
                    endpoint_sanitized = self._redaction_engine.sanitize_endpoint_pattern(endpoint or "")
                except Exception:
                    endpoint_sanitized = _cap_bytes(endpoint or "", 256)
            else:
                endpoint_sanitized = _cap_bytes(endpoint or "", 256)

        labels_in: Dict[str, Any] = {}
        if endpoint_sanitized:
            labels_in["endpoint"] = endpoint_sanitized
        if method:
            labels_in["method"] = method.upper() if isinstance(method, str) else str(method)
        if status_code is not None:
            labels_in["status"] = str(status_code)
        if error_type_name:
            labels_in["error_type"] = error_type_name
        if operation_status:
            labels_in["operation"] = operation_status
        if extra_labels:
            for ek, ev in extra_labels.items():
                if ek not in labels_in:
                    labels_in[ek] = ev

        filtered_labels = self._filter_labels(labels_in)
        filtered_counters = self._filter_counters(extra_counters or {})

        error_code_val: Optional[str] = None
        if isinstance(error, BaseException):
            try:
                ec = getattr(error, "error_code", None)
                if ec is not None:
                    error_code_val = _cap_bytes(str(ec), 128)
            except Exception:
                pass

        if category_val := filtered_labels.get("category"):
            category = category_val
        elif isinstance(error, BaseException):
            tn = type(error).__name__
            if tn in self._config.sensitive_error_type_names_to_mask:
                category = "safe_error"
            elif "auth" in tn.lower():
                category = "auth"
            elif any(k in tn.lower() for k in ("proof", "witness", "verify")):
                category = "verification"
            elif any(k in tn.lower() for k in ("crypto", "key", "wallet", "sign")):
                category = "crypto"
            elif any(k in tn.lower() for k in ("media", "video", "upload", "file")):
                category = "media"
            else:
                category = "general"
        else:
            category = "unknown"

        entry = LogEntry(
            entry_id=_generate_entry_id(),
            schema_version=EXPORT_LOG_VERSION,
            event_name=filtered_labels.get("operation", "error_event"),
            category=category,
            severity=severity,
            timestamp_epoch_seconds=time.time(),
            message_summary=capped_msg,
            endpoint_pattern=endpoint_sanitized,
            method=(method.upper() if isinstance(method, str) else str(method or "")),
            status_code=status_code,
            error_type=error_type_name,
            error_code=error_code_val,
            error_safe=(error_type_name not in self._config.sensitive_error_type_names_to_mask.values()),
            correlation_id_tag=correlation_tag,
            account_id_tag=account_tag,
            session_id_tag=session_tag,
            duration_seconds=duration_seconds,
            operation_status=operation_status,
            lifecycle_state=None,
            labels=filtered_labels,
            counters=filtered_counters,
            sanitized=True,
            export_safe=False,
            export_signature=None,
            source="backend",
            annotations={},
        )

        if self._config.require_export_safety_validation:
            self.validate_log_export_safety(entry)

        return entry

    def ingest(self, entry: LogEntry, allow_duplicate: bool = False) -> Tuple[bool, Optional[str]]:
        with self._lock:
            ok, reasons = validate_log_export_safety(entry)
            if not ok:
                self._export_safety_violations += 1
                if self._config.crash_on_export_safety_violation:
                    pass
                return (False, "export_safety_violation:" + ";".join(reasons[:3]))

            if len(self._entries) >= self._config.max_total_entries_per_request and not allow_duplicate:
                self._oversized_dropped += 1
                return (False, "max_entries_exceeded")

            if not allow_duplicate:
                for existing in self._entries[-32:]:
                    if (
                        existing.event_name == entry.event_name
                        and existing.endpoint_pattern == entry.endpoint_pattern
                        and existing.method == entry.method
                        and existing.status_code == entry.status_code
                    ):
                        return (False, "duplicate_entry")

            self._entries.append(entry)
            self._total_entries_processed += 1
            return (True, None)

    def export_json_logs(
        self,
        entries: Optional[List[LogEntry]] = None,
        compress: bool = False,
        max_entries: int = 64,
        max_bytes: int = 4_194_304,
    ) -> Tuple[str, int]:
        with self._lock:
            snapshot = list(self._entries) if entries is None else list(entries)

        working = snapshot[:max_entries]
        working.sort(key=lambda e: e.timestamp_epoch_seconds)

        final_entries: List[LogEntry] = []
        for e in working:
            ok, _reasons = validate_log_export_safety(e)
            if not ok:
                e.export_safe = False
                e.export_signature = None
            final_entries.append(e)

        while True:
            dicts = [dataclasses.asdict(e) for e in final_entries]
            try:
                serialized = json.dumps(dicts, sort_keys=True, separators=(",", ":"))
            except Exception:
                serialized = "[]"

            if compress:
                try:
                    compressed = gzip.compress(serialized.encode("utf-8"), compresslevel=6)
                    encoded = base64.b64encode(compressed).decode("ascii")
                except Exception:
                    encoded = serialized
                output = encoded
            else:
                output = serialized

            if len(output.encode("utf-8")) <= max_bytes or len(final_entries) <= 1:
                return (output, len(final_entries))

            final_entries = final_entries[:-1]

    def import_json_logs(
        self,
        serialized: str,
        compressed: bool = False,
        max_entries: int = 64,
    ) -> List[LogEntry]:
        data_str: str
        if compressed:
            try:
                decoded = base64.b64decode(serialized.encode("ascii"))
                decompressed = gzip.decompress(decoded)
                data_str = decompressed.decode("utf-8")
            except Exception:
                data_str = serialized
        else:
            data_str = serialized

        try:
            parsed = json.loads(data_str)
        except Exception:
            return []

        if not isinstance(parsed, list):
            return []

        results: List[LogEntry] = []
        for item in parsed[:max_entries]:
            if not isinstance(item, dict):
                continue
            try:
                capped_msg = _cap_bytes(item.get("message_summary", ""), 512)
                ep = _cap_bytes(item.get("endpoint_pattern", ""), 256)
                ev = item.get("event_name", "")
                ev = _cap_bytes(ev, 128)
                cat = _cap_bytes(item.get("category", "unknown"), 64)
                sev = item.get("severity", "info")
                if sev not in VALID_SEVERITIES:
                    sev = "info"
                entry_id = item.get("entry_id") or _generate_entry_id()
                labels_raw = item.get("labels", {}) or {}
                if not isinstance(labels_raw, dict):
                    labels_raw = {}
                counters_raw = item.get("counters", {}) or {}
                if not isinstance(counters_raw, dict):
                    counters_raw = {}
                filtered_labels = self._filter_labels(labels_raw)
                filtered_counters = self._filter_counters(counters_raw)
                annotations_raw = item.get("annotations", {}) or {}
                filtered_annotations = self._filter_labels(annotations_raw)
                entry = LogEntry(
                    entry_id=entry_id,
                    schema_version=item.get("schema_version", EXPORT_LOG_VERSION),
                    event_name=ev,
                    category=cat,
                    severity=sev,
                    timestamp_epoch_seconds=float(item.get("timestamp_epoch_seconds", 0.0) or 0.0),
                    message_summary=capped_msg,
                    endpoint_pattern=ep,
                    method=_cap_bytes(item.get("method", ""), 16),
                    status_code=item.get("status_code"),
                    error_type=item.get("error_type"),
                    error_code=item.get("error_code"),
                    error_safe=bool(item.get("error_safe", True)),
                    correlation_id_tag=item.get("correlation_id_tag"),
                    account_id_tag=item.get("account_id_tag"),
                    session_id_tag=item.get("session_id_tag"),
                    duration_seconds=item.get("duration_seconds"),
                    operation_status=item.get("operation_status"),
                    lifecycle_state=item.get("lifecycle_state"),
                    labels=filtered_labels,
                    counters=filtered_counters,
                    sanitized=bool(item.get("sanitized", False)),
                    export_safe=bool(item.get("export_safe", False)),
                    export_signature=item.get("export_signature"),
                    source=_cap_bytes(item.get("source", "backend"), 64),
                    annotations=filtered_annotations,
                )
                validate_log_export_safety(entry)
                results.append(entry)
            except Exception:
                continue
        return results

    def validate_log_export_safety(self, entry: LogEntry) -> Tuple[bool, List[str]]:
        passed, reasons = validate_log_export_safety(entry)
        if passed:
            sorted_label_keys = ",".join(sorted(entry.labels.keys()))
            sorted_counter_keys = ",".join(sorted(entry.counters.keys()))
            sig_input = "|".join([
                entry.entry_id,
                entry.event_name,
                entry.message_summary,
                sorted_label_keys,
                sorted_counter_keys,
            ])
            sig = hashlib.sha256(sig_input.encode("utf-8")).hexdigest()[:12]
            entry.export_signature = "sig-v1:" + sig
            entry.export_safe = True
        return (passed, reasons)


def _get_default_engine() -> Any:
    if RedactionEngine is not None:
        return RedactionEngine()
    return None


def _label_key_is_valid(k: str) -> bool:
    if k in SAFE_LABEL_KEYS:
        return True
    return bool(LABEL_KEY_PATTERN.match(k))


def validate_log_export_safety(entry: LogEntry) -> Tuple[bool, List[str]]:
    reasons: List[str] = []

    msg_bytes = entry.message_summary.encode("utf-8")
    if len(msg_bytes) > 512:
        reasons.append("message_summary_too_long")

    engine = _get_default_engine()
    if engine is not None and hasattr(engine, "_is_sensitive_value"):
        try:
            if not entry.message_summary.startswith("[REDACTED"):
                is_sens, _cat = engine._is_sensitive_value(entry.message_summary)
                if is_sens:
                    reasons.append("message_contains_unredacted_sensitive_value")
        except Exception:
            pass

    if entry.endpoint_pattern:
        if engine is not None and hasattr(engine, "sanitize_endpoint_pattern"):
            try:
                re_sanitized = engine.sanitize_endpoint_pattern(entry.endpoint_pattern)
                if re_sanitized != entry.endpoint_pattern:
                    reasons.append("endpoint_pattern_not_sanitized")
            except Exception:
                pass

    if len(entry.labels) > 32:
        reasons.append("labels_count_exceeded")
    for lk, lv in entry.labels.items():
        if not isinstance(lk, str) or not _label_key_is_valid(lk):
            reasons.append(f"invalid_label_key:{lk}")
            break
        if isinstance(lv, str):
            if len(lv.encode("utf-8")) > 256:
                reasons.append(f"label_value_too_long:{lk}")
                break

    if len(entry.counters) > 32:
        reasons.append("counters_count_exceeded")
    for ck, cv in entry.counters.items():
        if not isinstance(ck, str) or not _label_key_is_valid(ck):
            reasons.append(f"invalid_counter_key:{ck}")
            break
        if isinstance(cv, bool) or not isinstance(cv, int):
            reasons.append(f"invalid_counter_value:{ck}")
            break

    for field_hint in SENSITIVE_FIELD_HINTS:
        if field_hint in entry.labels:
            reasons.append(f"sensitive_hint_in_labels:{field_hint}")
            break
        if field_hint in entry.counters:
            reasons.append(f"sensitive_hint_in_counters:{field_hint}")
            break

    msg_lower = entry.message_summary.lower()
    for leak_word in DURABLE_LEAK_WORDS:
        idx = 0
        while True:
            pos = msg_lower.find(leak_word, idx)
            if pos < 0:
                break
            redacted_marker = False
            scan_start = max(0, pos - 40)
            scan_end = min(len(entry.message_summary), pos + len(leak_word) + 40)
            window = entry.message_summary[scan_start:scan_end]
            if "[REDACTED:" in window:
                redacted_marker = True
            if not redacted_marker:
                reasons.append(f"leak_category_word:{leak_word}")
                break
            idx = pos + 1
        if reasons and reasons[-1].startswith("leak_category_word:"):
            break

    return (len(reasons) == 0, reasons)


def export_json_logs(
    processor: LogProcessor,
    entries: Optional[List[LogEntry]] = None,
    compress: bool = False,
    max_entries: int = 64,
    max_bytes: int = 4_194_304,
) -> Tuple[str, int]:
    return processor.export_json_logs(
        entries=entries,
        compress=compress,
        max_entries=max_entries,
        max_bytes=max_bytes,
    )


def import_json_logs(
    serialized: str,
    compressed: bool = False,
    max_entries: int = 64,
) -> List[LogEntry]:
    proc = LogProcessor()
    return proc.import_json_logs(
        serialized=serialized,
        compressed=compressed,
        max_entries=max_entries,
    )


def sanitize_error_context(error: Any, **kwargs: Any) -> LogEntry:
    proc = LogProcessor(redaction_engine=None)
    return proc.sanitize_error_context(error, **kwargs)
