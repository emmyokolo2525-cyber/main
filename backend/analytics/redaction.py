import os
import re
import hashlib
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


CRYPTO_DOMAIN_VERSION = "harpocrates-redaction-v1"
DEFAULT_CAP_BYTES = 256
DEFAULT_MAX_DEPTH = 16
DEFAULT_MAX_TOTAL_NODES = 16_384

SENSITIVE_FIELD_CATEGORIES: Dict[str, List[str]] = {
    "secret": [
        "secret", "credential", "password", "passwd", "pwd", "token",
        "apikey", "apisecret", "privatekey", "private_key", "privkey",
        "mnemonic", "seedphrase", "seed_phrase", "recoveryphrase",
        "recovery_phrase", "access_key", "accesskey"
    ],
    "witness": [
        "witness", "witnessness", "witnessdata", "witness_data",
        "witness_input", "witnessinput", "witnessvars", "witness_vars",
        "assignment", "assignments", "witness_assignment"
    ],
    "media": [
        "video", "media", "upload", "uploaded_file", "uploadedfile",
        "file_content", "filecontent", "blob", "payload_content",
        "base64_content", "base64content", "binary", "raw_bytes",
        "rawbytes", "image", "audio", "recording", "screenshot",
        "frame", "frames", "clip", "avi", "mp4", "mov", "mkv", "webm",
        "mp3", "wav", "png", "jpg", "jpeg", "gif", "bmp", "tiff"
    ],
    "proof": [
        "proof", "proofdata", "proof_data", "proofpayload", "proof_payload",
        "prooffile", "proof_file", "pi", "witnessed_proof", "zkproof",
        "zk_proof", "circuitproof", "circuit_proof", "verificationkey",
        "verification_key", "vk", "provingkey", "proving_key", "pk",
        "public_inputs", "publicinputs", "private_inputs", "privateinputs",
        "commitments", "commitment", "nullifier", "nullifiers"
    ],
    "wallet_sig": [
        "signature", "sig", "wallet_signature", "walletsig",
        "stellaresignature", "stellar_signature", "txsignature",
        "tx_signature", "xdr", "signedtx", "signed_tx",
        "transactionenvelope", "transaction_envelope", "authsignature",
        "auth_signature", "ed25519signature", "ed25519_signature"
    ],
    "wallet_id": [
        "wallet", "address", "stellaraddress", "stellar_address", "pkh",
        "publickey", "public_key", "pubkey", "account", "accountid",
        "account_id", "muxedaccount", "muxed_account", "assetissuer",
        "asset_issuer", "sourceaccount", "source_account",
        "destinationaccount", "destination_account", "signer", "signers",
        "keypair"
    ],
    "pii": [
        "name", "email", "phone", "dob", "birth", "passport",
        "governmentid", "government_id", "ssn", "idnumber", "id_number",
        "address", "postal", "zip", "biometric", "biometrics", "ip",
        "user_ip", "client_ip"
    ],
}

PROOF_PAYLOAD_KEY_HINTS = set(
    SENSITIVE_FIELD_CATEGORIES["proof"] + SENSITIVE_FIELD_CATEGORIES["witness"]
)
WALLET_SIGNATURE_KEY_HINTS = set(SENSITIVE_FIELD_CATEGORIES["wallet_sig"])
WITNESS_MEDIA_KEY_HINTS = set(
    SENSITIVE_FIELD_CATEGORIES["witness"] + SENSITIVE_FIELD_CATEGORIES["media"]
)
DURABLE_LEAK_CATEGORIES = ["media", "proof", "witness", "secret", "wallet_sig", "pii"]

SAFE_CORRELATION_ID_KEYS = {
    "correlation_id", "request_id", "trace_id", "span_id", "event_id",
    "log_id", "session_id", "message_hash", "stack_trace_hash", "hash_",
    "digest_", "correlationid", "requestid", "traceid", "spanid",
    "eventid", "logid", "sessionid", "messagehash", "stacktracehash"
}

SAFE_ENDPOINT_WORDS = {
    "proof", "video", "embed", "extract", "upload", "api", "normal",
    "endpoint", "health", "metrics", "generate", "internal", "public",
    "private", "auth", "login", "logout", "session", "status", "info",
    "version", "ready", "readiness", "stego", "noir", "circom",
    "config", "export", "import", "download", "create", "update",
    "delete", "get", "list", "search", "verify", "validate", "submit",
    "callback", "hook", "webhook", "run", "execute", "cancel", "retry",
    "reset", "restore", "backup"
}


def stable_encode_key(key: str) -> str:
    if not isinstance(key, str):
        key = str(key)
    lowered = key.lower()
    result = []
    for ch in lowered:
        if ch.isalnum():
            result.append(ch)
    return "".join(result)


def cap_value_bytes(value: str, cap: int = DEFAULT_CAP_BYTES) -> Tuple[str, bool]:
    if not isinstance(value, str):
        value = str(value)
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= cap:
        return value, False
    truncated_bytes = encoded[:cap]
    try:
        truncated_str = truncated_bytes.decode("utf-8", "ignore")
    except Exception:
        truncated_str = truncated_bytes.decode("latin-1", "replace")
    return truncated_str + "\u2026[truncated]", True


def versioned_domain_tag(value) -> str:
    if isinstance(value, str):
        data = value.encode("utf-8", "replace")
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8", "replace")
    digest = hashlib.sha256(data).hexdigest()
    return "v1:" + digest[:16]


def _safe_compile(pattern: str, flags: int = 0) -> re.Pattern:
    try:
        return re.compile(pattern, flags)
    except re.error:
        try:
            return re.compile(r"a^", 0)
        except re.error:
            return re.compile(r".{0}", 0)


@dataclass
class RedactionPatterns:
    sensitive_field_regexes: Dict[str, re.Pattern] = field(default_factory=dict)
    stable_hints_by_category: Dict[str, set] = field(default_factory=dict)
    value_patterns: Dict[str, re.Pattern] = field(default_factory=dict)
    value_category_map: Dict[str, str] = field(default_factory=dict)
    file_path_patterns: List[re.Pattern] = field(default_factory=list)

    @classmethod
    def build(cls) -> "RedactionPatterns":
        patterns = cls()
        for cat, hints in SENSITIVE_FIELD_CATEGORIES.items():
            stable_hints = [stable_encode_key(h) for h in hints]
            patterns.stable_hints_by_category[cat] = set(stable_hints)
            escaped = [re.escape(sh) for sh in stable_hints if sh]
            if escaped:
                joined = "|".join(escaped)
                regex_str = r"(" + joined + r")"
                patterns.sensitive_field_regexes[cat] = _safe_compile(regex_str, re.IGNORECASE)
            else:
                patterns.sensitive_field_regexes[cat] = _safe_compile(r"a^", 0)

        value_defs = [
            ("uuid", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[4][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b", "pii"),
            ("hex_long", r"[0-9a-fA-F]{32,}", "secret"),
            ("base64_long", r"[A-Za-z0-9+/]{64,}={0,2}", "media"),
            ("stellar_address", r"G[A-Z2-7]{55}", "wallet_id"),
            ("stellar_muxed", r"M[A-Z2-7]{68}", "wallet_id"),
            ("stellar_tx_hash", r"[0-9a-fA-F]{64}", "wallet_sig"),
            ("stellar_signature_ed25519", r"[A-Za-z0-9+/]{86,}={0,2}", "wallet_sig"),
            ("private_key_pem", r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP|PRIVATE KEY)-----", "secret"),
            ("jwt_token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "secret"),
            ("xdr_b64_long", r"AAAA[A-Za-z0-9+/]{200,}={0,2}", "wallet_sig"),
            ("ip_address", r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "pii"),
            ("email_address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "pii"),
        ]
        for name, pat, cat in value_defs:
            patterns.value_patterns[name] = _safe_compile(pat, re.IGNORECASE if name not in ("stellar_address", "stellar_muxed") else 0)
            patterns.value_category_map[name] = cat

        media_exts = r"\.(?:avi|mp4|mov|mkv|webm|mp3|wav|png|jpg|jpeg|gif|bmp|tiff|pdf|zip|tar\.gz|tgz|rar|7z)(?:$|[?#])"
        patterns.file_path_patterns.append(_safe_compile(media_exts, re.IGNORECASE))
        path_seg = r"[\\/](?:proof|witness|secret|video|credential|wallet)[\\/.]"
        patterns.file_path_patterns.append(_safe_compile(path_seg, re.IGNORECASE))
        archive_exts = r"\.(?:zip|tar\.gz|tgz|rar|7z)(?:$|[?#])"
        patterns.file_path_patterns.append(_safe_compile(archive_exts, re.IGNORECASE))

        return patterns


@dataclass
class RedactionConfig:
    patterns: RedactionPatterns = field(default_factory=RedactionPatterns.build)
    max_depth: int = DEFAULT_MAX_DEPTH
    max_total_nodes: int = DEFAULT_MAX_TOTAL_NODES
    cap_bytes: int = DEFAULT_CAP_BYTES
    allow_idempotent: bool = True
    stable_key_encode: bool = True
    redact_markers: Dict[str, str] = field(default_factory=lambda: {
        "secret": "[REDACTED:secret]",
        "witness": "[REDACTED:witness]",
        "media": "[REDACTED:media]",
        "proof": "[REDACTED:proof]",
        "wallet_sig": "[REDACTED:wallet_sig]",
        "wallet_id": "[REDACTED:wallet_id]",
        "pii": "[REDACTED:pii]",
        "unknown": "[REDACTED]",
    })


@dataclass
class RedactionOutcome:
    data: Any = None
    nodes_visited: int = 0
    redactions_applied: int = 0
    depth_reached: int = 0
    categories_redacted: List[str] = field(default_factory=list)
    truncations_applied: int = 0
    leaked_categories_found: List[str] = field(default_factory=list)
    redaction_version: str = CRYPTO_DOMAIN_VERSION
    idempotent_signature: str = ""

    def finalize(self):
        cats_sorted = sorted(set(self.categories_redacted))
        sig_input = json.dumps({
            "categories": cats_sorted,
            "nodes_visited": self.nodes_visited,
        }, sort_keys=True)
        self.idempotent_signature = versioned_domain_tag(sig_input)
        self.categories_redacted = cats_sorted
        self.leaked_categories_found = sorted(set(self.leaked_categories_found))


class RedactionEngine:
    def __init__(
        self,
        patterns: Optional[RedactionPatterns] = None,
        config: Optional[RedactionConfig] = None,
    ):
        if config is None:
            self.config = RedactionConfig(patterns=patterns or RedactionPatterns.build())
        else:
            self.config = config
            if patterns is not None:
                self.config.patterns = patterns
        self._patterns = self.config.patterns

    def _is_sensitive_field(self, key: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(key, (str, int, float, bool)):
            return False, None
        if self.config.stable_key_encode:
            encoded = stable_encode_key(key)
        else:
            encoded = str(key).lower()
        if not encoded:
            return False, None
        for cat, stable_hints in self._patterns.stable_hints_by_category.items():
            if encoded in stable_hints:
                return True, cat
        for cat, pattern in self._patterns.sensitive_field_regexes.items():
            try:
                if pattern.search(encoded):
                    return True, cat
            except Exception:
                continue
        return False, None

    def _is_sensitive_value(self, value: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(value, str):
            return False, None
        if len(value) == 0:
            return False, None
        if value.startswith("[REDACTED"):
            return False, None
        for name, pattern in self._patterns.value_patterns.items():
            try:
                if pattern.search(value):
                    cat = self._patterns.value_category_map.get(name, "unknown")
                    return True, cat
            except Exception:
                continue
        if len(value) >= 3:
            if "/" in value or "\\" in value or (value.startswith("/") or value.startswith("\\")):
                for pattern in self._patterns.file_path_patterns:
                    try:
                        if pattern.search(value):
                            return True, "media"
                    except Exception:
                        continue
        return False, None

    def sanitize_endpoint_pattern(self, endpoint: str) -> str:
        if not isinstance(endpoint, str):
            return str(endpoint)
        cleaned = endpoint.split("?", 1)[0].split("#", 1)[0]
        if cleaned == "" or cleaned == "/":
            return cleaned
        segments = [s for s in cleaned.split("/")]
        is_absolute = len(segments) > 0 and segments[0] == ""
        if is_absolute:
            segments = segments[1:]

        uuid_pat = _safe_compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[4][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
        hex_pat = _safe_compile(r"^[0-9a-fA-F]{16,}$")
        digits_pat = _safe_compile(r"^[0-9]{7,}$")
        b64_pat = _safe_compile(r"^[A-Za-z0-9+/\-_]{41,}={0,3}$")
        long_alnum_pat = _safe_compile(r"^[A-Za-z0-9]{16,}$")

        processed = []
        for seg in segments:
            if seg == "":
                continue
            lower_seg = seg.lower()
            if uuid_pat.match(seg):
                processed.append("{id}")
                continue
            if hex_pat.match(seg):
                processed.append("{id}")
                continue
            if digits_pat.match(seg):
                processed.append("{id}")
                continue
            if b64_pat.match(seg):
                processed.append("{id}")
                continue
            if long_alnum_pat.match(seg) and lower_seg not in SAFE_ENDPOINT_WORDS:
                processed.append("{id}")
                continue
            if lower_seg in SAFE_ENDPOINT_WORDS:
                processed.append(lower_seg)
                continue
            processed.append(seg)

        deduped = []
        for seg in processed:
            if seg == "{id}" and deduped and deduped[-1] == "{id}":
                continue
            deduped.append(seg)

        if is_absolute:
            return "/" + "/".join(deduped)
        return "/".join(deduped)

    def _make_tracker(self) -> dict:
        return {
            "nodes_visited": 0,
            "redactions_applied": 0,
            "depth_reached": 0,
            "categories_redacted": [],
            "truncations_applied": 0,
            "stopped": False,
        }

    def _increment_nodes(self, tracker: dict, depth: int) -> bool:
        tracker["nodes_visited"] += 1
        if depth > tracker["depth_reached"]:
            tracker["depth_reached"] = depth
        if tracker["nodes_visited"] > self.config.max_total_nodes:
            tracker["stopped"] = True
            return False
        if depth > self.config.max_depth:
            tracker["stopped"] = True
            return False
        return True

    def _is_already_redacted(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        if value.startswith("[REDACTED"):
            return True
        return False

    def _marker_for(self, category: Optional[str]) -> str:
        if category is None:
            return self.config.redact_markers.get("unknown", "[REDACTED]")
        return self.config.redact_markers.get(
            category, self.config.redact_markers.get("unknown", "[REDACTED]")
        )

    def _record_redaction(self, tracker: dict, category: Optional[str]):
        tracker["redactions_applied"] += 1
        if category:
            tracker["categories_redacted"].append(category)

    def _record_truncation(self, tracker: dict):
        tracker["truncations_applied"] += 1

    def _sanitize_string(
        self,
        value: str,
        field_name: Optional[str],
        depth: int,
        tracker: dict,
        force_sensitive_cat: Optional[str] = None,
    ) -> str:
        if self.config.allow_idempotent and self._is_already_redacted(value):
            return value

        safe_key = None
        if field_name is not None:
            encoded_field = stable_encode_key(field_name)
            for sk in SAFE_CORRELATION_ID_KEYS:
                if sk == encoded_field or encoded_field.endswith(sk) or encoded_field.startswith(sk):
                    safe_key = sk
                    break

        final_cat = force_sensitive_cat
        matched = False

        if safe_key is not None:
            capped, did_truncate = cap_value_bytes(value, self.config.cap_bytes)
            if did_truncate:
                self._record_truncation(tracker)
            return capped

        if final_cat is None:
            is_sens, vcat = self._is_sensitive_value(value)
            if is_sens:
                final_cat = vcat
                matched = True

        if final_cat is not None:
            self._record_redaction(tracker, final_cat)
            return self._marker_for(final_cat)

        capped, did_truncate = cap_value_bytes(value, self.config.cap_bytes)
        if did_truncate:
            self._record_truncation(tracker)
        return capped

    def _sanitize_bytes(self, value: bytes, field_name: Optional[str], depth: int, tracker: dict) -> str:
        length = len(value)
        summary = f"<bytes len={length} sha256={hashlib.sha256(value).hexdigest()[:16]}>"
        capped, did_truncate = cap_value_bytes(summary, self.config.cap_bytes)
        if did_truncate:
            self._record_truncation(tracker)
        marker_cat = None
        if field_name is not None:
            is_sens, fcat = self._is_sensitive_field(field_name)
            if is_sens:
                marker_cat = fcat
        if marker_cat is None and length >= 64:
            try:
                as_b64 = base64.b64encode(value).decode("ascii")
                is_sens, vcat = self._is_sensitive_value(as_b64)
                if is_sens:
                    marker_cat = vcat
            except Exception:
                pass
        if marker_cat is not None:
            self._record_redaction(tracker, marker_cat)
            return self._marker_for(marker_cat)
        return capped

    def _sanitize_any(
        self,
        value: Any,
        field_name: Optional[str],
        depth: int,
        tracker: dict,
        parent_sensitive_cat: Optional[str] = None,
    ) -> Any:
        if not self._increment_nodes(tracker, depth):
            return "[REDACTED:max_depth_exceeded]" if depth > self.config.max_depth else "[REDACTED:max_nodes_exceeded]"

        if self.config.allow_idempotent and isinstance(value, str) and self._is_already_redacted(value):
            return value

        if isinstance(value, bytes):
            return self._sanitize_bytes(value, field_name, depth, tracker)

        local_sensitive_cat = parent_sensitive_cat
        if field_name is not None and local_sensitive_cat is None:
            is_sens, fcat = self._is_sensitive_field(field_name)
            if is_sens:
                local_sensitive_cat = fcat

        if isinstance(value, str):
            return self._sanitize_string(
                value, field_name, depth, tracker,
                force_sensitive_cat=local_sensitive_cat,
            )

        if value is None:
            return None

        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            capped, did_truncate = cap_value_bytes(str(value), self.config.cap_bytes)
            if did_truncate:
                self._record_truncation(tracker)
                return capped
            return value

        if isinstance(value, dict):
            if local_sensitive_cat is not None:
                self._record_redaction(tracker, local_sensitive_cat)
                result = {}
                for k, v in value.items():
                    if not self._increment_nodes(tracker, depth + 1):
                        break
                    if isinstance(v, (dict, list, tuple)):
                        result[k] = self._sanitize_any(
                            v, k if isinstance(k, str) else None,
                            depth + 1, tracker,
                            parent_sensitive_cat=local_sensitive_cat,
                        )
                    else:
                        self._record_redaction(tracker, local_sensitive_cat)
                        result[k] = self._marker_for(local_sensitive_cat)
                return result
            result = {}
            for k, v in value.items():
                if tracker["stopped"]:
                    break
                key_str = k if isinstance(k, str) else str(k)
                result[k] = self._sanitize_any(
                    v, key_str, depth + 1, tracker,
                    parent_sensitive_cat=None,
                )
            return result

        if isinstance(value, (list, tuple)):
            is_tuple = isinstance(value, tuple)
            if local_sensitive_cat is not None:
                self._record_redaction(tracker, local_sensitive_cat)
                result = []
                for item in value:
                    if not self._increment_nodes(tracker, depth + 1):
                        break
                    if isinstance(item, (dict, list, tuple)):
                        result.append(self._sanitize_any(
                            item, None, depth + 1, tracker,
                            parent_sensitive_cat=local_sensitive_cat,
                        ))
                    else:
                        self._record_redaction(tracker, local_sensitive_cat)
                        result.append(self._marker_for(local_sensitive_cat))
                return tuple(result) if is_tuple else result
            result = []
            for item in value:
                if tracker["stopped"]:
                    break
                result.append(self._sanitize_any(
                    item, None, depth + 1, tracker,
                    parent_sensitive_cat=None,
                ))
            return tuple(result) if is_tuple else result

        try:
            as_str = str(value)
            capped, did_truncate = cap_value_bytes(as_str, self.config.cap_bytes)
            if did_truncate:
                self._record_truncation(tracker)
            return capped
        except Exception:
            return "[REDACTED:unserializable]"

    def _scan_leaks(self, data: Any, marker_prefix: str = "[REDACTED:") -> List[str]:
        found = []
        try:
            data_str = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            data_str = str(data)
        for cat in DURABLE_LEAK_CATEGORIES:
            marker = marker_prefix + cat + "]"
            pass
        for cat, hints in SENSITIVE_FIELD_CATEGORIES.items():
            if cat not in DURABLE_LEAK_CATEGORIES:
                continue
            for hint in hints:
                pat = _safe_compile(r"(^|[_\W])" + re.escape(hint) + r"([_\W]|$)", re.IGNORECASE)
                try:
                    if pat.search(data_str):
                        if cat not in found:
                            found.append(cat)
                            break
                except Exception:
                    continue
        return found

    def sanitize(self, value: Any, context: Optional[str] = None) -> RedactionOutcome:
        tracker = self._make_tracker()
        root_field = context
        sanitized = self._sanitize_any(value, root_field, 0, tracker, parent_sensitive_cat=None)
        outcome = RedactionOutcome(
            data=sanitized,
            nodes_visited=tracker["nodes_visited"],
            redactions_applied=tracker["redactions_applied"],
            depth_reached=tracker["depth_reached"],
            categories_redacted=list(tracker["categories_redacted"]),
            truncations_applied=tracker["truncations_applied"],
            leaked_categories_found=[],
            redaction_version=CRYPTO_DOMAIN_VERSION,
            idempotent_signature="",
        )
        outcome.leaked_categories_found = self._scan_leaks(outcome.data)
        outcome.finalize()
        return outcome
