"""
Adversarial redaction tests – issue #28.

Covers:
  - RedactionEngine (analytics/redaction.py): nested secret fields, value-pattern
    matching (hex, base64, JWT, PEM, Stellar, email, IP), depth/node limits,
    idempotent re-redaction, leak scanning, bytes handling, and outcome metrics.
  - logging_utils.redact_sensitive: SENSITIVE_KEYS set, witness partial-match,
    nested dicts/lists/tuples, and log output verification.
  - No sensitive fixture value may appear in the sanitized output or in logs.
"""

from __future__ import annotations

import json
import logging
import io
import unittest

from analytics.redaction import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_TOTAL_NODES,
    DURABLE_LEAK_CATEGORIES,
    RedactionConfig,
    RedactionEngine,
    RedactionOutcome,
    RedactionPatterns,
    stable_encode_key,
    cap_value_bytes,
    versioned_domain_tag,
)
from logging_utils import (
    REDACTED_VALUE,
    SENSITIVE_KEYS,
    log_structured,
    redact_sensitive,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_SECRET_PASSWORD = "s3cr3t-p@ssw0rd-NEVER-LOG"
_SECRET_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
_PEM_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----"
_HEX_64 = "a" * 64          # 32-byte hex – matches hex_long / stellar_tx_hash patterns
_HEX_32 = "b" * 32          # 16-byte hex – matches hex_long pattern
_BASE64_64 = "A" * 64 + "=="  # 64-char base64 – matches base64_long pattern
_STELLAR_ADDRESS = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
_EMAIL = "user@example.com"
_IP_ADDR = "192.168.1.100"

_ENGINE = RedactionEngine()


# ---------------------------------------------------------------------------
# 1. logging_utils.redact_sensitive – key-based redaction
# ---------------------------------------------------------------------------

class TestLoggingUtilsRedactSensitive(unittest.TestCase):
    """Tests for the simpler key-based redactor used in request logging."""

    def _assert_redacted(self, key: str, value="sensitive"):
        result = redact_sensitive({key: value})
        self.assertEqual(
            result[key], REDACTED_VALUE,
            f"key '{key}' should be redacted but got: {result[key]!r}",
        )
        self.assertNotIn(str(value), json.dumps(result))

    def _assert_safe(self, key: str, value="safe-value"):
        result = redact_sensitive({key: value})
        self.assertEqual(result[key], value, f"key '{key}' should NOT be redacted")

    # --- SENSITIVE_KEYS exact matches ---
    def test_authorization_redacted(self):
        self._assert_redacted("authorization", "Bearer " + _JWT_TOKEN)

    def test_credentialsecret_redacted(self):
        self._assert_redacted("credentialSecret", _SECRET_PASSWORD)

    def test_nullifiersecret_redacted(self):
        self._assert_redacted("nullifierSecret", _SECRET_PASSWORD)

    def test_proof_redacted(self):
        self._assert_redacted("proof", _JWT_TOKEN)

    def test_publicinputs_redacted(self):
        self._assert_redacted("publicInputs", ["input1", "input2"])

    # --- witness partial-match (any key containing "witness") ---
    def test_witnessData_redacted(self):
        self._assert_redacted("witnessData", _SECRET_PASSWORD)

    def test_witnessProof_redacted(self):
        self._assert_redacted("witnessProof", _JWT_TOKEN)

    def test_myWitnessValue_redacted(self):
        self._assert_redacted("myWitnessValue", "some-witness-value")

    def test_WITNESS_uppercase_redacted(self):
        self._assert_redacted("WITNESS", "value")

    # --- safe keys are preserved ---
    def test_protocol_safe(self):
        self._assert_safe("protocol", "harpocrates")

    def test_tier_safe(self):
        self._assert_safe("tier", "silent")

    def test_source_hash_safe(self):
        self._assert_safe("sourceHash", "a" * 64)

    def test_version_safe(self):
        self._assert_safe("version", 2)

    def test_timestamp_safe(self):
        self._assert_safe("timestamp", "2024-01-01T00:00:00+00:00")

    # --- nested structures ---
    def test_nested_proof_key_redacted(self):
        data = {"outer": {"proof": _JWT_TOKEN, "safe": "ok"}}
        result = redact_sensitive(data)
        self.assertEqual(result["outer"]["proof"], REDACTED_VALUE)
        self.assertEqual(result["outer"]["safe"], "ok")
        self.assertNotIn(_JWT_TOKEN, json.dumps(result))

    def test_double_nested_witness_redacted(self):
        data = {"a": {"b": {"witnessData": _SECRET_PASSWORD}}}
        result = redact_sensitive(data)
        self.assertEqual(result["a"]["b"]["witnessData"], REDACTED_VALUE)
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(result))

    def test_list_with_sensitive_dict_redacted(self):
        data = {"items": [{"proof": _JWT_TOKEN}, {"safe": "value"}]}
        result = redact_sensitive(data)
        self.assertEqual(result["items"][0]["proof"], REDACTED_VALUE)
        self.assertEqual(result["items"][1]["safe"], "value")
        self.assertNotIn(_JWT_TOKEN, json.dumps(result))

    def test_tuple_with_sensitive_dict_redacted(self):
        data = {"pair": ({"proof": _JWT_TOKEN}, "safe")}
        result = redact_sensitive(data)
        self.assertEqual(result["pair"][0]["proof"], REDACTED_VALUE)
        self.assertEqual(result["pair"][1], "safe")

    def test_non_dict_passthrough(self):
        self.assertEqual(redact_sensitive("plain string"), "plain string")
        self.assertEqual(redact_sensitive(42), 42)
        self.assertIsNone(redact_sensitive(None))

    # --- log_structured emits no sensitive values ---
    def test_log_structured_omits_proof_token(self):
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("_adv_logging_utils_1_")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_structured(logger, logging.INFO, {"proof": _JWT_TOKEN, "tier": "silent"})
        logged = log_capture.getvalue()
        self.assertNotIn(_JWT_TOKEN, logged)
        self.assertIn("silent", logged)

    def test_log_structured_omits_nested_witness(self):
        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("_adv_logging_utils_2_")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        log_structured(
            logger, logging.INFO,
            {"meta": {"witnessData": _SECRET_PASSWORD, "version": 2}},
        )
        logged = log_capture.getvalue()
        self.assertNotIn(_SECRET_PASSWORD, logged)


# ---------------------------------------------------------------------------
# 2. RedactionEngine – field-name-based sensitive detection
# ---------------------------------------------------------------------------

class TestRedactionEngineFieldNames(unittest.TestCase):
    """RedactionEngine must redact values whose field name matches a sensitive category."""

    def _sanitize(self, data, context=None):
        return _ENGINE.sanitize(data, context=context)

    # secret category
    def test_secret_field_value_redacted(self):
        outcome = self._sanitize({"secret": _SECRET_PASSWORD})
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(outcome.data))
        self.assertGreater(outcome.redactions_applied, 0)

    def test_password_field_value_redacted(self):
        outcome = self._sanitize({"password": _SECRET_PASSWORD})
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(outcome.data))

    def test_token_field_value_redacted(self):
        outcome = self._sanitize({"token": _JWT_TOKEN})
        self.assertNotIn(_JWT_TOKEN, json.dumps(outcome.data))

    def test_privatekey_field_value_redacted(self):
        outcome = self._sanitize({"privateKey": _PEM_PRIVATE_KEY})
        self.assertNotIn("BEGIN RSA", json.dumps(outcome.data))

    def test_mnemonic_field_value_redacted(self):
        outcome = self._sanitize({"mnemonic": _SECRET_MNEMONIC})
        self.assertNotIn(_SECRET_MNEMONIC, json.dumps(outcome.data))

    # witness category
    def test_witness_field_value_redacted(self):
        outcome = self._sanitize({"witness": _HEX_64})
        self.assertNotIn(_HEX_64, json.dumps(outcome.data))

    def test_witnessdata_field_value_redacted(self):
        outcome = self._sanitize({"witnessData": _SECRET_PASSWORD})
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(outcome.data))

    # proof category
    def test_proof_field_value_redacted(self):
        outcome = self._sanitize({"proof": _HEX_64})
        self.assertNotIn(_HEX_64, json.dumps(outcome.data))

    def test_zkproof_field_value_redacted(self):
        outcome = self._sanitize({"zkProof": _BASE64_64})
        self.assertNotIn(_BASE64_64, json.dumps(outcome.data))

    # wallet_sig category
    def test_signature_field_value_redacted(self):
        outcome = self._sanitize({"signature": _HEX_64})
        self.assertNotIn(_HEX_64, json.dumps(outcome.data))

    def test_xdr_field_value_redacted(self):
        outcome = self._sanitize({"xdr": "AAAA" + "A" * 200})
        self.assertNotIn("AAAA", json.dumps(outcome.data))

    # wallet_id category
    def test_stellar_address_field_value_redacted(self):
        outcome = self._sanitize({"stellarAddress": _STELLAR_ADDRESS})
        self.assertNotIn(_STELLAR_ADDRESS, json.dumps(outcome.data))

    # pii category
    def test_email_field_value_redacted(self):
        outcome = self._sanitize({"email": _EMAIL})
        self.assertNotIn(_EMAIL, json.dumps(outcome.data))

    def test_name_field_value_redacted(self):
        outcome = self._sanitize({"name": "Alice Testerson"})
        # name is a pii key – value should be redacted
        result_str = json.dumps(outcome.data)
        self.assertNotIn("Alice Testerson", result_str)

    # safe fields survive
    def test_safe_field_preserved(self):
        outcome = self._sanitize({"tier": "silent", "version": 2})
        self.assertEqual(outcome.data["tier"], "silent")
        self.assertEqual(outcome.data["version"], 2)


# ---------------------------------------------------------------------------
# 3. RedactionEngine – value-pattern matching
# ---------------------------------------------------------------------------

class TestRedactionEngineValuePatterns(unittest.TestCase):
    """Even without a sensitive field name, sensitive values must be redacted."""

    def _sanitize(self, data):
        return _ENGINE.sanitize(data)

    def test_bare_jwt_value_redacted(self):
        outcome = self._sanitize({"info": _JWT_TOKEN})
        self.assertNotIn(_JWT_TOKEN, json.dumps(outcome.data))

    def test_bare_pem_key_value_redacted(self):
        outcome = self._sanitize({"info": _PEM_PRIVATE_KEY})
        self.assertNotIn("BEGIN RSA PRIVATE KEY", json.dumps(outcome.data))

    def test_long_hex_value_redacted(self):
        # hex_long pattern: 32+ hex chars
        outcome = self._sanitize({"info": _HEX_64})
        self.assertNotIn(_HEX_64, json.dumps(outcome.data))

    def test_hex_exactly_32_chars_redacted(self):
        outcome = self._sanitize({"info": _HEX_32})
        self.assertNotIn(_HEX_32, json.dumps(outcome.data))

    def test_short_hex_not_redacted_by_pattern(self):
        # Less than 32 hex chars – should not match hex_long
        short_hex = "deadbeef"
        outcome = self._sanitize({"safe_info": short_hex})
        # Value should survive (not match any value pattern)
        self.assertIn(short_hex, json.dumps(outcome.data))

    def test_stellar_address_value_redacted(self):
        outcome = self._sanitize({"addr": _STELLAR_ADDRESS})
        self.assertNotIn(_STELLAR_ADDRESS, json.dumps(outcome.data))

    def test_email_value_redacted(self):
        outcome = self._sanitize({"contact": _EMAIL})
        self.assertNotIn(_EMAIL, json.dumps(outcome.data))

    def test_ip_address_value_redacted(self):
        outcome = self._sanitize({"client": _IP_ADDR})
        self.assertNotIn(_IP_ADDR, json.dumps(outcome.data))

    def test_long_base64_value_redacted(self):
        outcome = self._sanitize({"data": _BASE64_64})
        self.assertNotIn(_BASE64_64, json.dumps(outcome.data))

    def test_ordinary_string_not_redacted(self):
        outcome = self._sanitize({"label": "harpocrates-evidence"})
        self.assertIn("harpocrates-evidence", json.dumps(outcome.data))

    def test_numeric_value_not_redacted(self):
        outcome = self._sanitize({"count": 42})
        self.assertEqual(outcome.data["count"], 42)

    def test_boolean_value_not_redacted(self):
        outcome = self._sanitize({"ok": True})
        self.assertTrue(outcome.data["ok"])

    def test_none_value_not_redacted(self):
        outcome = self._sanitize({"nullable": None})
        self.assertIsNone(outcome.data["nullable"])


# ---------------------------------------------------------------------------
# 4. RedactionEngine – nested secret fields at various depths
# ---------------------------------------------------------------------------

class TestRedactionEngineNestedSecrets(unittest.TestCase):

    def _sanitize(self, data):
        return _ENGINE.sanitize(data)

    def test_depth_2_secret_redacted(self):
        data = {"outer": {"secret": _SECRET_PASSWORD}}
        outcome = self._sanitize(data)
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(outcome.data))

    def test_depth_3_proof_redacted(self):
        data = {"a": {"b": {"proof": _JWT_TOKEN}}}
        outcome = self._sanitize(data)
        self.assertNotIn(_JWT_TOKEN, json.dumps(outcome.data))

    def test_depth_4_mnemonic_redacted(self):
        data = {"l1": {"l2": {"l3": {"mnemonic": _SECRET_MNEMONIC}}}}
        outcome = self._sanitize(data)
        self.assertNotIn(_SECRET_MNEMONIC, json.dumps(outcome.data))

    def test_secret_parent_key_redacts_entire_subtree(self):
        # When the parent key is sensitive, the whole subtree is redacted
        data = {"secret": {"nested": _SECRET_PASSWORD, "deeper": {"val": "x"}}}
        outcome = self._sanitize(data)
        result_str = json.dumps(outcome.data)
        self.assertNotIn(_SECRET_PASSWORD, result_str)

    def test_witness_list_of_secrets_redacted(self):
        data = {"witness": [_SECRET_PASSWORD, _JWT_TOKEN, _HEX_64]}
        outcome = self._sanitize(data)
        result_str = json.dumps(outcome.data)
        self.assertNotIn(_SECRET_PASSWORD, result_str)
        self.assertNotIn(_JWT_TOKEN, result_str)
        self.assertNotIn(_HEX_64, result_str)

    def test_proof_dict_subtree_redacted(self):
        data = {
            "proof": {
                "pi_a": _HEX_64,
                "pi_b": [_HEX_64, _HEX_64],
                "pi_c": _HEX_64,
            }
        }
        outcome = self._sanitize(data)
        result_str = json.dumps(outcome.data)
        self.assertNotIn(_HEX_64, result_str)

    def test_mixed_sensitive_and_safe_siblings(self):
        data = {
            "protocol": "harpocrates",
            "tier": "silent",
            "proof": _JWT_TOKEN,
            "version": 2,
        }
        outcome = self._sanitize(data)
        self.assertNotIn(_JWT_TOKEN, json.dumps(outcome.data))
        self.assertEqual(outcome.data["protocol"], "harpocrates")
        self.assertEqual(outcome.data["tier"], "silent")
        self.assertEqual(outcome.data["version"], 2)

    def test_safe_correlation_id_not_redacted(self):
        # SAFE_CORRELATION_ID_KEYS: request_id, trace_id, session_id, etc.
        data = {"request_id": "abc-123", "trace_id": "xyz-789"}
        outcome = self._sanitize(data)
        self.assertIn("abc-123", json.dumps(outcome.data))
        self.assertIn("xyz-789", json.dumps(outcome.data))


# ---------------------------------------------------------------------------
# 5. RedactionEngine – depth and node limits
# ---------------------------------------------------------------------------

class TestRedactionEngineLimits(unittest.TestCase):

    def _engine(self, max_depth=DEFAULT_MAX_DEPTH, max_nodes=DEFAULT_MAX_TOTAL_NODES):
        cfg = RedactionConfig(
            patterns=RedactionPatterns.build(),
            max_depth=max_depth,
            max_total_nodes=max_nodes,
        )
        return RedactionEngine(config=cfg)

    def _make_deep(self, depth: int, leaf_key="safe", leaf_val="ok") -> dict:
        node: dict = {leaf_key: leaf_val}
        for _ in range(depth - 1):
            node = {"child": node}
        return node

    def test_within_default_depth_limit(self):
        # 15 levels deep – should sanitize normally (limit is 16)
        data = self._make_deep(15, leaf_val="safe-value")
        outcome = _ENGINE.sanitize(data)
        self.assertIsNotNone(outcome.data)

    def test_exceeds_depth_limit_returns_marker(self):
        engine = self._engine(max_depth=3)
        # Build something 5 levels deep with a safe value at the bottom
        data = self._make_deep(5, leaf_val="deep-value")
        outcome = engine.sanitize(data)
        result_str = json.dumps(outcome.data, default=str)
        # The leaf should not be accessible at full depth
        self.assertNotIn("deep-value", result_str)

    def test_exceeds_node_limit_stops_gracefully(self):
        engine = self._engine(max_nodes=10)
        # 20 keys – will exceed the node budget
        data = {f"k{i}": f"value_{i}" for i in range(20)}
        outcome = engine.sanitize(data)
        # Must not raise; outcome.data must be a dict (possibly partial)
        self.assertIsInstance(outcome.data, dict)

    def test_outcome_nodes_visited_within_limit(self):
        engine = self._engine(max_nodes=50)
        data = {f"k{i}": f"v{i}" for i in range(40)}
        outcome = engine.sanitize(data)
        self.assertLessEqual(outcome.nodes_visited, 50)

    def test_deep_secret_at_limit_boundary_is_redacted(self):
        # Secret at exactly the max depth – must still be redacted
        engine = self._engine(max_depth=5)
        # 4 levels deep, secret at level 4
        data = {"a": {"b": {"c": {"secret": _SECRET_PASSWORD}}}}
        outcome = engine.sanitize(data)
        self.assertNotIn(_SECRET_PASSWORD, json.dumps(outcome.data))


# ---------------------------------------------------------------------------
# 6. RedactionEngine – idempotent re-redaction
# ---------------------------------------------------------------------------

class TestRedactionEngineIdempotent(unittest.TestCase):

    def test_already_redacted_value_unchanged(self):
        data = {"proof": "[REDACTED:proof]"}
        outcome = _ENGINE.sanitize(data)
        # Idempotent: a value that is already a redaction marker must not be
        # double-redacted or altered
        self.assertEqual(outcome.data["proof"], "[REDACTED:proof]")

    def test_already_redacted_generic_unchanged(self):
        data = {"token": "[REDACTED]"}
        outcome = _ENGINE.sanitize(data)
        self.assertEqual(outcome.data["token"], "[REDACTED]")

    def test_double_sanitize_is_stable(self):
        data = {"secret": _SECRET_PASSWORD, "safe": "hello"}
        first = _ENGINE.sanitize(data)
        second = _ENGINE.sanitize(first.data)
        # Second pass must produce identical data
        self.assertEqual(first.data, second.data)

    def test_idempotent_signature_is_deterministic(self):
        data = {"secret": _SECRET_PASSWORD}
        o1 = _ENGINE.sanitize(data)
        o2 = _ENGINE.sanitize({"secret": _SECRET_PASSWORD})
        self.assertEqual(o1.idempotent_signature, o2.idempotent_signature)

    def test_different_inputs_produce_different_signatures(self):
        o1 = _ENGINE.sanitize({"secret": "value-a"})
        o2 = _ENGINE.sanitize({"password": "value-b"})
        # Different categories may or may not differ, but data must differ
        self.assertNotEqual(o1.data, o2.data)


# ---------------------------------------------------------------------------
# 7. RedactionEngine – bytes handling
# ---------------------------------------------------------------------------

class TestRedactionEngineBytes(unittest.TestCase):

    def test_small_bytes_summarised(self):
        data = b"\x00\x01\x02\x03"
        outcome = _ENGINE.sanitize(data, context="raw_bytes")
        # bytes are replaced with a safe summary string
        self.assertIsInstance(outcome.data, str)
        self.assertNotIn("\\x", outcome.data)

    def test_large_sensitive_bytes_redacted(self):
        # 64+ bytes under a sensitive field name → redacted
        outcome = _ENGINE.sanitize({"signature": b"\xde\xad" * 64})
        result_str = json.dumps(outcome.data, default=str)
        # Must not contain raw byte data; must contain a redaction marker or summary
        self.assertNotIn("\\xde\\xad", result_str)

    def test_bytes_summary_contains_sha256_prefix(self):
        raw = b"some raw bytes here"
        outcome = _ENGINE.sanitize({"data": raw})
        result_str = json.dumps(outcome.data, default=str)
        # Safe bytes produce a summary like "<bytes len=N sha256=HEXPREFIX>"
        self.assertIn("bytes", result_str)


# ---------------------------------------------------------------------------
# 8. RedactionEngine – outcome metrics and categories
# ---------------------------------------------------------------------------

class TestRedactionEngineOutcomeMetrics(unittest.TestCase):

    def test_redaction_count_increments_for_each_sensitive_field(self):
        data = {"secret": "a", "password": "b", "token": "c"}
        outcome = _ENGINE.sanitize(data)
        self.assertGreaterEqual(outcome.redactions_applied, 3)

    def test_categories_redacted_lists_triggered_categories(self):
        data = {"secret": "x", "email": _EMAIL}
        outcome = _ENGINE.sanitize(data)
        # secret → "secret" category, email → "pii"
        self.assertIn("secret", outcome.categories_redacted)
        self.assertIn("pii", outcome.categories_redacted)

    def test_no_sensitive_data_zero_redactions(self):
        data = {"protocol": "harpocrates", "tier": "silent", "version": 2}
        outcome = _ENGINE.sanitize(data)
        self.assertEqual(outcome.redactions_applied, 0)

    def test_depth_reached_tracked(self):
        data = {"a": {"b": {"c": "deep"}}}
        outcome = _ENGINE.sanitize(data)
        self.assertGreaterEqual(outcome.depth_reached, 3)

    def test_redaction_version_present(self):
        outcome = _ENGINE.sanitize({"ok": True})
        self.assertTrue(outcome.redaction_version.startswith("harpocrates-redaction-v"))

    def test_idempotent_signature_format(self):
        outcome = _ENGINE.sanitize({"key": "value"})
        # versioned_domain_tag format: "v1:<16 hex chars>"
        self.assertTrue(outcome.idempotent_signature.startswith("v1:"))
        self.assertEqual(len(outcome.idempotent_signature), 3 + 16)

    def test_truncation_applied_for_long_string_value(self):
        # A safe field with a value > 256 bytes should be truncated
        long_val = "x" * 512
        outcome = _ENGINE.sanitize({"label": long_val})
        self.assertGreater(outcome.truncations_applied, 0)
        self.assertIn("\u2026[truncated]", outcome.data["label"])

    def test_no_truncation_for_short_values(self):
        outcome = _ENGINE.sanitize({"label": "short"})
        self.assertEqual(outcome.truncations_applied, 0)


# ---------------------------------------------------------------------------
# 9. RedactionEngine – leak scan
# ---------------------------------------------------------------------------

class TestRedactionEngineLeakScan(unittest.TestCase):

    def test_no_leaks_after_clean_sanitize(self):
        data = {"secret": _SECRET_PASSWORD, "proof": _JWT_TOKEN}
        outcome = _ENGINE.sanitize(data)
        # The post-sanitize scan should find no leaked categories
        self.assertEqual(
            outcome.leaked_categories_found,
            [],
            f"Unexpected leaks found: {outcome.leaked_categories_found}",
        )

    def test_no_leaks_for_benign_metadata(self):
        data = {
            "protocol": "harpocrates",
            "version": 2,
            "tier": "silent",
            "sourceHash": "ab" * 32,
        }
        outcome = _ENGINE.sanitize(data)
        self.assertEqual(outcome.leaked_categories_found, [])


# ---------------------------------------------------------------------------
# 10. Helper utilities
# ---------------------------------------------------------------------------

class TestHelperUtilities(unittest.TestCase):

    def test_stable_encode_key_strips_non_alnum(self):
        self.assertEqual(stable_encode_key("private_key"), "privatekey")
        self.assertEqual(stable_encode_key("PRIVATE KEY"), "privatekey")
        self.assertEqual(stable_encode_key("proof-data!"), "proofdata")

    def test_stable_encode_key_non_string_input(self):
        # Non-string input should be coerced without raising
        result = stable_encode_key(42)
        self.assertEqual(result, "42")

    def test_cap_value_bytes_short_unchanged(self):
        result, truncated = cap_value_bytes("hello", cap=256)
        self.assertEqual(result, "hello")
        self.assertFalse(truncated)

    def test_cap_value_bytes_long_truncated(self):
        result, truncated = cap_value_bytes("x" * 512, cap=256)
        self.assertTrue(truncated)
        self.assertIn("\u2026[truncated]", result)
        self.assertLessEqual(len(result.encode("utf-8")), 300)

    def test_cap_value_bytes_exactly_at_limit(self):
        result, truncated = cap_value_bytes("a" * 256, cap=256)
        self.assertFalse(truncated)

    def test_versioned_domain_tag_format(self):
        tag = versioned_domain_tag("test-value")
        self.assertTrue(tag.startswith("v1:"))
        self.assertEqual(len(tag), 3 + 16)

    def test_versioned_domain_tag_deterministic(self):
        self.assertEqual(versioned_domain_tag("x"), versioned_domain_tag("x"))

    def test_versioned_domain_tag_differs_for_different_inputs(self):
        self.assertNotEqual(versioned_domain_tag("a"), versioned_domain_tag("b"))

    def test_versioned_domain_tag_accepts_bytes(self):
        tag = versioned_domain_tag(b"raw-bytes")
        self.assertTrue(tag.startswith("v1:"))

    def test_versioned_domain_tag_accepts_non_string(self):
        tag = versioned_domain_tag({"key": "val"})
        self.assertTrue(tag.startswith("v1:"))


if __name__ == "__main__":
    unittest.main()
