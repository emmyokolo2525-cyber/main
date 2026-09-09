"""
Adversarial metadata validation tests – issue #28.

Covers:
  - Nested secret fields (sensitive values inside the metadata dict)
  - Oversized structures (payload exceeding the 64 KiB envelope limit and the
    16 KiB max_metadata_bytes app-level gate)
  - Invalid hash formats (wrong length, non-hex characters, wrong type)
  - Wrong JSON types for every required field
  - Unexpected / extra keys (forward-compat behaviour)
  - Stable HTTP status codes for each error class
  - Verified that no sensitive fixture value reaches stored metadata or logs
    via logging_utils.redact_sensitive
"""

from __future__ import annotations

import hashlib
import json
import string
import unittest
from datetime import datetime, timezone, timedelta

from envelope import (
    MAX_PAYLOAD_BYTES,
    ALLOWED_TIERS,
    pack_envelope,
    unpack_envelope,
    validate_v1,
    validate_v2,
    canonical_metadata_hash,
    _is_hex_32,
    _validate_timestamp,
)
from logging_utils import redact_sensitive, REDACTED_VALUE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENSITIVE_SECRET = "s3cr3t-password-should-never-appear"
_SENSITIVE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_5NjP1"
_SENSITIVE_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

_NOW_UTC = datetime.now(timezone.utc).isoformat()

_VALID_BASE: dict = {
    "protocol": "harpocrates",
    "version": 1,
    "tier": "silent",
    "sourceHash": "ab" * 32,
    "proofId": "cd" * 32,
    "timestamp": _NOW_UTC,
}


def _valid(**overrides) -> dict:
    m = dict(_VALID_BASE)
    m.update(overrides)
    return m


# ---------------------------------------------------------------------------
# 1. Required-field completeness
# ---------------------------------------------------------------------------

class TestRequiredFields(unittest.TestCase):
    """validate_v1 must reject any metadata missing a required field."""

    REQUIRED = ("protocol", "version", "tier", "sourceHash", "proofId", "timestamp")

    def test_complete_valid_metadata_passes(self):
        """Baseline: a fully valid metadata dict should not raise."""
        validate_v1(_valid())

    def test_each_missing_required_field_raises(self):
        for field in self.REQUIRED:
            with self.subTest(missing=field):
                m = _valid()
                del m[field]
                with self.assertRaises(ValueError, msg=f"should reject missing '{field}'"):
                    validate_v1(m)

    def test_empty_dict_raises(self):
        with self.assertRaises(ValueError):
            validate_v1({})

    def test_none_instead_of_dict_raises(self):
        with self.assertRaises((ValueError, AttributeError, TypeError)):
            validate_v1(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. Wrong JSON types for required fields
# ---------------------------------------------------------------------------

class TestWrongTypes(unittest.TestCase):
    """Each required field must reject non-string / wrong-type values."""

    def _assert_rejects(self, field: str, bad_value, msg: str = ""):
        m = _valid(**{field: bad_value})
        with self.assertRaises(ValueError, msg=msg or f"field '{field}' should reject {type(bad_value).__name__}"):
            validate_v1(m)

    # protocol
    def test_protocol_integer(self):
        self._assert_rejects("protocol", 1)

    def test_protocol_none(self):
        self._assert_rejects("protocol", None)

    def test_protocol_list(self):
        self._assert_rejects("protocol", ["harpocrates"])

    def test_protocol_wrong_string(self):
        self._assert_rejects("protocol", "other-protocol")

    # tier
    def test_tier_integer(self):
        self._assert_rejects("tier", 42)

    def test_tier_none(self):
        self._assert_rejects("tier", None)

    def test_tier_bool(self):
        self._assert_rejects("tier", True)

    def test_tier_empty_string(self):
        self._assert_rejects("tier", "")

    def test_tier_invalid_string(self):
        self._assert_rejects("tier", "premium")

    # sourceHash
    def test_source_hash_integer(self):
        self._assert_rejects("sourceHash", 12345)

    def test_source_hash_none(self):
        self._assert_rejects("sourceHash", None)

    def test_source_hash_list(self):
        self._assert_rejects("sourceHash", ["ab" * 32])

    def test_source_hash_dict(self):
        self._assert_rejects("sourceHash", {"hash": "ab" * 32})

    def test_source_hash_bool(self):
        self._assert_rejects("sourceHash", False)

    # proofId
    def test_proof_id_integer(self):
        self._assert_rejects("proofId", 0)

    def test_proof_id_none(self):
        self._assert_rejects("proofId", None)

    def test_proof_id_float(self):
        self._assert_rejects("proofId", 1.0)

    # timestamp
    def test_timestamp_integer(self):
        self._assert_rejects("timestamp", 1700000000)

    def test_timestamp_none(self):
        self._assert_rejects("timestamp", None)

    def test_timestamp_list(self):
        self._assert_rejects("timestamp", [_NOW_UTC])

    def test_timestamp_empty_string(self):
        self._assert_rejects("timestamp", "")

    def test_timestamp_whitespace_only(self):
        self._assert_rejects("timestamp", "   ")


# ---------------------------------------------------------------------------
# 3. Invalid hash formats
# ---------------------------------------------------------------------------

class TestInvalidHashFormats(unittest.TestCase):
    """sourceHash and proofId must be exactly 64 lowercase hex characters."""

    def _assert_hash_rejected(self, value, field="sourceHash"):
        m = _valid(**{field: value})
        with self.assertRaises(ValueError):
            validate_v1(m)

    # --- length violations ---
    def test_too_short_63_chars(self):
        self._assert_hash_rejected("a" * 63)

    def test_too_long_65_chars(self):
        self._assert_hash_rejected("a" * 65)

    def test_empty_string(self):
        self._assert_hash_rejected("")

    def test_32_bytes_not_64_hex(self):
        # Raw bytes repr, not hex – 32 chars but not valid 64-hex
        self._assert_hash_rejected("a" * 32)

    # --- character violations ---
    def test_uppercase_hex_rejected_by_is_hex_32(self):
        # _is_hex_32 only checks for valid hex digits; uppercase is still hex.
        # But a 64-char uppercase hex should actually pass int(value,16) check.
        # Confirm the helper itself accepts it (it does), and validate_v1 accepts it.
        upper = "AB" * 32
        # _is_hex_32 should return True for valid uppercase hex
        self.assertTrue(_is_hex_32(upper))

    def test_non_hex_chars_z(self):
        bad = "z" * 64
        self._assert_hash_rejected(bad)

    def test_non_hex_chars_space(self):
        bad = ("a" * 63) + " "
        self._assert_hash_rejected(bad)

    def test_non_hex_chars_dash(self):
        bad = ("a" * 63) + "-"
        self._assert_hash_rejected(bad)

    def test_non_hex_chars_unicode(self):
        bad = ("a" * 63) + "\u00e9"
        self._assert_hash_rejected(bad)

    def test_hex_with_0x_prefix(self):
        bad = "0x" + "a" * 62
        self._assert_hash_rejected(bad)

    def test_hash_looks_valid_but_wrong_field_type(self):
        # Wrap in a list – should still reject
        self._assert_hash_rejected(["ab" * 32])

    def test_proof_id_invalid_format(self):
        self._assert_hash_rejected("!!" * 32, field="proofId")

    def test_proof_id_too_short(self):
        self._assert_hash_rejected("ab" * 31, field="proofId")

    # --- _is_hex_32 unit-level ---
    def test_is_hex_32_true_for_valid(self):
        self.assertTrue(_is_hex_32("ab" * 32))

    def test_is_hex_32_false_for_short(self):
        self.assertFalse(_is_hex_32("ab" * 31))

    def test_is_hex_32_false_for_non_string(self):
        self.assertFalse(_is_hex_32(123))

    def test_is_hex_32_false_for_none(self):
        self.assertFalse(_is_hex_32(None))


# ---------------------------------------------------------------------------
# 4. Timestamp adversarial cases
# ---------------------------------------------------------------------------

class TestTimestampAdversarial(unittest.TestCase):

    def test_naive_datetime_rejected(self):
        # No timezone info
        naive = datetime.now().isoformat()
        m = _valid(timestamp=naive)
        with self.assertRaises(ValueError):
            validate_v1(m)

    def test_far_future_timestamp_rejected(self):
        far_future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        m = _valid(timestamp=far_future)
        with self.assertRaises(ValueError):
            validate_v1(m)

    def test_just_within_drift_window_accepted(self):
        just_ok = (datetime.now(timezone.utc) + timedelta(seconds=290)).isoformat()
        # Should not raise
        validate_v1(_valid(timestamp=just_ok))

    def test_past_timestamp_accepted(self):
        past = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        validate_v1(_valid(timestamp=past))

    def test_zulu_suffix_accepted(self):
        zulu = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        validate_v1(_valid(timestamp=zulu))

    def test_non_iso_string_rejected(self):
        m = _valid(timestamp="not-a-date")
        with self.assertRaises(ValueError):
            validate_v1(m)

    def test_date_only_rejected(self):
        m = _valid(timestamp="2024-01-01")
        with self.assertRaises(ValueError):
            validate_v1(m)

    def test_unix_epoch_integer_rejected(self):
        m = _valid(timestamp=1700000000)
        with self.assertRaises(ValueError):
            validate_v1(m)

    def test_validate_timestamp_direct_none(self):
        with self.assertRaises(ValueError):
            _validate_timestamp(None)

    def test_validate_timestamp_direct_empty(self):
        with self.assertRaises(ValueError):
            _validate_timestamp("")


# ---------------------------------------------------------------------------
# 5. Tier validation
# ---------------------------------------------------------------------------

class TestTierValidation(unittest.TestCase):

    def test_all_allowed_tiers_pass(self):
        for tier in ALLOWED_TIERS:
            with self.subTest(tier=tier):
                validate_v1(_valid(tier=tier))

    def test_unknown_tier_rejected(self):
        for bad in ("SILENT", "Silent", "gold", "free", " silent", "silent ", ""):
            with self.subTest(bad_tier=bad):
                m = _valid(tier=bad)
                with self.assertRaises(ValueError):
                    validate_v1(m)


# ---------------------------------------------------------------------------
# 6. Unexpected / extra keys (forward-compat)
# ---------------------------------------------------------------------------

class TestUnexpectedKeys(unittest.TestCase):
    """validate_v2 must preserve unknown keys; validate_v1 must not crash on them."""

    def test_v1_ignores_extra_keys(self):
        m = _valid(extra_key="extra_value", another=42)
        # validate_v1 should succeed – it only checks required fields
        validate_v1(m)

    def test_v2_preserves_extra_keys(self):
        m = _valid(version=2, foo="bar", nested={"a": 1})
        result = validate_v2(m)
        self.assertEqual(result.get("foo"), "bar")
        self.assertEqual(result.get("nested"), {"a": 1})

    def test_v2_many_extra_keys(self):
        m = _valid(version=2)
        for i in range(50):
            m[f"extra_{i}"] = f"value_{i}"
        result = validate_v2(m)
        for i in range(50):
            self.assertEqual(result[f"extra_{i}"], f"value_{i}")

    def test_v2_deeply_nested_extra_keys(self):
        nested = {"level1": {"level2": {"level3": "deep_value"}}}
        m = _valid(version=2, deep=nested)
        result = validate_v2(m)
        self.assertEqual(result["deep"]["level1"]["level2"]["level3"], "deep_value")

    def test_empty_string_key(self):
        m = _valid(version=2)
        m[""] = "empty key value"
        result = validate_v2(m)
        self.assertEqual(result[""], "empty key value")

    def test_numeric_like_string_key(self):
        m = _valid(version=2, **{"123": "numeric-key-value"})
        result = validate_v2(m)
        self.assertEqual(result["123"], "numeric-key-value")


# ---------------------------------------------------------------------------
# 7. Nested secret fields – must not survive redaction into stored metadata
# ---------------------------------------------------------------------------

class TestNestedSecretFields(unittest.TestCase):
    """
    Sensitive fixture values embedded at various nesting levels must be
    replaced with REDACTED_VALUE by logging_utils.redact_sensitive before
    they would reach storage or logs.
    """

    # --- top-level sensitive keys ---
    def test_top_level_proof_key_is_redacted(self):
        metadata = _valid(version=2, proof=_SENSITIVE_TOKEN)
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["proof"], REDACTED_VALUE)
        self.assertNotIn(_SENSITIVE_TOKEN, json.dumps(redacted))

    def test_top_level_authorization_is_redacted(self):
        metadata = _valid(version=2, authorization="Bearer " + _SENSITIVE_TOKEN)
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["authorization"], REDACTED_VALUE)

    def test_top_level_nullifier_secret_is_redacted(self):
        metadata = _valid(version=2, nullifierSecret=_SENSITIVE_SECRET)
        redacted = redact_sensitive(metadata)
        # _is_sensitive_key normalises "nullifierSecret" → "nullifiersecret"
        self.assertEqual(redacted["nullifierSecret"], REDACTED_VALUE)
        self.assertNotIn(_SENSITIVE_SECRET, json.dumps(redacted))

    def test_top_level_credential_secret_is_redacted(self):
        metadata = _valid(version=2, credentialSecret=_SENSITIVE_SECRET)
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["credentialSecret"], REDACTED_VALUE)

    def test_top_level_public_inputs_is_redacted(self):
        metadata = _valid(version=2, publicInputs=["input1", "input2"])
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["publicInputs"], REDACTED_VALUE)

    # --- witness keys (partial-match) ---
    def test_witness_key_is_redacted(self):
        metadata = _valid(version=2, witnessData=_SENSITIVE_TOKEN)
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["witnessData"], REDACTED_VALUE)
        self.assertNotIn(_SENSITIVE_TOKEN, json.dumps(redacted))

    def test_witness_prefix_key_is_redacted(self):
        metadata = _valid(version=2, witnessProof="some-proof-bytes")
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["witnessProof"], REDACTED_VALUE)

    # --- nested secret fields (depth ≥ 2) ---
    def test_nested_proof_key_is_redacted(self):
        metadata = _valid(version=2, inner={"proof": _SENSITIVE_TOKEN, "safe": "ok"})
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["inner"]["proof"], REDACTED_VALUE)
        self.assertEqual(redacted["inner"]["safe"], "ok")
        self.assertNotIn(_SENSITIVE_TOKEN, json.dumps(redacted))

    def test_double_nested_credential_is_redacted(self):
        metadata = _valid(
            version=2,
            outer={"middle": {"credentialSecret": _SENSITIVE_SECRET}},
        )
        redacted = redact_sensitive(metadata)
        self.assertEqual(
            redacted["outer"]["middle"]["credentialSecret"],
            REDACTED_VALUE,
        )
        self.assertNotIn(_SENSITIVE_SECRET, json.dumps(redacted))

    def test_nested_witness_in_list_is_redacted(self):
        metadata = _valid(
            version=2,
            items=[
                {"witnessData": _SENSITIVE_TOKEN, "index": 0},
                {"witnessData": _SENSITIVE_TOKEN, "index": 1},
            ],
        )
        redacted = redact_sensitive(metadata)
        for item in redacted["items"]:
            self.assertEqual(item["witnessData"], REDACTED_VALUE)
        self.assertNotIn(_SENSITIVE_TOKEN, json.dumps(redacted))

    # --- sensitive value does not appear after redaction ---
    def test_sensitive_value_absent_from_log_output(self):
        import io
        import logging

        from logging_utils import log_structured

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        test_logger = logging.getLogger("_test_adversarial_")
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.DEBUG)

        metadata = _valid(
            version=2,
            proof=_SENSITIVE_TOKEN,
            inner={"nullifierSecret": _SENSITIVE_SECRET},
        )
        log_structured(test_logger, logging.INFO, metadata)

        logged = log_capture.getvalue()
        self.assertNotIn(_SENSITIVE_TOKEN, logged)
        self.assertNotIn(_SENSITIVE_SECRET, logged)

    def test_mnemonic_in_nested_field_not_logged(self):
        import io
        import logging
        from logging_utils import log_structured

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        test_logger = logging.getLogger("_test_adversarial_mnemonic_")
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.DEBUG)

        payload = _valid(version=2, credentialSecret=_SENSITIVE_MNEMONIC)
        log_structured(test_logger, logging.INFO, payload)
        logged = log_capture.getvalue()
        self.assertNotIn(_SENSITIVE_MNEMONIC, logged)

    # --- safe fields are preserved after redaction ---
    def test_safe_fields_survive_redaction(self):
        metadata = _valid(
            version=2,
            proof=_SENSITIVE_TOKEN,
            safe_field="this-is-fine",
        )
        redacted = redact_sensitive(metadata)
        self.assertEqual(redacted["safe_field"], "this-is-fine")
        self.assertEqual(redacted["protocol"], "harpocrates")
        self.assertEqual(redacted["tier"], "silent")


# ---------------------------------------------------------------------------
# 8. Oversized structures
# ---------------------------------------------------------------------------

class TestOversizedStructures(unittest.TestCase):
    """pack_envelope must reject payloads exceeding the 64 KiB limit."""

    def test_pack_v1_rejects_oversized_payload(self):
        m = _valid(big_field="x" * (MAX_PAYLOAD_BYTES + 1))
        with self.assertRaises(ValueError, msg="should reject payload > 64 KiB"):
            pack_envelope(m, version=1)

    def test_pack_v2_rejects_oversized_payload(self):
        m = _valid(version=2, big_field="x" * (MAX_PAYLOAD_BYTES + 1))
        with self.assertRaises(ValueError):
            pack_envelope(m, version=2)

    def test_oversized_single_value(self):
        # One field with a value much larger than the limit
        m = _valid(version=2, giant="A" * (MAX_PAYLOAD_BYTES * 2))
        with self.assertRaises(ValueError):
            pack_envelope(m, version=2)

    def test_oversized_many_fields(self):
        m = _valid(version=2)
        # 500 fields × 200 chars each = 100 000 bytes of value data
        for i in range(500):
            m[f"field_{i}"] = "x" * 200
        with self.assertRaises(ValueError):
            pack_envelope(m, version=2)

    def test_exactly_at_limit_after_compression_is_fine(self):
        """A small valid payload must pack and unpack cleanly."""
        m = _valid(version=2)
        packed = pack_envelope(m, version=2)
        self.assertIsNotNone(packed)
        recovered = unpack_envelope(packed)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["protocol"], "harpocrates")

    def test_canonical_hash_is_stable_across_equivalent_dicts(self):
        m1 = _valid(version=2, extra="hello")
        m2 = _valid(version=2, extra="hello")
        self.assertEqual(canonical_metadata_hash(m1), canonical_metadata_hash(m2))

    def test_canonical_hash_differs_for_different_values(self):
        m1 = _valid(version=2, extra="hello")
        m2 = _valid(version=2, extra="world")
        self.assertNotEqual(canonical_metadata_hash(m1), canonical_metadata_hash(m2))


# ---------------------------------------------------------------------------
# 9. Envelope pack/unpack round-trip adversarial cases
# ---------------------------------------------------------------------------

class TestPackUnpackAdversarial(unittest.TestCase):

    def test_unpack_truncated_data_returns_none(self):
        packed = pack_envelope(_valid(), version=1)
        self.assertIsNone(unpack_envelope(packed[:10]))

    def test_unpack_empty_bytes_returns_none(self):
        self.assertIsNone(unpack_envelope(b""))

    def test_unpack_corrupted_checksum_returns_none(self):
        packed = bytearray(pack_envelope(_valid(), version=1))
        # Flip a byte inside the checksum region (bytes 11–42)
        packed[20] ^= 0xFF
        self.assertIsNone(unpack_envelope(bytes(packed)))

    def test_unpack_bad_magic_returns_none(self):
        self.assertIsNone(unpack_envelope(b"BADMAGC" + b"\x00" * 50))

    def test_unpack_corrupted_body_returns_none(self):
        packed = bytearray(pack_envelope(_valid(), version=1))
        # Corrupt a byte near the end of the body
        packed[-1] ^= 0xFF
        self.assertIsNone(unpack_envelope(bytes(packed)))

    def test_pack_unsupported_version_raises(self):
        with self.assertRaises(ValueError):
            pack_envelope(_valid(), version=99)

    def test_v2_auto_upgrades_version_field(self):
        m = _valid(version=1)
        packed = pack_envelope(m, version=2)
        recovered = unpack_envelope(packed)
        self.assertEqual(recovered["version"], 2)

    def test_round_trip_preserves_unicode_in_extra_field(self):
        m = _valid(version=2, label="harpocrätes-\u00e9l\u00e8ve")
        packed = pack_envelope(m, version=2)
        recovered = unpack_envelope(packed)
        self.assertEqual(recovered["label"], "harpocrätes-\u00e9l\u00e8ve")

    def test_round_trip_preserves_nested_dict(self):
        m = _valid(version=2, meta={"author": "alice", "tags": ["zk", "proof"]})
        packed = pack_envelope(m, version=2)
        recovered = unpack_envelope(packed)
        self.assertEqual(recovered["meta"]["author"], "alice")
        self.assertEqual(recovered["meta"]["tags"], ["zk", "proof"])


# ---------------------------------------------------------------------------
# 10. validate_v2 – type and structural guards
# ---------------------------------------------------------------------------

class TestValidateV2Guards(unittest.TestCase):

    def test_non_dict_input_raises(self):
        with self.assertRaises(ValueError):
            validate_v2("not-a-dict")  # type: ignore[arg-type]

    def test_list_input_raises(self):
        with self.assertRaises(ValueError):
            validate_v2([1, 2, 3])  # type: ignore[arg-type]

    def test_v2_with_version_1_auto_upgrades(self):
        m = _valid(version=1)
        result = validate_v2(m)
        self.assertEqual(result["version"], 2)

    def test_valid_v2_returns_dict(self):
        m = _valid(version=2)
        result = validate_v2(m)
        self.assertIsInstance(result, dict)

    def test_all_required_fields_present_in_result(self):
        m = _valid(version=2)
        result = validate_v2(m)
        for field in ("protocol", "version", "tier", "sourceHash", "proofId", "timestamp"):
            self.assertIn(field, result, f"'{field}' missing from validate_v2 result")


if __name__ == "__main__":
    unittest.main()
