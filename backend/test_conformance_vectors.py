"""Cross-layer verifier conformance runner (Python side, codec ``hpx-vi/1``).

Drives the shared corpus in ``zk/vectors/verifier_conformance_v1.json`` through
``backend.verifier_inputs``. The Rust runner
(``contracts/contracts/harpocrates-registry/src/test_conformance.rs``) and the
TypeScript runner (``frontend/src/verifierInputs.conformance.test.ts``) drive
the same file, so a divergence in any layer fails exactly one of the three
suites and names the offending case id.

See docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier_inputs import (
    BN254_SCALAR_FIELD_MODULUS,
    CODEC_ID,
    MAX_PROOF_BYTES,
    MIN_PROOF_BYTES,
    PUBLIC_INPUTS_LEN,
    REVOCATION_DOMAIN_SEPARATOR,
    RejectCode,
    VerifierInputError,
    classify,
    decode_hex,
    parse_public_inputs,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1] / "zk" / "vectors" / "verifier_conformance_v1.json"
)

CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES = CORPUS["cases"]


def case_id(case: dict) -> str:
    return case["id"]


# ── Corpus integrity ────────────────────────────────────────────────────────


def test_corpus_is_versioned_and_matches_this_codec():
    assert CORPUS["format"] == "harpocrates.verifier-conformance"
    assert CORPUS["version"] == 1
    assert CORPUS["codec"] == CODEC_ID


def test_corpus_constants_match_implementation_constants():
    constants = CORPUS["constants"]
    assert constants["public_inputs_len"] == PUBLIC_INPUTS_LEN
    assert constants["min_proof_bytes"] == MIN_PROOF_BYTES
    assert constants["max_proof_bytes"] == MAX_PROOF_BYTES
    assert int(constants["bn254_scalar_field_modulus_hex"], 16) == BN254_SCALAR_FIELD_MODULUS
    assert (
        bytes.fromhex(constants["revocation_domain_separator_hex"])
        == REVOCATION_DOMAIN_SEPARATOR
    )


def test_corpus_has_positive_and_negative_cases():
    assert len(CASES) >= 20
    assert any(case["expect"]["accept"] for case in CASES)
    assert any(not case["expect"]["accept"] for case in CASES)


def test_case_ids_are_unique():
    identifiers = [case["id"] for case in CASES]
    assert len(identifiers) == len(set(identifiers))


def test_every_reject_code_is_declared():
    declared = set(CORPUS["reject_codes"])
    assert declared <= {code.value for code in RejectCode}
    for case in CASES:
        code = case["expect"]["reject_code"]
        if code is not None:
            assert code in declared, f"{case['id']} uses an undeclared reject code"


def test_every_declared_reject_code_is_reachable_or_layer_specific():
    """Codes with no case must be justified: only ``unknown_schema`` is
    exercised outside the corpus (schema dispatch is not a wire input)."""
    exercised = {
        case["expect"]["reject_code"] for case in CASES if case["expect"]["reject_code"]
    }
    unexercised = set(CORPUS["reject_codes"]) - exercised
    assert unexercised <= {"malformed_hex"}


# ── The corpus itself ───────────────────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_conformance_case(case: dict):
    expected = case["expect"]["reject_code"] if not case["expect"]["accept"] else None
    actual = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert actual == expected, (
        f"{case['id']}: expected {expected!r}, got {actual!r} — "
        f"{case['description']}"
    )


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_conformance_case_is_deterministic(case: dict):
    """The same bytes must classify identically on repeat evaluation."""
    first = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    second = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert first == second


# ── Boundary behaviour not expressible as a corpus case ─────────────────────


def test_unknown_schema_is_rejected():
    valid = next(case for case in CASES if case["expect"]["accept"])
    assert (
        classify("silent_witness/v2", valid["public_inputs_hex"], valid["proof_hex"])
        == "unknown_schema"
    )


@pytest.mark.parametrize(
    "value",
    ["0", "0x00", "zz" * 64, "00 11", "00\n11"],
)
def test_malformed_hex_is_rejected(value: str):
    with pytest.raises(VerifierInputError) as excinfo:
        decode_hex(value, field="public_inputs")
    assert excinfo.value.code is RejectCode.MALFORMED_HEX


def test_error_signal_never_carries_input_material():
    """Rejections are safe to log: the payload names a field, never bytes."""
    valid = next(case for case in CASES if case["expect"]["accept"])
    tampered = "ff" * 32 + valid["public_inputs_hex"][64:]

    with pytest.raises(VerifierInputError) as excinfo:
        parse_public_inputs(valid["schema"], decode_hex(tampered))

    signal = excinfo.value.signal()
    rendered = json.dumps(signal)
    assert signal["codec"] == CODEC_ID
    assert tampered not in rendered
    assert "ff" * 8 not in rendered
    assert set(signal) <= {"codec", "reject_code", "field"}
