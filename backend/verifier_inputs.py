"""Canonical verifier-input codec for Harpocrates (codec ``hpx-vi/1``).

This module is the Python side of a three-way codec that must agree byte for
byte with:

    frontend/src/verifierInputs.ts                       (browser / TypeScript)
    contracts/contracts/harpocrates-registry/src/lib.rs  (Soroban / Rust)

Agreement is enforced by the shared corpus in
``zk/vectors/verifier_conformance_v1.json``; see docs/zk-conformance-vectors.md.

Design rules
------------
* **Bounded.** Every entry point rejects oversized material *before* allocating
  a decoded buffer, so hostile inputs cannot drive memory use.
* **Deterministic.** Validation runs in a fixed order and returns the first
  failing :class:`RejectCode`. The same bytes always produce the same code on
  every layer.
* **Silent.** Errors carry a stable machine code and a field *name* only. No
  witness material, proof bytes, or public-input bytes ever reach the message,
  so the error is safe to log and safe to return to a caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Final

CODEC_ID: Final[str] = "hpx-vi/1"

FIELD_LEN: Final[int] = 32
SILENT_WITNESS_FIELD_COUNT: Final[int] = 5
REVOCATION_FIELD_COUNT: Final[int] = 4
SILENT_WITNESS_PUBLIC_INPUTS_LEN: Final[int] = FIELD_LEN * SILENT_WITNESS_FIELD_COUNT  # 160
REVOCATION_PUBLIC_INPUTS_LEN: Final[int] = FIELD_LEN * REVOCATION_FIELD_COUNT          # 128
PUBLIC_INPUTS_LEN: Final[int] = SILENT_WITNESS_PUBLIC_INPUTS_LEN  # default (largest schema)

MIN_PROOF_BYTES: Final[int] = 64
MAX_PROOF_BYTES: Final[int] = 65_536

#: Hard ceiling on accepted hex input length. Anything longer is rejected on the
#: string itself, before any decoding, so a hostile caller cannot force a large
#: allocation just to be told the value is too big.
MAX_HEX_CHARS: Final[int] = 2 * (MAX_PROOF_BYTES + 1_024)

#: BN254 scalar field modulus. A 32-byte big-endian encoding is canonical only
#: when the value it denotes is strictly below this.
BN254_SCALAR_FIELD_MODULUS: Final[int] = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

#: Byte-for-byte identical to ``REVOCATION_DOMAIN_SEPARATOR`` in the Soroban
#: registry: seven bytes of BN254 padding followed by 25 ASCII bytes.
REVOCATION_DOMAIN_SEPARATOR: Final[bytes] = (b"\x00" * 7) + b"HARPOCRATES_REVOCATION_V1"

# Domain constants that must be byte-identical to the Noir circuit globals.
DOMAIN_PROTOCOL_FIELD: Final[bytes] = bytes.fromhex(
    "261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201"
)
DOMAIN_VERSION_FIELD: Final[bytes] = bytes.fromhex(
    "0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623"
)
DOMAIN_NETWORK_FIELD: Final[bytes] = bytes.fromhex(
    "2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f"
)

#: SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD)
#: Mirrors the Soroban contract's expected_domain_tag() implementation.
SILENT_WITNESS_DOMAIN_TAG: Final[bytes] = hashlib.sha256(
    DOMAIN_PROTOCOL_FIELD + DOMAIN_VERSION_FIELD + DOMAIN_NETWORK_FIELD
).digest()

SCHEMA_SILENT_WITNESS: Final[str] = "silent_witness/v1"
SCHEMA_REVOCATION_WITNESS: Final[str] = "revocation_witness/v1"

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")


class RejectCode(str, Enum):
    """Stable rejection codes shared across circuit, backend, browser, chain."""

    MALFORMED_HEX = "malformed_hex"
    LENGTH = "length"
    PADDING = "padding"
    NON_CANONICAL_FIELD = "non_canonical_field"
    ZERO_FIELD = "zero_field"
    DOMAIN_MISMATCH = "domain_mismatch"
    PROOF_UNDERSIZE = "proof_undersize"
    PROOF_OVERSIZE = "proof_oversize"
    UNKNOWN_SCHEMA = "unknown_schema"


class VerifierInputError(ValueError):
    """Raised for any rejected verifier input.

    Carries the machine-readable :class:`RejectCode` and, where meaningful, the
    *name* of the offending field. Never carries field contents.
    """

    def __init__(self, code: RejectCode, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code.value}" if field is None else f"{code.value}:{field}")

    def signal(self) -> dict[str, str]:
        """Privacy-safe structured payload for logs and metrics."""
        payload = {"codec": CODEC_ID, "reject_code": self.code.value}
        if self.field is not None:
            payload["field"] = self.field
        return payload


@dataclass(frozen=True)
class SilentWitnessInputs:
    """Parsed ``silent_witness/v1`` public inputs."""

    video_hash: bytes
    credential_root: bytes
    nullifier: bytes
    domain_tag: bytes


@dataclass(frozen=True)
class RevocationWitnessInputs:
    """Parsed ``revocation_witness/v1`` public inputs."""

    revocation_root: bytes
    nullifier: bytes
    domain_separator: bytes
    credential_root: bytes


# ── Primitives ──────────────────────────────────────────────────────────────


def decode_hex(
    value: str,
    *,
    field: str = "value",
    oversize_code: RejectCode = RejectCode.PROOF_OVERSIZE,
) -> bytes:
    """Decode an even-length, bounded hex string.

    Rejects odd lengths, non-hex characters, and anything past
    :data:`MAX_HEX_CHARS` without decoding it.
    """
    if not isinstance(value, str):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    if len(value) > MAX_HEX_CHARS:
        raise VerifierInputError(oversize_code, field)
    if len(value) % 2 != 0:
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    if any(character not in _HEX_DIGITS for character in value):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - guarded above
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field) from exc


def is_canonical_field(element: bytes) -> bool:
    """Is this 32-byte big-endian encoding strictly below the BN254 modulus?"""
    return (
        len(element) == FIELD_LEN
        and int.from_bytes(element, "big") < BN254_SCALAR_FIELD_MODULUS
    )


def check_proof_bounds(proof: bytes) -> None:
    """Enforce the accepted proof-blob size window."""
    if len(proof) < MIN_PROOF_BYTES:
        raise VerifierInputError(RejectCode.PROOF_UNDERSIZE, "proof")
    if len(proof) > MAX_PROOF_BYTES:
        raise VerifierInputError(RejectCode.PROOF_OVERSIZE, "proof")


def _split_fields(public_inputs: bytes, expected_len: int, count: int) -> list[bytes]:
    if len(public_inputs) != expected_len:
        raise VerifierInputError(RejectCode.LENGTH, "public_inputs")
    return [
        public_inputs[index * FIELD_LEN : (index + 1) * FIELD_LEN]
        for index in range(count)
    ]


def _require_canonical(fields: list[bytes], names: tuple[str, ...]) -> None:
    for element, name in zip(fields, names):
        if not is_canonical_field(element):
            raise VerifierInputError(RejectCode.NON_CANONICAL_FIELD, name)


def _require_non_zero(field_value: bytes, name: str) -> None:
    if field_value == b"\x00" * FIELD_LEN:
        raise VerifierInputError(RejectCode.ZERO_FIELD, name)


def _require_half_padding(field_value: bytes, name: str) -> bytes:
    """A 128-bit half is carried in the low 16 bytes; the high 16 must be zero."""
    if field_value[:16] != b"\x00" * 16:
        raise VerifierInputError(RejectCode.PADDING, name)
    return field_value[16:]


# ── Schema parsers ──────────────────────────────────────────────────────────

_SILENT_WITNESS_FIELDS: Final[tuple[str, ...]] = (
    "video_hash_hi",
    "video_hash_lo",
    "credential_root",
    "nullifier",
    "domain_tag",
)

_REVOCATION_FIELDS: Final[tuple[str, ...]] = (
    "revocation_root",
    "nullifier",
    "domain_separator",
    "credential_root",
)


def parse_silent_witness_inputs(public_inputs: bytes) -> SilentWitnessInputs:
    """Parse ``silent_witness/v1`` public inputs in canonical check order.

    Layout (5 × 32 bytes = 160 bytes):
      [0] video_hash_hi  — 128-bit half (low 16 bytes only)
      [1] video_hash_lo  — 128-bit half (low 16 bytes only)
      [2] credential_root
      [3] nullifier
      [4] domain_tag     — SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD)
    """
    fields = _split_fields(
        public_inputs, SILENT_WITNESS_PUBLIC_INPUTS_LEN, SILENT_WITNESS_FIELD_COUNT
    )

    high = _require_half_padding(fields[0], "video_hash_hi")
    low = _require_half_padding(fields[1], "video_hash_lo")

    _require_canonical(fields, _SILENT_WITNESS_FIELDS)

    _require_non_zero(fields[2], "credential_root")
    _require_non_zero(fields[3], "nullifier")
    _require_non_zero(fields[4], "domain_tag")

    if fields[4] != SILENT_WITNESS_DOMAIN_TAG:
        raise VerifierInputError(RejectCode.DOMAIN_MISMATCH, "domain_tag")

    return SilentWitnessInputs(
        video_hash=high + low,
        credential_root=fields[2],
        nullifier=fields[3],
        domain_tag=fields[4],
    )


def parse_revocation_witness_inputs(public_inputs: bytes) -> RevocationWitnessInputs:
    """Parse ``revocation_witness/v1`` public inputs in canonical check order."""
    fields = _split_fields(
        public_inputs, REVOCATION_PUBLIC_INPUTS_LEN, REVOCATION_FIELD_COUNT
    )

    _require_canonical(fields, _REVOCATION_FIELDS)

    _require_non_zero(fields[0], "revocation_root")
    _require_non_zero(fields[1], "nullifier")
    _require_non_zero(fields[3], "credential_root")

    if fields[2] != REVOCATION_DOMAIN_SEPARATOR:
        raise VerifierInputError(RejectCode.DOMAIN_MISMATCH, "domain_separator")

    return RevocationWitnessInputs(
        revocation_root=fields[0],
        nullifier=fields[1],
        domain_separator=fields[2],
        credential_root=fields[3],
    )


def parse_public_inputs(
    schema: str, public_inputs: bytes
) -> SilentWitnessInputs | RevocationWitnessInputs:
    """Dispatch to the parser for ``schema``."""
    if schema == SCHEMA_SILENT_WITNESS:
        return parse_silent_witness_inputs(public_inputs)
    if schema == SCHEMA_REVOCATION_WITNESS:
        return parse_revocation_witness_inputs(public_inputs)
    raise VerifierInputError(RejectCode.UNKNOWN_SCHEMA, "schema")


# ── Conformance entry point ─────────────────────────────────────────────────


def classify(schema: str, public_inputs_hex: str, proof_hex: str) -> str | None:
    """Classify one conformance case.

    Returns ``None`` when the material is accepted, otherwise the stable
    reject-code string. The check order — public inputs first, then the proof
    blob — is part of the codec contract and is mirrored by every layer.
    """
    try:
        public_inputs = decode_hex(
            public_inputs_hex,
            field="public_inputs",
            oversize_code=RejectCode.LENGTH,
        )
        parse_public_inputs(schema, public_inputs)
        proof = decode_hex(proof_hex, field="proof")
        check_proof_bounds(proof)
    except VerifierInputError as error:
        return error.code.value
    return None
