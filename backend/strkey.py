"""
Stellar StrKey validation.

Implements RFC 4648 base32 decoding and CRC16-XMODEM checksum verification
for Stellar account identifiers (G-addresses) and contract identifiers
(C-contract IDs).

Specification reference:
https://developers.stellar.org/docs/fundamentals-and-concepts/stellar-data-structures/accounts-and-data/account-addresses
"""
from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STELLAR_ALPHABET: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Version-byte constants (pre-shifted: type << 3)
_VERSION_BYTE_ED25519_PUBLIC: Final = 6 << 3   # G
_VERSION_BYTE_CONTRACT: Final = 2 << 3          # C

# StrKey canonical lengths
_STRKEY_ENCODED_LENGTH: Final = 56
_STRKEY_DECODED_LENGTH: Final = 35  # 1 (version) + 32 (payload) + 2 (checksum)

# CRC16-XMODEM polynomial
_CRC16_POLY: Final = 0x1021
_CRC16_INIT: Final = 0x0000
_CRC16_BIT_MASK: Final = 0xFFFF

# Pre-compute the reverse-lookup table for base32 characters (string index → 5-bit value)
_BASE32_DECODE: Final = {c: i for i, c in enumerate(_STELLAR_ALPHABET)}


# ---------------------------------------------------------------------------
# Base32 decoding
# ---------------------------------------------------------------------------

def _decode_base32(data: str) -> bytearray:
    """Decode a base32 string (no padding) into raw bytes.

    Each character encodes 5 bits.  56 characters → 280 bits → 35 bytes.
    """
    if len(data) != _STRKEY_ENCODED_LENGTH:
        raise ValueError(
            f"StrKey must be {_STRKEY_ENCODED_LENGTH} characters, got {len(data)}"
        )

    result = bytearray(_STRKEY_DECODED_LENGTH)
    bits_consumed = 0
    buffer = 0

    byte_index = 0
    for ch in data:
        value = _BASE32_DECODE.get(ch)
        if value is None:
            raise ValueError(f"invalid StrKey character: {ch!r}")

        buffer = (buffer << 5) | value
        bits_consumed += 5

        if bits_consumed >= 8:
            bits_consumed -= 8
            result[byte_index] = (buffer >> bits_consumed) & 0xFF
            byte_index += 1

    return result


# ---------------------------------------------------------------------------
# CRC16-XMODEM
# ---------------------------------------------------------------------------

def _crc16_xmodem(data: bytes | bytearray) -> int:
    """Compute CRC16-XMODEM over *data*.

    Polynomial: 0x1021, initial value: 0x0000.
    """
    crc = _CRC16_INIT
    for byte_val in data:
        crc ^= byte_val << 8
        for _ in range(8):
            crc <<= 1
            if crc & 0x10000:
                crc = (crc ^ _CRC16_POLY) & _CRC16_BIT_MASK
    return crc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_valid_strkey(value: str, expected_version_byte: int) -> bool:
    """Return True if *value* is a valid Stellar StrKey with the given version byte."""
    if not isinstance(value, str):
        return False
    if len(value) != _STRKEY_ENCODED_LENGTH:
        return False
    # Normalise to uppercase — Stellar StrKeys are case-insensitive in practice.
    normalised = value.upper()
    # Fast check: first character must match the expected type prefix
    expected_prefix = _STELLAR_ALPHABET[expected_version_byte >> 3]
    if normalised[0] != expected_prefix:
        return False
    try:
        decoded = _decode_base32(normalised)
    except ValueError:
        return False

    # Verify version byte
    version_byte = decoded[0]
    if version_byte != expected_version_byte:
        return False

    # Verify CRC16-XMODEM checksum (last 2 bytes)
    payload = decoded[:33]  # version byte + 32 payload bytes
    expected_crc = (decoded[33] << 8) | decoded[34]
    computed_crc = _crc16_xmodem(payload)
    return expected_crc == computed_crc


def validate_source_address(value: object) -> str | None:
    """Validate a Stellar G-address (account public key).

    Returns the normalized (uppercase) address if valid, ``None`` if the value
    is ``None`` (explicitly nullable field).

    Raises ``ValueError`` with a field-specific message on malformed input.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("sourceAddress must be a valid Stellar G-address")
    normalized = value.strip().upper()
    if not is_valid_strkey(normalized, _VERSION_BYTE_ED25519_PUBLIC):
        raise ValueError("sourceAddress must be a valid Stellar G-address")
    return normalized


def validate_contract_id(value: object) -> str | None:
    """Validate a Stellar C-contract ID.

    Returns the normalized (uppercase) contract ID if valid, ``None`` if the
    value is ``None`` (explicitly nullable field).

    Raises ``ValueError`` with a field-specific message on malformed input.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("contractId must be a valid Stellar C-contract ID")
    normalized = value.strip().upper()
    if not is_valid_strkey(normalized, _VERSION_BYTE_CONTRACT):
        raise ValueError("contractId must be a valid Stellar C-contract ID")
    return normalized


def make_strkey(version_byte: int, payload: bytes) -> str:
    """Encode a Stellar StrKey from a version byte and 32-byte payload.

    Used for generating valid test addresses.

    Raises ``ValueError`` if *payload* is not exactly 32 bytes.
    """
    if len(payload) != 32:
        raise ValueError(f"payload must be 32 bytes, got {len(payload)}")

    raw = bytearray([version_byte]) + bytearray(payload)
    crc = _crc16_xmodem(raw)
    raw.append((crc >> 8) & 0xFF)
    raw.append(crc & 0xFF)

    # Base32 encode without padding
    return _encode_base32(raw)


def _encode_base32(data: bytes | bytearray) -> str:
    """Encode raw bytes into a base32 string (no padding)."""
    result: list[str] = []
    bit_buffer = 0
    bits_in_buffer = 0

    for byte_val in data:
        bit_buffer = (bit_buffer << 8) | byte_val
        bits_in_buffer += 8

        while bits_in_buffer >= 5:
            bits_in_buffer -= 5
            idx = (bit_buffer >> bits_in_buffer) & 0x1F
            result.append(_STELLAR_ALPHABET[idx])

    if bits_in_buffer > 0:
        result.append(_STELLAR_ALPHABET[(bit_buffer << (5 - bits_in_buffer)) & 0x1F])

    return "".join(result)
