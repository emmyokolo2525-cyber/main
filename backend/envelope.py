import hashlib
import json
import struct
import zlib
from typing import Any
from datetime import datetime, timezone, timedelta

MAGIC_V1 = b"HRPSTG1"
MAGIC_V2 = b"HRPSTG2"
MAX_PAYLOAD_BYTES = 64 * 1024
ALLOWED_TIERS = {"silent", "source", "seal"}


def canonical_metadata_hash(metadata: dict[str, Any]) -> str:
    """Returns the canonical deterministic hash for any supported metadata."""
    return hashlib.sha256(_canonical_json(metadata)).hexdigest()


def _canonical_json(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_hex_32(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("metadata timestamp must be a string")
    ts = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        raise ValueError("metadata timestamp must be a timezone-aware ISO-8601 string")
    if dt.tzinfo is None:
        raise ValueError("metadata timestamp must be timezone-aware")
    if dt > datetime.now(timezone.utc) + timedelta(seconds=300):
        raise ValueError("metadata timestamp is unreasonably far in the future")


def validate_v1(metadata: dict[str, Any]) -> None:
    required = {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}
    missing = required - set(metadata.keys())
    if missing:
        raise ValueError(f"metadata missing required field: {sorted(missing)[0]}")
    if metadata.get("protocol") != "harpocrates":
        raise ValueError("metadata protocol must be harpocrates")
    if metadata.get("tier") not in ALLOWED_TIERS:
        raise ValueError("metadata tier is invalid")
    if not _is_hex_32(metadata.get("sourceHash")):
        raise ValueError("metadata sourceHash must be a 32-byte hex string")
    if not _is_hex_32(metadata.get("proofId")):
        raise ValueError("metadata proofId must be a 32-byte hex string")
    _validate_timestamp(metadata.get("timestamp"))


def validate_v2(metadata: dict[str, Any]) -> dict[str, Any]:
    # v2 enforces similar constraints but allows forward compatibility (stripping unknown fields or maintaining them)
    # Actually, to make it canonical and safe, we can enforce strict schema or pass through.
    # The requirement is "unknown-field behavior". Let's preserve unknown fields in V2 for forward compat.
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    
    # Require same base fields
    validate_v1(metadata)
    
    # version in V2 must be >= 2
    if metadata.get("version", 1) < 2:
        # Auto-upgrade the version field if it's migrating
        metadata["version"] = 2
        
    return metadata


def pack_envelope(metadata: dict[str, Any], version: int = 2) -> bytes:
    if version == 1:
        validate_v1(metadata)
        magic = MAGIC_V1
    elif version == 2:
        metadata = validate_v2(dict(metadata))  # Copy and validate/upgrade
        magic = MAGIC_V2
    else:
        raise ValueError(f"unsupported metadata version {version}")

    body = zlib.compress(_canonical_json(metadata), level=9)
    if len(body) > MAX_PAYLOAD_BYTES:
        raise ValueError("metadata payload exceeds the 64 KiB steganography limit")

    checksum = hashlib.sha256(body).digest()
    return magic + struct.pack(">I", len(body)) + checksum + body


def unpack_envelope(data: bytes) -> dict[str, Any] | None:
    if len(data) < 7 + 4 + 32:
        return None

    magic = data[:7]
    if magic not in (MAGIC_V1, MAGIC_V2):
        return None

    size = struct.unpack(">I", data[7:11])[0]
    if size > MAX_PAYLOAD_BYTES:
        return None

    checksum_start = 11
    body_start = 43
    body_end = body_start + size
    if len(data) < body_end:
        return None

    checksum = data[checksum_start:body_start]
    body = data[body_start:body_end]
    if hashlib.sha256(body).digest() != checksum:
        return None

    try:
        value = json.loads(zlib.decompress(body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, zlib.error):
        return None

    if not isinstance(value, dict):
        return None
        
    try:
        # Validate based on the magic bytes to ensure safety
        if magic == MAGIC_V1:
            validate_v1(value)
            # Auto-migrate v1 to v2 representation in-memory?
            # Issue says: "preserve... unless versioned migration is included."
            # We can upgrade it on extraction so the rest of the system deals with V2 shape if needed, 
            # or just leave it as is. We'll just leave it and let the system handle it.
        elif magic == MAGIC_V2:
            value = validate_v2(value)
    except ValueError:
        return None

    return value
