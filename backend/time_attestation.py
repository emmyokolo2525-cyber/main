"""
Time attestation envelope for Harpocrates evidence protocol.

Implements versioned time-attestation envelopes supporting:
- Claimed capture time (from device/user)
- Observed registration time (backend timestamp)
- Independent anchors: Stellar ledger timestamps and RFC 3161 TSA tokens

Designed to prevent backdating, detect digest substitution, and provide
graduated trust levels without breaking privacy guarantees.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from datetime import datetime, timezone

# ── Constants ──────────────────────────────────────────────────────────────

PROFILE_ID = "harpocrates-time-attestation/v1"
SUPPORTED_VERSIONS = {1}

# Maximum allowed future drift: 5 minutes (accounts for clock skew)
MAX_FUTURE_DRIFT_SECONDS = 300

# Maximum resource consumption bounds
MAX_TIMESTAMP_TOKEN_SIZE = 10_000  # 10 KB for RFC 3161 token
MAX_ANCHOR_COUNT = 10  # Maximum independent time sources per envelope

# Time source types
TimeSourceType = Literal["claimed", "observed", "stellar_ledger", "rfc3161_tsa"]

# Verification status
VerificationStatus = Literal["valid", "invalid", "unverified", "expired", "untrusted"]


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ClaimedTime:
    """Time claimed by the capture device or user."""
    
    unix_ms: int
    source_label: str  # e.g., "device_clock", "manual_entry"
    uncertainty_ms: int = 0  # Clock uncertainty estimate


@dataclass(frozen=True)
class ObservedTime:
    """Time observed by the registration backend."""
    
    unix_ms: int
    source_label: str  # e.g., "backend_ntp_synced", "backend_system_clock"


@dataclass(frozen=True)
class StellarAnchor:
    """Stellar ledger timestamp anchor."""
    
    ledger_sequence: int
    ledger_timestamp: int  # Unix seconds from Stellar ledger
    transaction_hash: str  # 64-char hex
    network_passphrase: str  # e.g., "Test SDF Network ; September 2015"


@dataclass(frozen=True)
class RFC3161Anchor:
    """RFC 3161 timestamp token anchor."""
    
    token_bytes: str  # Base64-encoded DER token
    tsa_url: str
    gen_time: int  # Unix milliseconds from parsed GeneralizedTime
    policy_oid: str | None = None
    cert_fingerprint: str | None = None  # SHA-256 of TSA signing cert
    verification_status: VerificationStatus = "unverified"
    verification_error: str | None = None


@dataclass(frozen=True)
class TimeAttestation:
    """Complete time attestation envelope."""
    
    version: int
    protocol: str
    evidence_digest: str  # 64-char hex SHA-256 of canonical evidence
    
    claimed_time: ClaimedTime | None = None
    observed_time: ObservedTime | None = None
    stellar_anchors: list[StellarAnchor] = field(default_factory=list)
    rfc3161_anchors: list[RFC3161Anchor] = field(default_factory=list)


# ── Encoding ───────────────────────────────────────────────────────────────

def encode_time_attestation(attestation: TimeAttestation) -> dict[str, Any]:
    """Encode a time attestation to canonical JSON-safe dictionary."""
    
    if attestation.version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported time attestation version: {attestation.version}")
    
    if attestation.protocol != PROFILE_ID:
        raise ValueError(f"Protocol mismatch: expected {PROFILE_ID}, got {attestation.protocol}")
    
    if not _is_valid_hex(attestation.evidence_digest, 64):
        raise ValueError("evidence_digest must be 64-character hex string")
    
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) > MAX_ANCHOR_COUNT:
        raise ValueError(f"Total anchor count exceeds maximum of {MAX_ANCHOR_COUNT}")
    
    obj: dict[str, Any] = {
        "version": attestation.version,
        "protocol": attestation.protocol,
        "evidenceDigest": attestation.evidence_digest,
    }
    
    if attestation.claimed_time:
        obj["claimedTime"] = {
            "unixMs": attestation.claimed_time.unix_ms,
            "sourceLabel": attestation.claimed_time.source_label,
            "uncertaintyMs": attestation.claimed_time.uncertainty_ms,
        }
    
    if attestation.observed_time:
        obj["observedTime"] = {
            "unixMs": attestation.observed_time.unix_ms,
            "sourceLabel": attestation.observed_time.source_label,
        }
    
    if attestation.stellar_anchors:
        obj["stellarAnchors"] = [
            {
                "ledgerSequence": anchor.ledger_sequence,
                "ledgerTimestamp": anchor.ledger_timestamp,
                "transactionHash": anchor.transaction_hash,
                "networkPassphrase": anchor.network_passphrase,
            }
            for anchor in attestation.stellar_anchors
        ]
    
    if attestation.rfc3161_anchors:
        obj["rfc3161Anchors"] = [
            {
                "tokenBytes": anchor.token_bytes,
                "tsaUrl": anchor.tsa_url,
                "genTime": anchor.gen_time,
                "policyOid": anchor.policy_oid,
                "certFingerprint": anchor.cert_fingerprint,
                "verificationStatus": anchor.verification_status,
                "verificationError": anchor.verification_error,
            }
            for anchor in attestation.rfc3161_anchors
        ]
    
    return obj


def decode_time_attestation(obj: dict[str, Any]) -> TimeAttestation:
    """Decode and validate a time attestation dictionary."""
    
    _validate_time_attestation_obj(obj)
    
    claimed_time = None
    if "claimedTime" in obj:
        ct = obj["claimedTime"]
        claimed_time = ClaimedTime(
            unix_ms=ct["unixMs"],
            source_label=ct["sourceLabel"],
            uncertainty_ms=ct.get("uncertaintyMs", 0),
        )
    
    observed_time = None
    if "observedTime" in obj:
        ot = obj["observedTime"]
        observed_time = ObservedTime(
            unix_ms=ot["unixMs"],
            source_label=ot["sourceLabel"],
        )
    
    stellar_anchors = []
    for anchor_obj in obj.get("stellarAnchors", []):
        stellar_anchors.append(
            StellarAnchor(
                ledger_sequence=anchor_obj["ledgerSequence"],
                ledger_timestamp=anchor_obj["ledgerTimestamp"],
                transaction_hash=anchor_obj["transactionHash"],
                network_passphrase=anchor_obj["networkPassphrase"],
            )
        )
    
    rfc3161_anchors = []
    for anchor_obj in obj.get("rfc3161Anchors", []):
        rfc3161_anchors.append(
            RFC3161Anchor(
                token_bytes=anchor_obj["tokenBytes"],
                tsa_url=anchor_obj["tsaUrl"],
                gen_time=anchor_obj["genTime"],
                policy_oid=anchor_obj.get("policyOid"),
                cert_fingerprint=anchor_obj.get("certFingerprint"),
                verification_status=anchor_obj.get("verificationStatus", "unverified"),
                verification_error=anchor_obj.get("verificationError"),
            )
        )
    
    return TimeAttestation(
        version=obj["version"],
        protocol=obj["protocol"],
        evidence_digest=obj["evidenceDigest"],
        claimed_time=claimed_time,
        observed_time=observed_time,
        stellar_anchors=stellar_anchors,
        rfc3161_anchors=rfc3161_anchors,
    )


def canonical_time_attestation_hash(attestation: TimeAttestation) -> str:
    """Compute the canonical SHA-256 hash of a time attestation."""
    encoded = encode_time_attestation(attestation)
    canonical = _canonical_json(encoded)
    return hashlib.sha256(canonical).hexdigest()


# ── Validation ─────────────────────────────────────────────────────────────

def validate_time_attestation(attestation: TimeAttestation, evidence_digest: str) -> list[str]:
    """
    Validate a time attestation envelope.
    
    Returns a list of validation errors. Empty list means valid.
    """
    errors: list[str] = []
    
    # Verify evidence digest binding
    if attestation.evidence_digest != evidence_digest:
        errors.append(
            f"Evidence digest mismatch: expected {evidence_digest}, "
            f"got {attestation.evidence_digest}"
        )
    
    current_time_ms = int(time.time() * 1000)
    
    # Validate claimed time
    if attestation.claimed_time:
        claimed_ms = attestation.claimed_time.unix_ms
        if claimed_ms > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"Claimed time {claimed_ms} is too far in the future "
                f"(current: {current_time_ms})"
            )
        if claimed_ms < 0:
            errors.append(f"Claimed time {claimed_ms} is negative")
    
    # Validate observed time
    if attestation.observed_time:
        observed_ms = attestation.observed_time.unix_ms
        if observed_ms > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"Observed time {observed_ms} is too far in the future "
                f"(current: {current_time_ms})"
            )
        if observed_ms < 0:
            errors.append(f"Observed time {observed_ms} is negative")
    
    # Validate Stellar anchors
    for i, anchor in enumerate(attestation.stellar_anchors):
        if not _is_valid_hex(anchor.transaction_hash, 64):
            errors.append(
                f"Stellar anchor {i}: transaction_hash must be 64-char hex"
            )
        if anchor.ledger_sequence < 0:
            errors.append(
                f"Stellar anchor {i}: ledger_sequence must be non-negative"
            )
        if anchor.ledger_timestamp < 0:
            errors.append(
                f"Stellar anchor {i}: ledger_timestamp must be non-negative"
            )
    
    # Validate RFC 3161 anchors
    for i, anchor in enumerate(attestation.rfc3161_anchors):
        if len(anchor.token_bytes) > MAX_TIMESTAMP_TOKEN_SIZE:
            errors.append(
                f"RFC 3161 anchor {i}: token exceeds {MAX_TIMESTAMP_TOKEN_SIZE} bytes"
            )
        if anchor.gen_time < 0:
            errors.append(
                f"RFC 3161 anchor {i}: genTime must be non-negative"
            )
        if anchor.gen_time > current_time_ms + (MAX_FUTURE_DRIFT_SECONDS * 1000):
            errors.append(
                f"RFC 3161 anchor {i}: genTime is too far in the future"
            )
    
    # Validate at least one time source exists
    has_time_source = (
        attestation.claimed_time is not None
        or attestation.observed_time is not None
        or attestation.stellar_anchors
        or attestation.rfc3161_anchors
    )
    if not has_time_source:
        errors.append("At least one time source is required")
    
    return errors


def check_backdating_risk(attestation: TimeAttestation) -> dict[str, Any]:
    """
    Analyze backdating risk based on available time sources.
    
    Returns a risk assessment with:
    - risk_level: "none", "low", "medium", "high"
    - reasons: list of contributing factors
    - recommendations: suggested actions
    """
    risk_level = "none"
    reasons: list[str] = []
    recommendations: list[str] = []
    
    has_independent_anchor = bool(
        attestation.stellar_anchors or attestation.rfc3161_anchors
    )
    
    if not has_independent_anchor:
        risk_level = "medium"
        reasons.append("No independent timestamp anchor (Stellar/RFC 3161)")
        recommendations.append("Add Stellar ledger timestamp from transaction")
    
    if attestation.claimed_time and attestation.observed_time:
        claimed_ms = attestation.claimed_time.unix_ms
        observed_ms = attestation.observed_time.unix_ms
        drift_seconds = abs(claimed_ms - observed_ms) / 1000
        
        if drift_seconds > 86400:  # 1 day
            if risk_level == "none":
                risk_level = "low"
            elif risk_level == "medium":
                risk_level = "high"
            reasons.append(
                f"Large drift between claimed and observed time: "
                f"{drift_seconds:.0f} seconds"
            )
        
        if claimed_ms < observed_ms - 3600000:  # Claimed > 1 hour before observed
            if risk_level in ("none", "low"):
                risk_level = "medium"
            elif risk_level == "medium":
                risk_level = "high"
            reasons.append("Claimed time significantly predates observed time")
    
    if not attestation.observed_time:
        if risk_level == "none":
            risk_level = "low"
        reasons.append("No observed registration time recorded")
    
    if not reasons:
        reasons.append("All time sources align within acceptable bounds")
    
    if not recommendations:
        recommendations.append("Time attestation appears robust")
    
    return {
        "risk_level": risk_level,
        "reasons": reasons,
        "recommendations": recommendations,
    }


# ── Factory functions ──────────────────────────────────────────────────────

def create_time_attestation(
    evidence_digest: str,
    claimed_time_ms: int | None = None,
    claimed_source_label: str = "device_clock",
    uncertainty_ms: int = 0,
) -> TimeAttestation:
    """
    Create a new time attestation with observed time.
    
    Automatically captures the current backend time as observed_time.
    Stellar and RFC 3161 anchors should be added separately after
    transaction confirmation or TSA response.
    """
    if not _is_valid_hex(evidence_digest, 64):
        raise ValueError("evidence_digest must be 64-character hex string")
    
    observed_ms = int(time.time() * 1000)
    
    claimed_time = None
    if claimed_time_ms is not None:
        claimed_time = ClaimedTime(
            unix_ms=claimed_time_ms,
            source_label=claimed_source_label,
            uncertainty_ms=uncertainty_ms,
        )
    
    observed_time = ObservedTime(
        unix_ms=observed_ms,
        source_label="backend_system_clock",
    )
    
    return TimeAttestation(
        version=1,
        protocol=PROFILE_ID,
        evidence_digest=evidence_digest,
        claimed_time=claimed_time,
        observed_time=observed_time,
    )


def add_stellar_anchor(
    attestation: TimeAttestation,
    ledger_sequence: int,
    ledger_timestamp: int,
    transaction_hash: str,
    network_passphrase: str,
) -> TimeAttestation:
    """Add a Stellar ledger timestamp anchor to an existing attestation."""
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) >= MAX_ANCHOR_COUNT:
        raise ValueError(f"Maximum anchor count ({MAX_ANCHOR_COUNT}) reached")
    
    if not _is_valid_hex(transaction_hash, 64):
        raise ValueError("transaction_hash must be 64-character hex string")
    
    new_anchor = StellarAnchor(
        ledger_sequence=ledger_sequence,
        ledger_timestamp=ledger_timestamp,
        transaction_hash=transaction_hash,
        network_passphrase=network_passphrase,
    )
    
    return TimeAttestation(
        version=attestation.version,
        protocol=attestation.protocol,
        evidence_digest=attestation.evidence_digest,
        claimed_time=attestation.claimed_time,
        observed_time=attestation.observed_time,
        stellar_anchors=[*attestation.stellar_anchors, new_anchor],
        rfc3161_anchors=attestation.rfc3161_anchors,
    )


def add_rfc3161_anchor(
    attestation: TimeAttestation,
    token_bytes: str,
    tsa_url: str,
    gen_time: int,
    policy_oid: str | None = None,
    cert_fingerprint: str | None = None,
    verification_status: VerificationStatus = "unverified",
    verification_error: str | None = None,
) -> TimeAttestation:
    """Add an RFC 3161 timestamp token anchor to an existing attestation."""
    if len(attestation.stellar_anchors) + len(attestation.rfc3161_anchors) >= MAX_ANCHOR_COUNT:
        raise ValueError(f"Maximum anchor count ({MAX_ANCHOR_COUNT}) reached")
    
    if len(token_bytes) > MAX_TIMESTAMP_TOKEN_SIZE:
        raise ValueError(f"Timestamp token exceeds {MAX_TIMESTAMP_TOKEN_SIZE} bytes")
    
    new_anchor = RFC3161Anchor(
        token_bytes=token_bytes,
        tsa_url=tsa_url,
        gen_time=gen_time,
        policy_oid=policy_oid,
        cert_fingerprint=cert_fingerprint,
        verification_status=verification_status,
        verification_error=verification_error,
    )
    
    return TimeAttestation(
        version=attestation.version,
        protocol=attestation.protocol,
        evidence_digest=attestation.evidence_digest,
        claimed_time=attestation.claimed_time,
        observed_time=attestation.observed_time,
        stellar_anchors=attestation.stellar_anchors,
        rfc3161_anchors=[*attestation.rfc3161_anchors, new_anchor],
    )


# ── Internal helpers ───────────────────────────────────────────────────────

def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Encode dictionary to canonical JSON bytes."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_valid_hex(value: str, expected_length: int) -> bool:
    """Check if value is a valid hex string of expected length."""
    if len(value) != expected_length:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _validate_time_attestation_obj(obj: dict[str, Any]) -> None:
    """Validate structure of time attestation dictionary."""
    if not isinstance(obj, dict):
        raise TypeError("Time attestation must be a dictionary")
    
    required_fields = ["version", "protocol", "evidenceDigest"]
    for field in required_fields:
        if field not in obj:
            raise ValueError(f"Missing required field: {field}")
    
    if obj["version"] not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported version: {obj['version']}")
    
    if obj["protocol"] != PROFILE_ID:
        raise ValueError(f"Protocol mismatch: expected {PROFILE_ID}, got {obj['protocol']}")
    
    if not isinstance(obj["evidenceDigest"], str):
        raise TypeError("evidenceDigest must be a string")
    
    if not _is_valid_hex(obj["evidenceDigest"], 64):
        raise ValueError("evidenceDigest must be 64-character hex string")
