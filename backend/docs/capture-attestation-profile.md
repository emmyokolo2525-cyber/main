# Harpocrates Capture-Device Attestation Profile

**Version:** 1.0.0-draft
**Status:** Proposed
**Date:** 2026-07-26

## 1. Overview

This document defines a platform-neutral profile for binding optional
capture-session attestation to evidence without exposing a stable device
identifier. The profile is designed to be layered on top of the existing
Harpocrates metadata envelope and proof-manifest conventions.

## 2. Design Principles

1. **Privacy-first:** No raw device serial, advertising ID, account
   identity, or location is ever required.
2. **Per-session identifiers:** Scoped to a single capture session or
   relying-party interaction. Not linkable across sessions.
3. **Graceful degradation:** Unknown platforms and unavailable attestation
   remain interoperable. The absence of attestation is explicit rather
   than silently ignored.
4. **Deterministic verification:** All encodings are canonical and
   versioned so verifiers can reproduce byte-identical digests.
5. **No parallel truth sources:** Attestation data flows through the
   existing metadata manifest, proof, and Soroban contract boundaries.

## 3. Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | `unattested` | No device attestation was performed. |
| 1 | `software_attested` | Application-level assertion only (e.g., signed by the app). |
| 2 | `hardware_backed` | Hardware-backed key attestation (Android KeyStore, iOS Secure Enclave, TPM). |
| 3 | `rooted_or_emulated` | Platform indicates rooting, jailbreaking, or emulation. |
| 4 | `unverifiable` | Attestation was attempted but could not be verified. |

## 4. Canonical Attestation Object

### 4.1 Schema

```json
{
  "attestation": {
    "version": 1,
    "profile": "harpocrates-capture-attestation/v1",
    "trustLevel": 2,
    "captureNonce": "32-byte-hex",
    "appIdentity": {
      "packageName": "com.example.camera",
      "versionCode": "42",
      "buildFingerprint": "optional-platform-build-fingerprint",
      "signingDigest": "sha256-hex-of-signing-cert"
    },
    "secureTime": {
      "unixMs": 1721971200000,
      "source": "hardware_clock",
      "driftMs": 150
    },
    "cameraPipeline": {
      "sensorOrientation": 90,
      "hasWatermark": false,
      "claimedIntegrity": "raw_sensor"
    },
    "deviceCommitment": "32-byte-hex",
    "privacyScope": "per_session",
    "evidenceDigestBinding": "32-byte-hex",
    "platformClaims": {}
  }
}
```

### 4.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Schema version (1). |
| `profile` | string | Yes | Fixed value `harpocrates-capture-attestation/v1`. |
| `trustLevel` | integer | Yes | 0–4 per the trust-level table above. |
| `captureNonce` | hex32 | Yes | Server-provided random nonce, single-use per capture. |
| `appIdentity` | object | Yes | Application and build identity claims. |
| `appIdentity.packageName` | string | Yes | Reverse-domain app identifier. |
| `appIdentity.versionCode` | string | Yes | App version/build code. |
| `appIdentity.buildFingerprint` | string | No | Platform build fingerprint (optional). |
| `appIdentity.signingDigest` | hex32 | No | SHA-256 of the app signing certificate. |
| `secureTime` | object | No | Independently verifiable time evidence. |
| `secureTime.unixMs` | integer | Yes | Unix timestamp in milliseconds. |
| `secureTime.source` | string | Yes | `hardware_clock`, `ntp_synchronized`, `platform_clock`. |
| `secureTime.driftMs` | integer | Yes | Estimated drift from ground truth in ms. |
| `cameraPipeline` | object | No | Claims about the camera capture pipeline. |
| `cameraPipeline.sensorOrientation` | integer | No | EXIF orientation value (1-8). |
| `cameraPipeline.hasWatermark` | boolean | No | Whether a visible watermark was applied. |
| `cameraPipeline.claimedIntegrity` | string | No | `raw_sensor`, `processed`, `screen_capture`, `unknown`. |
| `deviceCommitment` | hex32 | Yes | HMAC-SHA256(nonce, perSessionDeviceKey). |
| `privacyScope` | string | Yes | `per_session`, `per_relying_party`, `per_device_group`. |
| `evidenceDigestBinding` | hex32 | Yes | SHA-256 of the evidence payload this attestation describes. |
| `platformClaims` | object | No | Platform-specific transparent claims (e.g. SafetyNet/Play Integrity raw JWTs). |

### 4.3 Canonical Encoding

The attestation object is serialised using the same canonical JSON
convention used throughout Harpocrates:

```
JSON.stringify(attestation, sortedKeys, noWhitespace).encode('utf-8')
```

The canonical hash is then:

```
SHA-256(canonical_bytes)
```

## 5. Integration Points

### 5.1 Metadata Envelope

The attestation object is included as an **optional** `attestation` field
in the Harpocrates metadata envelope embedded in video files:

```json
{
  "protocol": "harpocrates",
  "version": 1,
  "tier": "source",
  "sourceHash": "...",
  "proofId": "...",
  "timestamp": "2026-07-24T12:00:00.000Z",
  "attestation": {
    "version": 1,
    "profile": "harpocrates-capture-attestation/v1",
    "trustLevel": 2,
    ...
  }
}
```

The canonical metadata hash (used for on-chain registration) covers
the entire metadata including the attestation sub-object, so tampering
with attestation data is detectable on-chain.

### 5.2 Proof Manifest

The attestation status is reflected in the proof manifest as an
informational field:

```json
{
  "contractId": "...",
  "metadataHash": "...",
  "network": "...",
  "proofId": "...",
  "protocol": "harpocrates",
  "sourceHash": "...",
  "tier": "...",
  "timestamp": "...",
  "transactionRef": "...",
  "version": 1,
  "videoHash": "...",
  "attestationTrustLevel": 2
}
```

### 5.3 CLI and SDK

The `@harpocrates/cli` package includes attestation validation utilities
that verify the attestation binding against the evidence digest.

### 5.4 Soroban Contract

No on-chain changes are required. The attestation is fully verified
off-chain and its integrity is covered by the metadata hash that is
already stored in the contract's proof records.

## 6. Threat Model

### 6.1 Adversarial Capabilities

| Threat | Mitigation |
|--------|------------|
| Replay attack (reuse attestation for different evidence) | `evidenceDigestBinding` ties attestation to a specific piece of evidence. |
| Cloned attestation (copy from another device) | `captureNonce` is single-use, server-provided. |
| Stale nonce (reuse old nonce) | Server enforces nonce expiry; `secureTime` provides freshness evidence. |
| Cross-scope correlation | `privacyScope` limits linkability; per-session keys prevent long-term tracking. |
| Downgrade attack (strip attestation) | Absence of attestation results in `unattested` level; verifier policy decides acceptance. |
| Wrong evidence digest | `evidenceDigestBinding` must match the SHA-256 of the actual evidence. |
| Unknown platform | Handled gracefully; `trustLevel: 4` (`unverifiable`). |

### 6.2 Platform Trust Assumptions

- **Hardware-backed (Level 2):** Trusts the device's hardware key store
  and the platform's attestation API (Android KeyStore, iOS Secure Enclave).
- **Software-attested (Level 1):** Trusts the application's signing key
  and the integrity of the app binary.
- **Unattested (Level 0):** No trust assumptions. The verifier must
  evaluate evidence on its own merits.

## 7. Test Vectors

Reference implementations and test vectors are maintained in:

- `backend/test_capture_attestation.py` — Python reference implementation.
- `cli/test/capture-attestation.test.ts` — Node.js test vectors.

## 8. Migration and Compatibility

- **Versioning:** The `profile` string includes a `/v1` suffix. Future
  versions will use `/v2`, etc.
- **Backward compatibility:** V1 verifiers MUST reject unknown profile
  versions. Adding new optional fields to the same version is allowed.
- **Schema changes:** Require bumping the `version` number in the
  attestation object.

## 9. Out of Scope

- Live production deployment of attestation capture.
- Mobile app implementation (this is a protocol specification).
- Real credentials or sensitive media.
- Integration with specific hardware attestation SDKs.
