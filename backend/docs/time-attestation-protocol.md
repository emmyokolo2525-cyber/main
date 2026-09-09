# Time Attestation Protocol for Harpocrates

## Overview

The time attestation protocol provides independently verifiable timestamp evidence for Harpocrates evidence packages. It distinguishes between:

1. **Claimed time** - timestamp provided by the capture device or user
2. **Observed time** - timestamp recorded by the registration backend
3. **Anchored time** - independently verifiable timestamps from:
   - Stellar ledger (transaction inclusion time)
   - RFC 3161 Timestamp Authorities (TSA)

## Protocol Specification

### Profile Identifier
```
harpocrates-time-attestation/v1
```

### Version
Current version: `1`

### Canonical Encoding

Time attestations use deterministic JSON encoding with alphabetically sorted keys and no whitespace:

```json
{
  "version": 1,
  "protocol": "harpocrates-time-attestation/v1",
  "evidenceDigest": "a1b2c3...",
  "claimedTime": {
    "unixMs": 1672531200000,
    "sourceLabel": "device_clock",
    "uncertaintyMs": 500
  },
  "observedTime": {
    "unixMs": 1672531205000,
    "sourceLabel": "backend_ntp_synced"
  },
  "stellarAnchors": [{
    "ledgerSequence": 12345,
    "ledgerTimestamp": 1672531200,
    "transactionHash": "abc123...",
    "networkPassphrase": "Test SDF Network ; September 2015"
  }],
  "rfc3161Anchors": [{
    "tokenBytes": "base64encodedtoken==",
    "tsaUrl": "https://freetsa.org/tsr",
    "genTime": 1672531200000,
    "policyOid": "1.2.3.4.5",
    "certFingerprint": "d4e5f6...",
    "verificationStatus": "valid",
    "verificationError": null
  }]
}
```

## Security Properties

### Digest Binding

Every time attestation is cryptographically bound to a specific evidence package via `evidenceDigest`:

```
evidenceDigest = SHA-256(canonical_evidence_payload)
```

This prevents:
- **Digest substitution**: attestation cannot be reused for different evidence
- **Replay attacks**: attestation is specific to one evidence package

### Backdating Prevention

Multiple time sources with different trust levels:

1. **Claimed time only** - Low assurance (user-controlled)
2. **Claimed + Observed** - Medium assurance (backend verification)
3. **Claimed + Observed + Stellar** - High assurance (blockchain anchor)
4. **Claimed + Observed + RFC 3161** - High assurance (TSA anchor)
5. **Multiple anchors** - Highest assurance (cross-verification)

### Future Time Rejection

Times more than 5 minutes in the future (accounting for clock skew) are rejected:

```
MAX_FUTURE_DRIFT_SECONDS = 300
```

### Resource Bounds

- Maximum timestamp token size: 10 KB (RFC 3161)
- Maximum anchor count per attestation: 10
- Bounded parsing and validation time

## Trust Model

### Trust Levels (Increasing Assurance)

1. **No independent anchor** - Rely on claimed/observed times only
2. **Stellar ledger anchor** - Trust Stellar network consensus
3. **RFC 3161 TSA anchor** - Trust specific Timestamp Authority
4. **Multiple independent anchors** - Cross-verify multiple sources

### Threat Model

**In scope:**
- Backdating attempts by malicious users
- Clock manipulation on capture devices
- Digest substitution attacks
- Resource exhaustion via oversized tokens

**Out of scope:**
- Compromise of Stellar validator majority
- Compromise of TSA private keys
- GPS spoofing (device-level attacks)
- Network-level time manipulation (NTP attacks)

### Trust Store Operations

For RFC 3161 verification:
- TSA certificates must be validated against a configured trust store
- Certificate revocation status should be checked (CRL/OCSP)
- Expired certificates invalidate the timestamp
- Self-signed or untrusted certificates result in "unverified" status

**Note:** Unverified RFC 3161 timestamps are valid protocol states but provide lower assurance.

## API Endpoints

### Create Time Attestation

```http
POST /api/time-attestation/create
Content-Type: application/json

{
  "evidenceDigest": "a1b2c3...",
  "claimedTimeMs": 1672531200000,
  "claimedSourceLabel": "device_clock",
  "uncertaintyMs": 500
}
```

Response:
```json
{
  "ok": true,
  "timeAttestation": { /* encoded attestation */ },
  "riskAssessment": {
    "risk_level": "medium",
    "reasons": ["No independent timestamp anchor"],
    "recommendations": ["Add Stellar ledger timestamp"]
  }
}
```

### Add Anchors

```http
POST /api/time-attestation/anchor
Content-Type: application/json

{
  "timeAttestation": { /* existing attestation */ },
  "stellarAnchor": {
    "ledgerSequence": 12345,
    "ledgerTimestamp": 1672531200,
    "transactionHash": "abc123...",
    "networkPassphrase": "Test SDF Network ; September 2015"
  }
}
```

### Validate Time Attestation

```http
POST /api/time-attestation/validate
Content-Type: application/json

{
  "evidenceDigest": "a1b2c3...",
  "timeAttestation": { /* attestation to validate */ }
}
```

Response:
```json
{
  "ok": true,
  "errors": [],
  "riskAssessment": {
    "risk_level": "none",
    "reasons": ["All time sources align within acceptable bounds"],
    "recommendations": ["Time attestation appears robust"]
  }
}
```

## Integration with Evidence Registration

Time attestations are included in the evidence registration payload:

```http
POST /api/proofs/register
Content-Type: application/json

{
  "videoHash": "...",
  "metadataHash": "...",
  "proofId": "...",
  "tier": "silent",
  "txHash": "...",
  "sourceAddress": "...",
  "contractId": "...",
  "timeAttestation": { /* time attestation envelope */ }
}
```

The backend:
1. Validates the time attestation
2. Verifies digest binding
3. Extracts `claimedTime` for database indexing
4. Stores complete attestation as JSONB
5. Automatically adds Stellar anchor from transaction

## Stellar Anchor Integration

When evidence is registered on Stellar:

1. Transaction is confirmed on ledger
2. Backend retrieves ledger sequence and timestamp
3. Stellar anchor is added to time attestation
4. Updated attestation is stored in database

```python
from time_attestation import add_stellar_anchor

# After Stellar transaction confirmation
attestation = add_stellar_anchor(
    attestation,
    ledger_sequence=tx_result.ledger_sequence,
    ledger_timestamp=tx_result.ledger_timestamp,
    transaction_hash=tx_result.hash,
    network_passphrase="Test SDF Network ; September 2015"
)
```

## RFC 3161 Timestamp Tokens

### Obtaining a Timestamp Token

1. Generate timestamp request with evidence digest
2. Send request to RFC 3161 TSA
3. Receive and validate timestamp token
4. Add token to time attestation

Example TSA endpoints:
- FreeTSA: `https://freetsa.org/tsr`
- DigiCert: `http://timestamp.digicert.com`

### Token Verification

Verification requires:
- Parsing DER-encoded TimeStampToken
- Validating TSA signature against certificate
- Checking certificate chain to trusted root
- Verifying message imprint matches evidence digest
- Checking policy OID is acceptable

**Note:** Full RFC 3161 verification is complex and should use established libraries (e.g., `cryptography`, `pyasn1`).

## Offline Verification

Time attestations support offline verification:

1. Parse attestation from stored JSONB
2. Verify digest binding locally
3. Check Stellar anchor against local ledger archive
4. Verify RFC 3161 token with local trust store
5. Assess backdating risk based on time source alignment

No live network access required for verification.

## Migration and Compatibility

### Backward Compatibility

- Time attestation fields are optional in database
- Existing evidence without time attestations remains valid
- Frontend gracefully handles missing time attestation data

### Forward Compatibility

- Version field supports protocol evolution
- New anchor types can be added without breaking existing verifiers
- Unknown fields are preserved during encoding/decoding

### Database Migration

```sql
-- Add time attestation fields (idempotent)
ALTER TABLE proof_events 
ADD COLUMN IF NOT EXISTS time_attestation JSONB;

ALTER TABLE proof_events 
ADD COLUMN IF NOT EXISTS claimed_capture_time TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS proof_events_claimed_capture_time_idx
ON proof_events (claimed_capture_time);
```

## Privacy Considerations

Time attestations preserve Harpocrates privacy guarantees:

- No device identifiers in attestation
- Clock uncertainty is aggregate, not per-device
- Source labels are generic ("device_clock", not "iPhone 14 Pro")
- Stellar anchors reveal transaction time, not user identity
- RFC 3161 tokens reveal TSA used, not user identity

## Testing

### Test Vectors

Comprehensive test coverage includes:

- Valid attestation creation and encoding
- Backdating attempts with large time drift
- Digest substitution prevention
- Future time rejection (>5 min drift)
- Expired/untrusted TSA certificates
- Ledger mismatch detection
- Leap second and Y2038 boundary conditions
- Offline verification scenarios
- Resource exhaustion attempts

### Adversarial Scenarios

- Wrong evidence digest
- Malformed RFC 3161 tokens
- Weak cryptographic algorithms
- Clock manipulation attempts
- Concurrent anchor updates
- Replay attacks across evidence packages

## Operational Guidance

### Recommended Configuration

1. **Always capture observed time** - Provides baseline verification
2. **Add Stellar anchor on-chain registration** - Automatic, high assurance
3. **Optionally add RFC 3161 for critical evidence** - Strongest assurance
4. **Monitor backdating risk assessments** - Alert on high-risk patterns

### Safe Failure Behavior

- Missing time attestation → Evidence valid, lower assurance
- Unverified RFC 3161 token → Evidence valid, note verification failure
- Failed Stellar anchor lookup → Evidence valid, manual verification required
- Clock uncertainty high → Evidence valid, increased backdating risk

### Rollback Procedure

If issues discovered:

1. Time attestation fields are nullable - no data loss
2. Remove time attestation validation from registration
3. Frontend continues displaying basic timestamps
4. Investigate and fix issue
5. Re-enable validation
6. No evidence package repair required

## References

- RFC 3161: Time-Stamp Protocol (TSP)
- Stellar Protocol: Ledger timestamps
- ISO 8601: Date and time format
- NIST SP 800-102: Recommendation for Digital Signature Timeliness

## Version History

- **v1** (2024): Initial protocol specification
  - Claimed, observed, and anchored time sources
  - Stellar and RFC 3161 anchor support
  - Backdating risk assessment
  - Privacy-preserving design
