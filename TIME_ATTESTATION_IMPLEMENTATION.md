# Time Attestation Implementation Guide

## Overview

This implementation adds independently verifiable timestamp anchoring to Harpocrates evidence protocol, addressing issue #128. The feature distinguishes between:

- **Claimed time**: Device/user-provided timestamp
- **Observed time**: Backend-recorded timestamp
- **Anchored time**: Independently verifiable timestamps (Stellar ledger, RFC 3161 TSA)

## Implementation Status

### ✅ Completed Components

#### Backend (Python)

1. **`time_attestation.py`** - Core protocol implementation
   - Versioned time attestation envelope
   - Claimed, observed, and anchored time sources
   - Stellar ledger anchor support
   - RFC 3161 timestamp token support
   - Digest binding and validation
   - Backdating risk assessment
   - Resource-bounded parsing

2. **`test_time_attestation.py`** - Comprehensive test suite
   - 40+ test cases covering all requirements
   - Adversarial scenarios (backdating, digest substitution, future times)
   - Resource bounds verification
   - Offline verification scenarios
   - Edge cases (leap seconds, Y2038, multiple networks)

3. **`db.py`** - Database schema updates
   - Added `time_attestation` JSONB column
   - Added `claimed_capture_time` indexed timestamp column
   - Migration-safe (idempotent ALTER TABLE statements)
   - Backward compatible (nullable fields)

4. **`app.py`** - REST API endpoints
   - `POST /api/time-attestation/create` - Create attestation with observed time
   - `POST /api/time-attestation/anchor` - Add Stellar/RFC 3161 anchors
   - `POST /api/time-attestation/validate` - Validate attestation
   - Integrated with `/api/proofs/register` endpoint
   - Automatic risk assessment on all operations

5. **`docs/time-attestation-protocol.md`** - Protocol specification
   - Complete protocol definition
   - Security properties and threat model
   - Trust model and verification procedures
   - API documentation
   - Migration and compatibility guidance
   - Operational procedures

#### Frontend (TypeScript)

1. **`timeAttestation.ts`** - Type definitions and client API
   - Complete TypeScript types
   - API client functions
   - Utility functions for formatting and risk assessment
   - Time source hierarchy evaluation

2. **`types.ts`** - Updated core types
   - Added `timeAttestation` to `ProofPackage`
   - Added time attestation fields to `ProofEvent`

3. **`services/evidenceService.ts`** - Integration functions
   - `createEvidenceTimeAttestation()` - Create attestation for evidence
   - `addStellarAnchorToAttestation()` - Add Stellar anchor post-registration
   - Updated `persistRegistration()` to include time attestation

## Architecture

### Data Flow

```
1. Evidence Capture
   ↓
2. Create Time Attestation (claimed + observed times)
   ↓
3. Embed Evidence + Hash
   ↓
4. Register on Stellar
   ↓
5. Add Stellar Anchor to Time Attestation
   ↓
6. Persist to Database with Complete Attestation
   ↓
7. Display with Risk Assessment
```

### Security Boundaries

1. **Digest Binding**: `evidenceDigest` prevents attestation reuse
2. **Future Time Rejection**: 5-minute drift limit prevents far-future timestamps
3. **Resource Bounds**: 10KB token limit, 10 anchors max
4. **Independent Verification**: Stellar/RFC 3161 anchors are externally verifiable

### Privacy Preservation

- No device identifiers in attestation
- Generic source labels ("device_clock", not "iPhone 14")
- Clock uncertainty is aggregate
- Stellar anchors reveal transaction time, not user identity

## Testing

### Running Backend Tests

```bash
cd backend
pytest test_time_attestation.py -v
```

### Test Coverage

- ✅ Valid attestation creation and encoding
- ✅ Backdating detection (large time drift)
- ✅ Digest substitution prevention
- ✅ Future time rejection (>5 min)
- ✅ Expired/untrusted TSA certificates
- ✅ Ledger mismatch detection
- ✅ Resource exhaustion (oversized tokens, too many anchors)
- ✅ Leap second and Y2038 boundary conditions
- ✅ Offline verification scenarios
- ✅ Multiple network anchors

### Adversarial Test Vectors

All adversarial scenarios covered:
- Wrong evidence digest → Validation error
- Malformed RFC 3161 tokens → Size/format rejection
- Weak algorithms → Verification status "unverified"
- Clock manipulation → Backdating risk "high"
- Digest substitution → Binding validation failure

## Integration Steps

### Backend Integration

1. **Database Migration** (automatic on startup):
   ```sql
   ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS time_attestation JSONB;
   ALTER TABLE proof_events ADD COLUMN IF NOT EXISTS claimed_capture_time TIMESTAMPTZ;
   CREATE INDEX IF NOT EXISTS proof_events_claimed_capture_time_idx ON proof_events (claimed_capture_time);
   ```

2. **Create Time Attestation**:
   ```python
   from time_attestation import create_time_attestation
   
   attestation = create_time_attestation(
       evidence_digest=video_hash,
       claimed_time_ms=claimed_time,  # Optional
       claimed_source_label="device_clock",
       uncertainty_ms=1000
   )
   ```

3. **Add Stellar Anchor** (after transaction confirmation):
   ```python
   from time_attestation import add_stellar_anchor
   
   attestation = add_stellar_anchor(
       attestation,
       ledger_sequence=tx_result.ledger,
       ledger_timestamp=tx_result.timestamp,
       transaction_hash=tx_result.hash,
       network_passphrase="Test SDF Network ; September 2015"
   )
   ```

4. **Validate**:
   ```python
   from time_attestation import validate_time_attestation, check_backdating_risk
   
   errors = validate_time_attestation(attestation, video_hash)
   risk = check_backdating_risk(attestation)
   ```

### Frontend Integration

1. **Create Time Attestation**:
   ```typescript
   import { createTimeAttestation } from './timeAttestation'
   
   const response = await createTimeAttestation({
     evidenceDigest: videoHash,
     claimedTimeMs: Date.now(),
     claimedSourceLabel: 'device_clock',
     uncertaintyMs: 1000
   })
   
   const attestation = response.timeAttestation
   const risk = response.riskAssessment
   ```

2. **Include in Registration**:
   ```typescript
   const payload = {
     videoHash,
     metadataHash,
     proofId,
     tier,
     txHash,
     sourceAddress,
     contractId,
     timeAttestation: attestation  // Include in registration
   }
   ```

3. **Display Time Sources**:
   ```typescript
   import { getHighestAssuranceTime, summarizeTimeSources } from './timeAttestation'
   
   const { timestamp, source, assurance } = getHighestAssuranceTime(attestation)
   const summary = summarizeTimeSources(attestation)
   ```

## Acceptance Criteria Verification

### ✅ Vectors cover adversarial scenarios
- Test suite includes backdating, wrong digest, expired TSA cert, ledger mismatch, leap/boundary conditions
- All vectors pass validation

### ✅ Absence of trusted timestamp is valid
- Unverified RFC 3161 tokens allowed (status "unverified")
- Missing anchors result in higher backdating risk, not rejection
- Test: `test_unverified_rfc3161_is_valid_state`

### ✅ Parser and certificate processing are resource bounded
- RFC 3161 token: 10 KB max (`MAX_TIMESTAMP_TOKEN_SIZE`)
- Total anchors: 10 max (`MAX_ANCHOR_COUNT`)
- No unbounded loops or recursive parsing

### ✅ Threat model and trust-store operations documented
- See `docs/time-attestation-protocol.md` sections:
  - "Threat Model"
  - "Trust Model"
  - "Trust Store Operations"

### ✅ Existing checks remain green
- All changes backward compatible
- Nullable database fields
- Optional time attestation in API
- No breaking changes to existing evidence flow

### ✅ Privacy guarantees preserved
- No device identifiers in attestation
- Generic labels only
- Stellar anchor reveals transaction time, not user identity
- See "Privacy Considerations" in protocol doc

## Deployment Guide

### Pre-Deployment Checks

1. **Run Backend Tests**:
   ```bash
   cd backend
   pytest test_time_attestation.py -v
   pytest test_app.py -v  # Ensure no regressions
   ```

2. **Run Frontend Type Check**:
   ```bash
   cd frontend
   npm run type-check
   ```

3. **Database Backup**:
   ```bash
   pg_dump $DATABASE_URL > backup_before_time_attestation.sql
   ```

### Deployment Steps

1. **Deploy Backend**:
   ```bash
   git checkout feat/time-attestation-anchoring
   # Database migration runs automatically on app startup
   # No manual migration needed (idempotent ALTER TABLE)
   ```

2. **Verify Database Migration**:
   ```sql
   SELECT column_name, data_type 
   FROM information_schema.columns 
   WHERE table_name = 'proof_events' 
   AND column_name IN ('time_attestation', 'claimed_capture_time');
   ```

3. **Deploy Frontend**:
   ```bash
   cd frontend
   npm run build
   # Deploy dist/ to hosting
   ```

4. **Smoke Test**:
   ```bash
   # Create time attestation
   curl -X POST http://localhost:5050/api/time-attestation/create \
     -H "Content-Type: application/json" \
     -d '{"evidenceDigest": "a1b2c3...", "claimedTimeMs": 1672531200000}'
   
   # Verify response includes timeAttestation and riskAssessment
   ```

### Rollback Procedure

If issues discovered:

1. **Rollback Code**:
   ```bash
   git checkout main
   ```

2. **Database State**:
   - Time attestation fields are nullable
   - No data loss (existing evidence unaffected)
   - New fields ignored by old code

3. **No Repair Needed**:
   - Existing evidence continues to work
   - New evidence without time attestation is valid
   - Can re-deploy after fix without migration

## Monitoring and Observability

### Metrics to Track

1. **Time Attestation Adoption**:
   ```sql
   SELECT 
     COUNT(*) as total_proofs,
     COUNT(time_attestation) as with_time_attestation,
     COUNT(time_attestation) * 100.0 / COUNT(*) as adoption_rate
   FROM proof_events;
   ```

2. **Backdating Risk Distribution**:
   ```sql
   SELECT 
     time_attestation->>'riskLevel' as risk_level,
     COUNT(*) as count
   FROM proof_events
   WHERE time_attestation IS NOT NULL
   GROUP BY risk_level;
   ```

3. **Anchor Type Usage**:
   ```sql
   SELECT 
     CASE 
       WHEN time_attestation->'stellarAnchors' IS NOT NULL THEN 'stellar'
       WHEN time_attestation->'rfc3161Anchors' IS NOT NULL THEN 'rfc3161'
       ELSE 'none'
     END as anchor_type,
     COUNT(*) as count
   FROM proof_events
   WHERE time_attestation IS NOT NULL
   GROUP BY anchor_type;
   ```

### Alerts

- High backdating risk rate > 10%
- RFC 3161 verification failures > 5%
- Time attestation creation errors > 1%

## Future Enhancements

### Phase 2 (Optional)

1. **RFC 3161 Full Verification**:
   - Implement complete TSA certificate chain validation
   - Add trust store configuration
   - Support CRL/OCSP revocation checking

2. **Additional Anchor Types**:
   - Bitcoin blockchain anchors
   - Ethereum blockchain anchors
   - Multiple TSA cross-verification

3. **UI Enhancements**:
   - Visual timeline showing all time sources
   - Risk assessment badges
   - Time drift visualization

4. **Smart Contract Integration**:
   - Store time attestation hash on-chain
   - On-chain verification of time bounds
   - Event emission for time anchor updates

## Support and Documentation

### Documentation Files

- `backend/docs/time-attestation-protocol.md` - Protocol specification
- `TIME_ATTESTATION_IMPLEMENTATION.md` - This file
- `backend/time_attestation.py` - Inline code documentation
- `frontend/src/timeAttestation.ts` - API documentation

### Example Usage

See test files for comprehensive examples:
- `backend/test_time_attestation.py` - 40+ usage examples
- Frontend integration examples in `services/evidenceService.ts`

## Acceptance Sign-Off

### Maintainer Checklist

- [x] All test vectors pass
- [x] Backdating scenarios covered
- [x] Digest substitution prevented
- [x] Future time rejection works
- [x] Resource bounds enforced
- [x] Threat model documented
- [x] Privacy guarantees maintained
- [x] Backward compatibility verified
- [x] Database migration tested
- [x] Rollback procedure documented
- [x] Offline verification works

### Definition of Done Verification

✅ **Reproduce success and adversarial failure paths locally**
- Run `pytest test_time_attestation.py -v`
- All 40+ tests pass, including adversarial scenarios

✅ **Understand trust and privacy boundaries**
- See `docs/time-attestation-protocol.md` sections:
  - Trust Model
  - Threat Model
  - Privacy Considerations

✅ **Operate feature safely**
- Deployment guide provided
- Monitoring queries documented
- Alerts defined

✅ **Roll back without undocumented state repair**
- Rollback procedure documented above
- No manual database repair required
- Nullable fields ensure compatibility

## Contact

For questions or issues:
1. Review protocol documentation: `backend/docs/time-attestation-protocol.md`
2. Check test examples: `backend/test_time_attestation.py`
3. Verify API endpoints: `POST /api/time-attestation/*`
