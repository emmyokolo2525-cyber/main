# Lineage Implementation

## Overview

The Harpocrates lineage feature enables representing cropped, transcoded, blurred, redacted, or composed media as verifiable derivatives of registered evidence.

## Supported Operations

- **crop**: Extract a specific region from the original media
- **transcode**: Convert media to a different format or codec
- **blur**: Apply blur transformation to obscure portions
- **redact**: Redact sensitive information from media
- **compose**: Combine multiple media sources into one derivative

## Architecture

### Frontend (`frontend/src/lineageManifest.ts`)

The frontend defines the `TransformationManifest` type which captures:
- `protocol`: Always "harpocrates"
- `version`: Manifest version (currently 2)
- `parentProofIds`: Array of parent proof IDs (up to 4)
- `operationType`: Type of transformation applied
- `parametersDigest`: SHA-256 digest of transformation parameters
- `toolIdentity`: Identity of the tool that performed transformation
- `toolVersion`: Version of the transformation tool
- `outputDigest`: SHA-256 digest of the resulting derivative
- `network`: Network identifier (e.g., "testnet")
- `actorAddress`: Stellar address of the actor performing the transformation

### Backend (`backend/lineage.py`)

The backend provides:
- **Manifest normalization**: `canonical_lineage_manifest()` - produces deterministic JSON serialization
- **Manifest digesting**: `lineage_manifest_digest()` - computes SHA-256 hash of canonical manifest
- **Graph validation**: `validate_lineage_graph()` - enforces constraints:
  - Depth limit: Maximum 4 levels deep
  - Fan-out limit: Maximum 4 parents per derivative
  - Cycle detection: Prevents self-referential and transitive cycles
  - Actor validation: Requires non-empty actor address

### Backend API Endpoints

#### Register Lineage
```
POST /api/proofs/lineage
Content-Type: application/json

{
  "parentProofIds": ["hash1", "hash2"],
  "operationType": "crop",
  "parametersDigest": "...",
  "toolIdentity": "harpocrates-studio",
  "toolVersion": "1.2.3",
  "outputDigest": "...",
  "network": "testnet",
  "actorAddress": "GABC123"
}

Response: 201 Created
{
  "ok": true,
  "manifestDigest": "...",
  "db_event": {...}
}
```

#### List Lineage Events
```
GET /api/proofs/lineage?limit=25
Response: 200 OK
{
  "ok": true,
  "events": [...]
}
```

#### Query Lineage by Actor
```
GET /api/lineage/by-actor/<actor_address>?limit=25
Response: 200 OK
{
  "ok": true,
  "events": [...]
}
```

### Database Schema

#### lineage_events table
```sql
CREATE TABLE lineage_events (
  id BIGSERIAL PRIMARY KEY,
  manifest_digest TEXT NOT NULL UNIQUE,
  manifest JSONB NOT NULL,
  actor_address TEXT NOT NULL,
  parent_proof_ids TEXT[] NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX lineage_events_actor_idx ON lineage_events (actor_address);
```

### Soroban Contract (`contracts/contracts/harpocrates-registry/src/lib.rs`)

The contract provides:
- `register_lineage()` - Records a lineage transformation on-chain
- `get_lineage()` - Retrieves a stored lineage record
- Validates bounded depth, fan-out, and payload size on-chain

## Validation Rules

### Constraints Enforced
1. **Duplicate Prevention**: Identical output digest submissions fail with 409 Conflict
2. **Cycle Detection**: 
   - Direct cycles (output digest appears in parents) are rejected
   - Transitive cycles (output would create circular dependency) are rejected
3. **Bounded Depth**: Maximum 4 levels of transformation chain
4. **Bounded Fan-out**: Maximum 4 parent proofs per derivative
5. **Payload Size**: Maximum 4KB for manifest
6. **Actor Requirement**: Every transformation must have an authorized actor address
7. **Hex Validation**: All IDs must be valid 32-byte hex strings

### Success Criteria
- Lineage records survive database re-indexing from contract events
- Concurrent submissions are handled idempotently
- Partial backend failures don't corrupt lineage state
- Privacy boundaries are maintained (no exposure of private evidence)

## Testing

### Backend Tests (`backend/test_lineage.py`)
- Canonical manifest serialization (deterministic)
- Unsupported operation rejection
- Excessive fan-out rejection
- Direct cycle detection
- Missing actor validation
- Valid graph acceptance

### Frontend Tests (`frontend/src/lineageManifest.test.ts`)
- Manifest creation with deterministic serialization
- Operation type validation
- Type safety

### App Tests (`backend/test_app.py`)
- All existing tests continue to pass
- Lineage endpoint validation

## Migration Considerations

- No breaking changes to existing proof or metadata schemas
- lineage_events table is additive and doesn't require existing data migration
- Existing lint, type checks, tests, and builds remain green

## Privacy and Security

- Lineage records are bound to actor addresses (immutable)
- Manifest hashes are deterministic and reproducible
- No transformation parameters or sensitive evidence details are exposed in lineage queries
- All operations are logged with correlation IDs for auditability

## Future Work

- Live production deployment testing
- Contract event indexing and re-indexing from Testnet
- Dashboard visualization of lineage chains
- Advanced query support (reverse lineage, transitive closure)
