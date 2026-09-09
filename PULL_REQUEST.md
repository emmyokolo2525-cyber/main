# Bounded Aggregation of Silent Witness Proofs

## Summary

Implements bounded aggregation of multiple Silent Witness proofs into a single verifiable UltraHonk statement. A prover can bundle up to **8** video hashes under the same credential identity and produce one compact proof, reducing on-chain verification costs by up to 8× for batch submissions.

Closes # (issue number)

## Motivation

Harpocrates handles privacy-sensitive media, proof material, Stellar transactions, and on-chain verification. This change is production-grade: secure by default, bounded under hostile inputs, observable without leaking evidence or witnesses, and recoverable across partial failures.

## What Changed

### New: `silent_witness_aggregator` Noir Circuit (`zk/noir/silent_witness_aggregator/`)

- Bounded batch circuit accepting exactly **8** elements (1–8 meaningful, rest zero-padded)
- Verifies all `credential_root` values match (same identity across batch)
- Verifies per-element nullifiers bind to `(credential_secret, nullifier_secret, video_hash_hi, video_hash_lo)`
- `MAX_AGGREGATION_SIZE = 8` enforced at circuit level
- Comprehensive test corpus: positive full batch, edge cases (zero/max secrets, all-zero hashes), negative cases (mismatched roots, wrong nullifiers, swapped fields, replay)
- Versioned domain isolation via `AGGREGATION_DOMAIN_SEPARATOR`

### New: `silent_witness_aggregator_helper` Noir Circuit (`zk/noir/silent_witness_aggregator_helper/`)

- Derives batch public inputs (credential_root, nullifiers) from private secrets and video hashes
- Mirrors the `silent_witness_helper` pattern for aggregation flow

### New Build + Generation Scripts (`zk/noir/scripts/`)

- `build-silent-witness-aggregator.sh` – compile, prove, write_vk, and verify the aggregator circuit
- `generate-silent-witness-aggregator.sh` – generate aggregated proofs for 1–8 video hashes

### Updated: Soroban Registry Contract (`contracts/contracts/harpocrates-registry/src/lib.rs`)

- **`register_batch_verified`** – new entry point for batch registration:
  - Accepts `batch_id`, `metadata_hash`, aggregated `public_inputs`, aggregated `proof`, and `video_hashes` vector
  - Validates domain separator matches `AGGREGATION_DOMAIN_SEPARATOR` (version binding)
  - Verifies the aggregated UltraHonk proof through the configured external verifier
  - Validates credential root is active and identical across all elements
  - Checks per-element nullifier uniqueness (no replay)
  - Checks per-video hash uniqueness
  - Persists all elements atomically after full pre-validation
  - Derives deterministic sub-proof_ids for each element
- **`AGGREGATION_DOMAIN_SEPARATOR`** – versioned domain tag `"HARPOCRATES_AGG_V1"`
- **`parse_aggregated_public_inputs`** – parses 32 + (batch_size × 128) byte layout efficiently (no large stack allocation)
- **`derive_element_proof_id`** – deterministic sub-proof_id derivation with full 32-byte XOR spread
- **`ProofRecord.batch_size`** – new field tracking batch membership (0 = individual)
- New error types: `BatchSizeExceeded` (14), `BatchCredentialRootMismatch` (15), `BatchCountMismatch` (16)

### New: Contract Tests (`contracts/contracts/harpocrates-registry/src/test_aggregation.rs`)

- Happy path: 3-element batch registers all elements successfully
- Empty batch rejected (`BatchSizeExceeded`)
- Oversized batch (9 elements) rejected (`BatchSizeExceeded`)
- Mismatched credential roots rejected (`BatchCredentialRootMismatch`)
- No verifier configured rejected (`VerifierNotSet`)
- Unknown credential root rejected (`UnknownCredentialRoot`)
- Wrong domain separator rejected (`InvalidPublicInputs`)
- Duplicate nullifier rejected (`DuplicateNullifier`)
- Public input length mismatch rejected (`InvalidPublicInputs`)
- Verifier rejects proof → registration fails (`InvalidProof`)
- MAX_AGGREGATION_SIZE (8) batch succeeds

### Updated: Backend (`backend/`)

- `noir.py` – added `generate_aggregated_proof()` function
- `app.py` – added `POST /api/noir/silent-witness/aggregate` endpoint:
  - Accepts `videoHashes` array (1–8), `credentialSecret`, `nullifierSecret`
  - Bounded input validation with size checking
  - Privacy-safe logging (batch size logged, secrets redacted)

### Updated: Frontend (`frontend/src/noirClient.ts`)

- Added `generateAggregatedProof()` function
- Loads aggregator circuits (`silent_witness_aggregator.json`, `silent_witness_aggregator_helper.json`)
- Derives batch public inputs via helper, then generates single UltraHonk proof
- Returns typed `AggregatedProof` with batch metadata

### Updated: Documentation

- `zk/noir/README.md` – aggregator circuit section with properties and build instructions
- `contracts/VERIFIER_INTEGRATION.md` – batch aggregation section with public input layout and semantics

### New: Test Vectors (`zk/noir/fixtures/aggregation_vectors.json`)

- Deterministic fixture data for batch of 8 elements
- Zero-credential-secret edge case fixture

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **MAX_AGGREGATION_SIZE = 8** | Balances circuit size with practical batching; 8 public inputs × 128 bytes = 1024 bytes per batch |
| **Explicit unrolled verification** (not loops) | Noir circuit constraints must be bounded at compile time; unrolled per-element verification eliminates dynamic iteration |
| **Pre-validation then persist** | Two-phase approach prevents partial writes; all checks pass before any write |
| **XOR-based sub-proof_id** | Deterministic, cheap, and collision-resistant within batch; full 32-byte spread with index-dependent mask |
| **Same-identity binding** | All credential roots must match; prevents cross-identity aggregation attacks |
| **Per-element nullifiers** | Individual video proofs cannot be replayed outside batch context |
| **Versioned domain separator** | Prevents cross-version proof replay; both circuit and contract check it |

## Security Properties

1. **Soundness**: Prover cannot forge aggregate proof without knowing secrets for every video
2. **Binding**: All credential roots identical; prevents cross-identity bundling
3. **Bounded work**: Exactly 8 elements; oversized/undersized inputs rejected
4. **Domain isolation**: `AGGREGATION_DOMAIN_SEPARATOR != REVOCATION_DOMAIN_SEPARATOR` prevents cross-circuit replay
5. **Nullifier consumption**: Each element gets its own consumed nullifier; no single-video replay

## Rollout

1. **Compatibility**: Backward compatible; `ProofRecord.batch_size` defaults to 0 for existing records
2. **Migration**: No data migration needed; new contract deployment required to add `register_batch_verified`
3. **Rollback**: Revert to previous contract deployment; batch registration fails but individual registration continues working

## Out of Scope

- Real user evidence or production secrets
- Live mainnet deployment
- Browser-side aggregator circuit generation (requires compiled WASM artifacts)
- Unrelated visual redesign or dependency upgrades

## Dependencies

- Noir 1.0.0-beta.9+ and Barretenberg 0.87.0+ for circuit compilation/proving
- `rs-soroban-ultrahonk` verifier contract for on-chain UltraHonk verification
- Soroban SDK 25.x for registry contract compilation

## Testing

```bash
# Noir circuit tests (requires nargo)
cd zk/noir/silent_witness_aggregator
nargo test

# Contract tests (requires cargo)
cd contracts
cargo test

# Backend tests (requires python)
cd backend
python -m pytest
```
