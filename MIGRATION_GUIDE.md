# Scoped Nullifier Migration and Rollout Guide

**Version:** 2.0  
**Date:** 2026-07-26  
**Status:** Active

---

## 1. Overview

This guide covers the migration from the legacy (v1) nullifier derivation to the scoped nullifier v2 derivation.  It is intended for maintainers and operators of Harpocrates registry contracts and verifier contracts.

---

## 2. What Changed

### 2.1 New Features

- **Scoped nullifier derivation** — nullifiers are now bound to a verifier/purpose scope and a bounded epoch, reducing cross-context correlation.
- **Epoch management** — the registry admin can advance the epoch for each scope, enabling time-bound nullifier validity.
- **Domain separator versioning** — the `SCOPED_NULLIFIER_V1` domain separator prevents proof replay across protocol versions.
- **Backward-compatible public input parsing** — the contract automatically detects v1 (128-byte) vs v2 (192-byte) public inputs.

### 2.2 What Stayed the Same

- v1 proofs continue to work unchanged
- The `register_anonymous` stub path is unchanged
- The `register_source` and `register_seal` paths are unchanged
- The revocation witness circuit is unchanged
- The credential root derivation is unchanged
- The nullifier consumption model (global set) is unchanged

---

## 3. Migration Steps

### 3.1 Prerequisites

- Soroban CLI installed and configured
- Admin keypair for the existing registry contract
- New verifier contract compiled with v2 support (192-byte public inputs)

### 3.2 Step 1: Deploy the New Verifier Contract

Build and deploy a new UltraHonk verifier contract that supports the v2 scoped public input layout (192 bytes, 6 × BN254 field elements):

```powershell
cd contracts
stellar contract build
stellar contract deploy `
  --wasm target\wasm32-unknown-unknown\release\harpocrates_registry.wasm `
  --source <admin> `
  --network testnet
```

### 3.3 Step 2: Update the Registry Contract

If you are deploying a new registry contract, use the latest `lib.rs` which includes:

- `SCOPED_NULLIFIER_V1` domain separator constant
- `MAX_SCOPE_LENGTH = 64` byte limit
- `DataKey::ScopeEpoch` for per-scope epoch tracking
- `register_anonymous_verified` v2 parsing path (192-byte inputs)
- `set_scope_epoch` / `get_scope_epoch` admin entry points
- `StaleEpoch` error variant

If you are upgrading an existing registry contract, this is a **non-breaking upgrade** — the existing v1 path is preserved and the v2 path is additive.

### 3.4 Step 3: Set the Verifier on the Registry

```powershell
.\contracts\scripts\set-verifier.ps1 `
  -ContractId <REGISTRY_CONTRACT_ID> `
  -Admin <ADMIN_KEY> `
  -Verifier <NEW_VERIFIER_CONTRACT_ID>
```

### 3.5 Step 4: Configure Scopes and Epochs

For each verifier/purpose combination, compute the scope field element and set the initial epoch:

```powershell
# In the frontend, derive the scope field:
# npx ts-node -e "import { deriveVerifierScope } from './seedVault'; deriveVerifierScope('GC...', 'attestation').then(console.log)"

# Then set the epoch on-chain:
.\contracts\scripts\set-scope-epoch.ps1 `
  -ContractId <REGISTRY_CONTRACT_ID> `
  -Admin <ADMIN_KEY> `
  -Scope <SCOPE_FIELD_ELEMENT> `
  -Epoch 0
```

### 3.6 Step 5: Verify the Migration

Run the contract test suite to verify that:

1. v1 proofs still work (backward compatibility)
2. v2 scoped proofs work with the new verifier
3. Epoch management works correctly
4. Replay protection is enforced

```powershell
cd contracts
cargo test --lib
```

---

## 4. Rollout Strategy

### 4.1 Phase 1: Shadow Deployment

- Deploy the new registry contract alongside the existing one
- Run both contracts in parallel
- Log all v2 scoped registrations for monitoring
- Do not enforce scope/epoch requirements yet

### 4.2 Phase 2: Soft Enforcement

- Begin accepting v2 scoped proofs
- Set initial epochs to 0 for all scopes
- Monitor for replay attempts and epoch mismatches
- Verify that v1 and v2 proofs coexist without conflict

### 4.3 Phase 3: Epoch Enforcement

- Begin rotating epochs for active scopes on a schedule
- Reject stale proofs (epoch mismatch)
- Monitor for any legitimate proofs that fail due to epoch rotation

### 4.4 Phase 4: Legacy Deprecation

- After a sufficient observation period, deprecate the v1 path
- Remove `register_anonymous_verified` v1 support if desired
- Update documentation to require v2 scoped proofs

---

## 5. Rollback Plan

### 5.1 Rollback Scenarios

| Scenario | Rollback Action |
|----------|----------------|
| v2 proof verification fails | Switch verifier back to the v1 verifier contract |
| Epoch rotation causes legitimate failures | Reset epoch to the previous value via `set_scope_epoch` |
| Scope configuration error | Remove the scope epoch entry (set to 0) |
| Contract bug in v2 path | Deploy a patched contract and redirect verifier |

### 5.2 Rollback Procedure

1. Switch the verifier back to the previous verifier contract:
   ```powershell
   .\contracts\scripts\set-verifier.ps1 `
     -ContractId <REGISTRY_CONTRACT_ID> `
     -Admin <ADMIN_KEY> `
     -Verifier <OLD_VERIFIER_CONTRACT_ID>
   ```
2. Reset any scope epochs that were advanced:
   ```powershell
   .\contracts\scripts\set-scope-epoch.ps1 `
     -ContractId <REGISTRY_CONTRACT_ID> `
     -Admin <ADMIN_KEY> `
     -Scope <SCOPE_FIELD> `
     -Epoch <PREVIOUS_EPOCH>
   ```
3. Verify that v1 proofs work again:
   ```powershell
   .\scripts\e2e-harpocrates.ps1
   ```

### 5.3 State Repair

The registry contract does not require any state repair on rollback because:

- v1 and v2 nullifiers are tracked in the same global set
- Nullifiers consumed by v2 proofs remain consumed (they are one-use tokens)
- The `Nullifier` set is append-only and does not need to be cleared

---

## 6. Monitoring and Observability

### 6.1 Key Metrics

| Metric | Description |
|--------|-------------|
| `v1_registrations_total` | Count of v1 (legacy) proof registrations |
| `v2_registrations_total` | Count of v2 (scoped) proof registrations |
| `stale_epoch_rejections_total` | Count of proofs rejected due to epoch mismatch |
| `duplicate_nullifier_rejections_total` | Count of replay attempts |
| `scope_epoch_rotations_total` | Count of epoch advancement operations |

### 6.2 Events to Monitor

- `ScopeEpochSet` — emitted when the admin advances a scope epoch
- `ProofRegistered` — emitted for all successful registrations
- `NonRevocationChecked` — emitted for non-revocation proof checks

### 6.3 Alerts

- **StaleEpoch spike** — a sudden increase in stale epoch rejections may indicate a misconfigured epoch rotation schedule
- **DuplicateNullifier spike** — may indicate a replay attack attempt
- **ScopeEpochSet without corresponding registrations** — may indicate an admin error

---

## 7. Security Considerations

### 7.1 Scope String Validation

Scope strings must be validated before derivation:

- Non-empty
- At most 64 bytes
- Lowercase ASCII alphanumeric with colons, hyphens, or underscores only
- No whitespace or uppercase characters

The contract enforces the 64-byte limit via `MAX_SCOPE_LENGTH`. The frontend enforces the canonical format via `deriveScopeField` in `seedVault.ts`.

### 7.2 Epoch Advancement

- Epochs can only be advanced by the registry admin
- Epochs are monotonically increasing within a scope
- There is no epoch rollback — once an epoch is advanced, proofs from previous epochs are permanently rejected

### 7.3 Cross-Network Isolation

Each registry contract deployment has its own independent nullifier set. A nullifier consumed on one network is not tracked on another. This is an inherent property of the Soroban contract boundary.

### 7.4 Cross-Verifier Isolation

The verifier contract address is stored on-chain and used to verify proofs. A proof produced for verifier A will not verify against verifier B (different proving keys). Changing the verifier on the registry does not invalidate previously consumed nullifiers.

---

## 8. References

- [Nullifier Derivation Spec](NULLIFIER_DERIVATION_SPEC.md)
- [Threat Model](THREAT_MODEL.md)
- [Noir Circuit Source](zk/noir/silent_witness/src/main.nr)
- [Contract Source](contracts/contracts/harpocrates-registry/src/lib.rs)
- [Frontend Scope Derivation](frontend/src/seedVault.ts)