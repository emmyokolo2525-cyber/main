# Harpocrates Soroban Contracts

This workspace contains the Stellar Soroban contracts for Harpocrates.

## Contracts

```text
contracts/harpocrates-registry
```

`HarpocratesRegistry` stores evidence records for all identity tiers:

- Tier 1 Silent Witness: anonymous Noir proof with nullifier protection.
- Tier 2 Consistent Source: Stellar account signed source.
- Tier 3 Public Seal: approved institutional issuer.

## Build

```powershell
cargo test
stellar contract build
```

## Registry State-Machine Fuzzing

Issue #93 adds deterministic state-machine fuzzing for the registry contract in
`contracts/harpocrates-registry/src/test_state_machine.rs`. The harness drives
the real Soroban contract boundary with bounded authorized and adversarial
command streams, including duplicate proof/video/nullifier attempts, wrong
admins, revoked and unknown issuers, invalid and oversized public inputs,
missing verifier/revocation-root cases, replayed non-revocation nullifiers,
admin-transfer replacement/cancellation, TTL expiry, and client-side cancelled,
timed-out, or partial operations that must not reach contract storage.

The oracle is an explicit model of registry storage and status semantics. After
every generated command it checks:

- `Proof`, `Video`, `Nullifier`, `Issuer`, `CredentialRoot`, `Verifier`,
  `ProofTtl`, and `RevocationRoot` query results match the model.
- `get_proof_status` returns `Valid`, `Expired`, `Revoked`, or `NotFound`
  according to the modeled timestamp, TTL, and revocation state.
- rejected transitions return the expected `RegistryError`, emit no contract
  event, and leave storage unchanged.
- successful transitions emit only the existing typed lifecycle events, except
  `set_proof_ttl`, which intentionally has no event.
- each command remains inside a fixed fuzz budget ceiling so hostile inputs stay
  bounded in CI.

The CI corpus is the combination of curated adversarial sequences and fixed
generated seeds in `REGRESSION_SEEDS`; it runs as part of normal
`cargo test --workspace`, so no workflow or dependency upgrade is required.
Local expansion is opt-in:

```bash
cd contracts
HARPOCRATES_REGISTRY_FUZZ_RUNS=128 \
HARPOCRATES_REGISTRY_FUZZ_SEED=0x9300000000000001 \
cargo test -p harpocrates-registry registry_state_machine -- --nocapture
```

When a case fails, the runner shrinks the command stream by deletion and command
simplification, then prints the original seed, the failing step, the shrunk
command list, and the expected/actual error code. It never prints proof bytes,
public input bytes, witnesses, media, credentials, signatures, or raw metadata.
The model uses deterministic slot numbers and synthetic hashes only.

### Compatibility And Rollout

This fuzzing change is test-only. It does not alter exported contract
functions, storage keys, event schemas, proof/public-input formats, verifier
domains, script arguments, or deployed artifact compatibility. There is no
migration. Rollout is enabling the new tests in CI through the existing
contracts workflow. Rollback is removal or revert of the test module and this
documentation; no on-chain repair is needed.

### Signals And Privacy

Production observers continue to rely on existing typed events:

```text
["proof", "reg", proof_id]        => video_hash, tier, status
["proof", "revoke", proof_id]     => status
["issuer", "add", issuer]         => metadata_hash
["issuer", "revoke", issuer]      => {}
["verif", "set", verifier]        => {}
["credroot", "add", root]         => metadata_hash, issued_at
["credroot", "revoke", root]      => {}
["admin", "propose", pending]     => current_admin
["admin", "cancel", pending]      => current_admin
["admin", "accept", new_admin]    => previous_admin
["revroot", "set", root]          => {}
["nonrev", "check", root]         => nullifier, revocation_root
```

Failures are observable as deterministic transaction reverts with typed
`RegistryError` codes, not as extra events. The fuzz runner treats failed,
cancelled, timed-out, and partial operations as privacy-sensitive and asserts
that they do not emit success signals or write registry records.

### Threat Assumptions And Limits

The harness assumes Soroban ledger execution is atomic and serializes
concurrent submissions. Concurrent behavior is modeled as interleaved retries
and collisions against the same global `Proof`, `Video`, and `Nullifier` keys.
Client-side timeouts/cancellations are modeled as commands that never submit a
transaction; submitted partial failures are modeled through contract calls that
fail after parsing or authorization gates. Real user evidence, production
secrets, live mainnet behavior, and cryptographic verifier soundness are out of
scope for this test module. Cryptographic vectors remain owned by the Noir and
verifier conformance fixtures.

### Troubleshooting

Use the printed seed and shrunk commands to reproduce a failure with
`HARPOCRATES_REGISTRY_FUZZ_SEED`. If the failure is a budget ceiling only,
compare against `src/test_budget.rs` before raising the fuzz ceiling. If a
contract error changes intentionally, update the model order to match the
contract's exact validation order and keep the fixed seed in the corpus.

The current registry exports:

```text
init
propose_admin
cancel_admin_transfer
accept_admin
add_credential_root
revoke_credential_root
get_credential_root
add_issuer
revoke_issuer
set_verifier
get_verifier
set_proof_ttl
get_proof_ttl
register_anonymous
register_anonymous_verified
register_source
register_seal
revoke_proof
get_proof
get_by_video
has_nullifier
get_issuer
set_revocation_root
get_revocation_root
check_non_revocation
get_proof_status
get_proof_history
get_proof_history_at
get_proof_history_count
verify_proof
expire_proof
correct_proof
set_guardian
get_guardian
pause
unpause
is_paused
get_pause_state
```

## Staged verifier rotation

The registry now supports a staged verifier transition so a new verifier can be introduced without an unsafe instant cutover:

1. The admin schedules a pending verifier with an activation ledger and rollback window.
2. Once the ledger reaches the activation threshold, the admin activates the pending verifier.
3. During the rollback window, the admin can revert to the previous verifier if the new verifier misbehaves or fails validation.

The rotation state is persisted and can be inspected via `get_verifier_state`.

### Operational flow

```powershell
./scripts/schedule-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin -Verifier YOUR_NEW_VERIFIER -ActivationLedger 1000 -OverlapWindow 100 -RollbackWindow 200
./scripts/activate-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
./scripts/rollback-verifier-rotation.ps1 -ContractId YOUR_REGISTRY -Admin harpocrates-admin
```

### Rollback and troubleshooting

- Activation is rejected before the configured activation ledger.
- Rollback is rejected once the rollback window closes.
- If the pending verifier fails validation or causes operational issues, revert to the previous verifier within the rollback window.
- If you need to reconfigure the verifier after the rotation completes, call `set_verifier` again to reset the rotation state and install a fresh verifier.

## Admin Transfer

Admin control uses a two-step transfer:

1. The current admin calls `propose_admin`, which creates or replaces the pending
   admin proposal.
2. The pending admin calls `accept_admin` to complete the transfer.

The current admin may call `cancel_admin_transfer` before acceptance. Proposals,
cancellations, and acceptances emit `["admin", "propose"]`,
`["admin", "cancel"]`, and `["admin", "accept"]` lifecycle events.

### Storage compatibility

The existing `DataKey::Admin` value and all existing record layouts are
unchanged. `DataKey::PendingAdmin` is appended as a new, independent persistent
storage key, so upgrading an initialized contract preserves its current admin
and all existing registry data. An upgraded contract starts with no pending
admin proposal.

## Emergency Pause

Registration can be paused per identity tier without affecting reads or
unaffected tiers. See `EMERGENCY_PAUSE.md` for the domain model, authorization
matrix, event schema, migration/rollback notes, and troubleshooting.

## Tier 1 Verifier

`register_anonymous` is the development/demo boundary.

`register_anonymous_verified` is the real Tier 1 entrypoint. It checks public
inputs, requires an active credential root, prevents nullifier reuse, then calls
the configured verifier contract:

```text
verify_proof(public_inputs, proof)
```

See `VERIFIER_INTEGRATION.md` for the UltraHonk verifier deployment plan.

Current Testnet verifier:

```text
CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
```

## Events

The registry emits typed Soroban events with `#[contractevent]`:

```text
["proof", "reg", proof_id]        => video_hash, tier, status
["proof", "revoke", proof_id]     => status
["issuer", "add", issuer]         => metadata_hash
["issuer", "revoke", issuer]      => {}
["verif", "set", verifier]        => {}
["credroot", "add", root]         => metadata_hash, issued_at
["credroot", "revoke", root]      => {}
["proof", "history", proof_id]    => action, timestamp, actor, reason_code
["admin", "propose", pending]     => current_admin
["admin", "cancel", pending]      => current_admin
["admin", "accept", new_admin]    => previous_admin
["revroot", "set", root]          => {}
["nonrev", "check", root]         => nullifier, revocation_root
["pause", "set", domain]          => paused_by, paused_at, expires_at
["pause", "clear", domain]        => unpaused_by, unpaused_at
["guardian", "set", guardian]     => {}
```

## Lifecycle History (#90)

Every proof carries an append-only history of lifecycle transitions. History
entries are privacy-safe: they contain only `proof_id`, `action`, `timestamp`,
`actor`, and `reason_code`. No `video_hash`, `metadata_hash`, `nullifier`, or
proof bytes are ever stored in history or emitted in history events.

### Actions

```text
Registered  = 1
Verified    = 2
Revoked     = 3
Expired     = 4
Corrected   = 5
TtlUpdated  = 6
```

### Bounds

- `MAX_HISTORY_ENTRIES_PER_PROOF = 256` caps total entries per proof.
- `MAX_HISTORY_LIMIT = 50` caps the maximum number of entries returned by a
  single `get_proof_history` call.

### Query

```text
get_proof_history(proof_id, offset, limit) -> Vec<ProofHistoryEntry>
get_proof_history_count(proof_id) -> u32
```

`offset` is zero-based. `limit` must be `<= MAX_HISTORY_LIMIT`. Entries are
returned in chronological order.

### State Transitions

| Function | Authorization | Effect |
|----------|---------------|--------|
| `verify_proof` | Admin | Records a verification event in history. |
| `expire_proof` | Admin | Sets `status = STATUS_EXPIRED` and records history. Rejects if already expired. |
| `correct_proof` | Admin | Updates `metadata_hash` and records history. Rejects if metadata is unchanged. |

All registration functions and `revoke_proof` automatically record history.

### Privacy Properties

- History entries contain no sensitive proof material.
- Reason codes are bounded `u32` values (`0..=255`); free-text reasons are not accepted.
- The `actor` field records the address that authorized the transition, or `None` for anonymous registrations.
- On-chain history events use the topic `["proof", "history", proof_id]` so indexers can filter without reading contract storage.

### Backward Compatibility

Proofs registered before this feature have zero history entries. `get_proof_history`
returns an empty vector for such proofs. The existing `ProofRecord` schema is unchanged.

## Scripts

PowerShell helpers live in `scripts/`:

```text
add-issuer.ps1
add-credential-root.ps1
register-anonymous-verified.ps1
register-source.ps1
register-seal.ps1
revoke-credential-root.ps1
set-verifier.ps1
schedule-verifier-rotation.ps1
activate-verifier-rotation.ps1
rollback-verifier-rotation.ps1
```
