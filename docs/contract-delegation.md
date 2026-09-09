# Constrained Issuer and Source Delegation

A newsroom's verified source needs its publishing pipeline to register evidence.
An accredited issuer needs a scheduler to seal overnight. Neither should have to
hand over the key that makes them a source or an issuer in the first place.

Delegation grants exactly one capability, for a bounded time, to exactly one
address — and nothing else.

Implemented in `contracts/contracts/harpocrates-registry/src/lib.rs`, tested in
`src/test_delegation.rs`.

## What a delegation is not

- **Not issuer or source authority.** A delegate cannot add or revoke issuers,
  add or revoke credential roots, set the verifier, pause a domain, revoke a
  proof, or touch admin state. Those paths still require the grantor's own key,
  and `test_delegation.rs` pins each one.
- **Not transitive.** `grant_delegation` requires the grantor's own signature,
  and the delegated registration entry points are not grant entry points. There
  is no call path by which a delegate re-delegates the authority it received. A
  delegate that grants to a third party grants only *its own* authority; the
  third party still cannot act for the original grantor. This is enforced by
  construction, so it holds without bounding a delegation-graph walk.
- **Not attribution laundering.** The stored `ProofRecord` still names the
  grantor as source or issuer. The delegate appears in the proof's lifecycle
  history, so an auditor can always separate authority from actor.
- **Not a substitute for standing.** A seal delegation from an address that is
  not a registered, active issuer fails with `UnknownIssuer`. Revoking an issuer
  immediately stops its delegates too.

## Scopes

| Constant | Value | Grants |
| --- | --- | --- |
| `DELEGATION_SCOPE_REGISTER_SOURCE` | `1 << 0` | `register_source_delegated` |
| `DELEGATION_SCOPE_REGISTER_SEAL` | `1 << 1` | `register_seal_delegated` |
| `DELEGATION_SCOPE_ALL` | both | Both of the above, nothing more |

`scope` must be a non-empty subset of `DELEGATION_SCOPE_ALL`. Zero or an unknown
bit is rejected with `InvalidDelegationScope` — a delegation is never created
with a scope the contract does not understand.

## API

```rust
// Grantor's own signature required. Returns the epoch second of auto-expiry.
grant_delegation(grantor, delegate, scope, duration_secs) -> u64

// Callable by the grantor or the admin. A no-op if nothing is stored.
revoke_delegation(revoker, grantor, delegate)

// Read-only.
get_delegation(grantor, delegate)              -> Option<DelegationRecord>
is_delegation_active(grantor, delegate, scope) -> bool
get_delegation_count(grantor)                  -> u32

// Delegated registration. Authorizes the delegate, attributes the grantor.
register_source_delegated(delegate, source, video_hash, metadata_hash, proof_id) -> ProofRecord
register_seal_delegated(delegate, issuer, video_hash, metadata_hash, proof_id)   -> ProofRecord
```

`is_delegation_active` returns `false` — rather than erroring — for unknown,
expired, or insufficiently scoped delegations, so a client can pre-flight
without spending a reverted transaction.

## State machine

```
ABSENT ──grant_delegation──▶ ACTIVE ──ledger reaches expires_at──▶ LAPSED
   ▲                            │                                    │
   │                            │                                    │
   └────revoke_delegation───────┴────────revoke_delegation───────────┘
```

- **ACTIVE → ACTIVE.** Re-granting to an existing delegate overwrites its
  record — narrowing or widening scope, extending or shortening expiry — and
  does *not* consume another storage slot. Retries and renewals are idempotent
  in storage.
- **ACTIVE → LAPSED.** Automatic, at `expires_at`, with no transaction. A
  forgotten grant cannot become permanent authority. `expires_at` itself is
  already outside the window (`now < expires_at` is the liveness test).
- **LAPSED → ABSENT.** Only by `revoke_delegation`. A lapsed record stays
  readable so operators can see and prune it.
- **ABSENT → ABSENT.** Revoking something absent is a no-op, not an error, so
  retried or concurrent revocations converge.

## Bounds

| Bound | Value | Rationale |
| --- | --- | --- |
| `MAX_DELEGATION_DURATION_SECS` | 30 days | Caps blast radius of a leaked delegate key |
| `MAX_DELEGATIONS_PER_GRANTOR` | 32 distinct delegates | Bounds per-grantor storage growth |

`duration_secs` of zero or above the cap is `InvalidDelegationDuration`; exactly
at the cap is accepted. Exceeding the delegate cap is `DelegationsSaturated`.

The cap counts **distinct delegate addresses**, not live delegations. A lapsed
record still holds its slot until revoked. This keeps the cap a simple,
auditable count rather than a time-dependent quantity that could differ between
a simulation and the ledger that executes it. Operators prune with
`revoke_delegation`; the slot is freed immediately, with saturating arithmetic
so a corrupted counter can never underflow into a huge allowance.

Caps are per grantor. One grantor's saturation never affects another's.

## Errors

| Code | Error | Meaning |
| --- | --- | --- |
| 24 | `InvalidDelegationScope` | `scope` was zero or had unknown bits |
| 25 | `InvalidDelegationDuration` | `duration_secs` was zero or over the cap |
| 26 | `DelegationNotFound` | No delegation from that grantor to this caller |
| 27 | `DelegationExpired` | The delegation exists but has lapsed |
| 28 | `DelegationScopeExceeded` | Live, but lacks the required scope |
| 29 | `DelegationsSaturated` | Grantor already holds the maximum delegates |
| 30 | `SelfDelegation` | A grantor may not delegate to itself |

Absent, expired, and insufficiently scoped are kept **distinct** because an
operator responding to a failed registration needs to know which one happened,
and none of the three discloses anything about the media or the proof.

## Signals

Three events, all carrying addresses and scopes only — never media hashes'
provenance, credential material, or witness data:

| Event | Topics | Payload |
| --- | --- | --- |
| `DelegationGranted` | `("deleg","grant")`, grantor, delegate | `scope`, `granted_at`, `expires_at` |
| `DelegationRevoked` | `("deleg","revoke")`, grantor, delegate | `revoked_by`, `revoked_at` |
| `DelegationUsed` | `("deleg","used")`, grantor, delegate | `scope`, `proof_id` |

`DelegationUsed` is the saturation- and abuse-monitoring signal: an unexpected
rate of delegated registrations for one grantor is visible without inspecting
any evidence. `proof_id` is already public in `ProofRegistered`, so the event
discloses nothing new.

## Interaction with existing controls

Delegated registration is subject to **every** rule direct registration obeys:

- Tier 2 / Tier 3 pause domains (`Paused`, error 21).
- Proof and video uniqueness (`DuplicateProof`, `DuplicateVideo`).
- Issuer standing for seals (`UnknownIssuer`).
- Proof TTL and expiry policy — `expires_at` is computed identically.

## Compatibility, rollout, rollback

**Additive.** `Delegation` and `DelegationCount` are new storage keys; the
delegated entry points are new functions; the new errors are appended. No
existing function, storage layout, event, or error value changed. Existing
deployments read as "no delegations" until a grantor opts in, so **no migration
step is required**.

**Rollout.** Deploy the new wasm. Nothing changes until a grantor calls
`grant_delegation`. Adoption is per grantor and reversible at any time.

**Rollback.** Deploying a pre-change wasm removes the delegated entry points and
ignores the new keys. This **fails closed**: delegated registration stops
working and only direct-key registration remains. No proof registered through a
delegation is affected — those records are ordinary `ProofRecord`s attributed to
the grantor, indistinguishable from directly registered ones. Orphaned
`Delegation` keys are inert; they cost storage rent until pruned, which a
re-deploy of the new wasm can do with `revoke_delegation`.

## Operating it

```rust
// Grant a CI pipeline the ability to register source proofs for 7 days.
let expires_at = client.grant_delegation(
    &source, &pipeline, &DELEGATION_SCOPE_REGISTER_SOURCE, &(7 * 24 * 60 * 60));

// The pipeline registers; the proof is attributed to `source`.
client.register_source_delegated(&pipeline, &source, &video_hash, &metadata_hash, &proof_id);

// Incident: the admin cuts it off immediately, without the source's key.
client.revoke_delegation(&admin, &source, &pipeline);
```

## Threat assumptions

- **A leaked delegate key** can register proofs attributed to the grantor within
  the granted scope until expiry or revocation. It cannot escalate, cannot
  re-delegate, and cannot touch anything outside registration. Bounded duration
  and admin revocation cap the exposure.
- **A hostile grantor** cannot use delegation to exceed its own authority: a
  seal delegation is worthless unless the grantor is an active issuer.
- **A hostile client** cannot exhaust storage: the per-grantor delegate cap and
  the duration cap are enforced before any write.
- **A compromised admin** could revoke delegations. That is already within an
  admin's power over the registry generally and is covered by the admin-transfer
  and pause controls.

## Limitations

- Delegations cannot be enumerated on chain. `get_delegation` requires knowing
  the delegate address; there is no `list_delegations(grantor)`, because an
  unbounded iteration over an attacker-influenced set is exactly the pattern
  this contract avoids elsewhere. Off-chain indexers should follow
  `DelegationGranted` and `DelegationRevoked` events.
- A lapsed delegation holds its slot until pruned. A grantor that cycles through
  32 short-lived delegates must revoke before granting the 33rd.
- Scope is coarse: "may register source proofs", not "may register source proofs
  for this specific video hash". Per-artifact delegation would need a
  fundamentally larger key space and is out of scope here.
