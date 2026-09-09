# Compatibility releases

Harpocrates publishes a release bundle, never an independently promoted
frontend, backend, circuit, verifier, or registry. The source of truth is
[`release/compatibility-manifest.json`](../release/compatibility-manifest.json).
It contains public identities and SHA-256 digests only; do not place media,
witnesses, credentials, proofs, signatures, transaction XDR, or deployment
secrets in it.

## Local verification

Run the release gate and its adversarial tests from the repository root:

```bash
python3 devx/release_guard.py
python3 -m unittest discover -s devx -p 'test_*.py' -v
```

The gate rejects unknown fields, malformed versions, mismatched circuit and
verifier proof systems, unbound network/interface versions, duplicate or
escaping artifact paths, modified artifacts, and attempts to publish a
non-active rollout. The workflow also runs each component's existing test and
build path. A digest mismatch is deliberate: rebuild and review all dependent
artifacts, then update one manifest in the same reviewed change.

## Release state machine

`candidate -> staged -> active` is the forward path. `candidate` is valid for
local and CI verification but cannot be published. `staged` requires a durable
approval reference and a bounded `max_stage_percent`; production promotion
must first pass the conformance suite and health checks. `active` additionally
requires the deployment controller to run `python3 devx/release_guard.py
--require-active` against the exact checked-out bundle. `rollback` requires
`previous_release`, deploys that previously verified immutable bundle, and
never mutates its artifacts.

State transitions are idempotent by `release_id`: a controller records the
release ID, manifest SHA-256, target network, transition, and timestamp in its
durable deployment store with a unique `(network, release_id, transition)`
key. Concurrent requests must use a transaction/compare-and-set and return
the already-recorded transition. Timeouts or cancellation leave a transition
pending; reconciliation re-verifies the bundle and deployment before retrying.
No single process or in-memory lock is authoritative.

## Deployment and rollback constraints

The manifest network must equal the deployment target. Promote backend and
frontend only after the registry/verifier addresses and their built WASM/VK
digests are recorded by the deployment controller. Route a stage only to
instances reporting the exact public release ID and network. If any component
reports another tuple, stop traffic expansion and rollback to
`previous_release`; do not repair records by editing a released manifest.

The current repository tracks source and browser-verifier artifact hashes.
Production deployment must extend the manifest with the built registry WASM
and verifier VK/WASM hashes before activation. That prevents a compiler or
packaging change from silently reusing a source-only approval.

## Signals and troubleshooting

Emit only bounded, public fields: `release_id`, manifest digest, component
name, target network, state transition, result code, duration bucket, and
saturation bucket. Never log request bodies, metadata, media hashes if they
are sensitive in context, witnesses, proof bytes, credential roots, secrets,
signatures, or transaction payloads. Alert on digest mismatch, network
mismatch, failed readiness, repeated reconciliation, and rollout saturation.

If the gate says `digest mismatch`, restore the intended artifact or update
the digest only as part of a full compatible bundle. If it says `not active`,
the deployment controller must complete staging and record an approval; do not
bypass `--require-active`. If a frontend reaches a different backend release,
remove it from routing and redeploy the verified bundle rather than attempting
cross-version retries.

## Deprecation policy

V1 metadata, public inputs, API, and contract interface stay supported for at
least one active release train and one rollback window. Breaking changes need a
new protocol/cryptographic domain and a versioned migration in the manifest,
deterministic vectors shared by circuit/backend/frontend/contract, a parallel
read path, and an announced removal date. A release may not remove old readers
until every supported active and rollback bundle is outside that window.
