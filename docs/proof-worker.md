# Cancellable Proof Generation Worker

## Overview

Silent Witness proof generation (Noir witness execution + UltraHonk proving)
runs inside a dedicated Web Worker instead of the main thread. This keeps the
UI responsive during proving and allows in-flight proof generation to be
cancelled deterministically.

Implementation:
- `src/workers/proofWorker.ts` — runs inside the worker, wraps `noirClient.ts`
- `src/workers/proofWorker.types.ts` — shared message/state types
- `src/workers/proofWorkerClient.ts` — main-thread client (`ProofWorkerClient`)

## Threat assumptions

- `credentialSecret` and `nullifierSecret` are sensitive witness inputs and
  must never be logged, persisted, or included in any worker message other
  than the initial transfer.
- Secrets are transferred to the worker as `ArrayBuffer`s via structured
  clone's transfer list (zero-copy, and the buffer is detached from the
  sender). The worker zeroes the underlying bytes after use, in a `finally`
  block, regardless of success or failure.
- The worker assumes hostile/malformed input is possible (oversized secrets,
  non-hex video hashes) and validates before ever touching the worker or the
  network — see `INVALID_INPUT` below.
- A stuck or unresponsive worker (e.g. due to a WASM-level hang) is treated
  the same as a crash: it is terminated and replaced, never left running
  indefinitely.

## State machine

Each `ProofWorkerClient` instance holds a single Web Worker and dispatches
at most one active proof request at a time.

idle --generate()--> running --resolves/rejects--> idle
running --generate() again--> immediately rejected with BUSY (original request unaffected)
running --cancel()--> worker terminated + respawned, request rejects CANCELLED
running --60s elapsed--> worker terminated + respawned, request rejects TIMEOUT
running --worker crash (onerror/onmessageerror)--> worker terminated + respawned, all pending requests reject CRASHED


Cancellation and timeout both terminate the worker outright rather than
signalling it cooperatively, because the underlying Noir/UltraHonk calls have
no cancellation hook and may block the worker's event loop for the duration
of proving. Terminating and spawning a fresh worker is the only way to
guarantee an in-flight proof stops promptly.

## Error codes

| Code | Meaning |
|---|---|
| `BUSY` | A proof is already running on this client; request rejected immediately without touching the worker. |
| `INVALID_INPUT` | `videoHash` is not 64 hex characters, a secret is empty, or a secret exceeds the maximum size (256 bytes). Rejected before any worker/network activity. |
| `CANCELLED` | `cancel()` was called for this request. |
| `TIMEOUT` | Proof generation exceeded `PROOF_TIMEOUT_MS` (60s). |
| `CRASHED` | The worker fired `onerror`/`onmessageerror` unexpectedly. |
| `CIRCUIT_LOAD_FAILED` | Fetching a compiled circuit artifact failed. |
| `PROOF_GENERATION_FAILED` | Witness execution or proof generation threw (e.g. invalid field value). |

## Local verification

Run the worker's automated tests:

```powershell
cd frontend
npx vitest run src/workers/proofWorkerClient.test.ts
```

For a manual end-to-end check in a real browser (bypassing the rest of the
app), open the dev server in a browser tab, open DevTools console, and run:

```js
const mod = await import('/src/workers/proofWorkerClient.ts')
const client = new mod.ProofWorkerClient()
const { requestId, result } = client.generate(
  { videoHash: '0'.repeat(64), credentialSecret: '123456789', nullifierSecret: '987654321' },
  (stage) => console.log('progress:', stage),
)
result.then(r => console.log('RESULT', r)).catch(e => console.log('ERROR', e.code, e.message))
```

Call `client.cancel(requestId)` while it's running to confirm cancellation.

## Operational signals

Progress callbacks report only the current stage name (`loading_circuits`,
`executing_helper`, `executing_main`, `generating_proof`) — never witness
values, secrets, or proof material. This is safe to log or surface in UI
without risk of leaking sensitive data.

## Rollout / rollback

This change is additive at the call-site level: `App.tsx`'s
`attachSilentWitnessProof` now calls `ProofWorkerClient.generate()` instead of
calling `generateSilentWitnessProof` from `noirClient.ts` directly.
`noirClient.ts` itself is unchanged and still the single source of truth for
the actual proving logic — the worker only wraps it.

To roll back, revert `App.tsx`'s `attachSilentWitnessProof` to call
`generateSilentWitnessProof` from `noirClient.ts` directly on the main
thread. No data migration, persisted state, or artifact format changes are
involved — the change is confined to how/where the existing proving logic is
invoked.

## Known limitations

- Only one proof request is served per `ProofWorkerClient` instance at a
  time; concurrent requests are rejected with `BUSY` rather than queued.
- Cancellation and timeout both discard in-flight worker state entirely
  (via `terminate()`); there is no partial-result recovery.
- The `@vitest/web-worker` test-environment mock does not fully replicate
  real browser `Worker.terminate()` semantics — an in-flight `fetch` inside a
  terminated worker may still resolve/reject in the mock after termination,
  surfacing as a benign "unhandled rejection" in test output. This has been
  observed not to affect real-browser behavior (verified manually).