# Fuzzing Malformed Proofs and Public Inputs

The public-input frame and the proof blob are fully attacker-controlled. They
arrive over HTTP from an untrusted client, get handed to a browser prover, and
end up at a Soroban entry point. Every one of those boundaries must fail
*deterministically*, *cheaply*, and *silently* on malformed material.

This document covers the harnesses, the mutators, the budget, and the regression
policy. The codec they exercise is defined in
[`docs/zk-conformance-vectors.md`](zk-conformance-vectors.md).

## Harnesses

| Layer | File | Boundary exercised |
| --- | --- | --- |
| Backend | `backend/test_verifier_fuzz.py` | `backend/verifier_inputs.py` |
| Browser | `frontend/src/verifierInputs.fuzz.test.ts` | `frontend/src/verifierInputs.ts` |
| Contract | `contracts/contracts/harpocrates-registry/src/test_fuzz.rs` | the pure codec **and** the real on-chain `classify_public_inputs` |

The PRNG, the mutator set, the mutator ordering, and the seeds are mirrored
byte-for-byte across all three, so the layers explore the same space and any
divergence is attributable to one layer rather than to luck.

## What is asserted

**1. Totality.** Every mutant produces either acceptance or a declared reject
code. Never an unexpected exception type, never a panic, never a hang, never a
value outside the declared set. On the contract side this includes the real
entry point: a mutant must not panic the host.

**2. Determinism.** A seed replays the same mutant sequence and the same verdict
sequence. A failure is reproducible from the seed alone — there is no "flaky
fuzz failure" to chase. A companion test asserts distinct seeds explore distinct
paths, guarding against a mis-wired PRNG silently collapsing the search.

**3. Boundedness.** Iteration counts and mutant sizes are fixed constants, so the
CI cost of these files is a constant. Oversized hex is rejected on the string
itself, before any decoding, so a hostile caller cannot force a large allocation
just to be told the value is too big. The contract harness sweeps the entire
`u32` range of claimed proof lengths, including values no host could ever
materialise.

**4. Cross-boundary agreement.** `on_chain_and_pure_codec_agree_on_every_mutant`
runs each mutant through both contract boundaries and asserts identical verdicts,
collecting all divergences before failing.

**5. Silence.** No rejection signal ever contains attacker-supplied bytes. The
harnesses take the first and last eight bytes of each mutant and assert neither
appears in the rendered signal or message.

**6. No residue.** The on-chain harness asserts that classifying a mutant never
consumes a nullifier or otherwise mutates state.

## The PRNG

A Numerical Recipes LCG, chosen for exact reproducibility across Python,
TypeScript, and Rust rather than for statistical quality:

```
state = (state * 1664525 + 1013904223) mod 2^32
```

Python masks with `0xFFFFFFFF`, Rust uses `wrapping_mul`/`wrapping_add`,
TypeScript uses `Math.imul(...) >>> 0`. All three produce identical streams from
identical seeds.

## Mutators

Purely random bytes almost never survive the length check, so the mutators are
**structured** — aware of the 32-byte field grid. Indices are shared across
layers:

| # | Mutator | What it probes |
| --- | --- | --- |
| 0 | `truncate_tail` | Framing: every truncation length |
| 1 | `extend_tail` | Framing: trailing-byte tolerance |
| 2 | `bit_flip` | Single-bit sensitivity anywhere in the frame |
| 3 | `byte_saturate` | `0x00` / `0xff` at any offset |
| 4 | `field_zero` | Zero identity fields (replay protection removal) |
| 5 | `field_saturate` | Field far above the modulus |
| 6 | `field_swap` | Field reordering / role confusion |
| 7 | `frame_duplicate` | Two frames concatenated |
| 8 | `frame_rotate` | Whole-frame offset shifts |
| 9 | `field_modulus` | The exact modulus — catches `<=` where `<` is meant |

Proof blobs are fuzzed separately, by length, across the whole accepted window
and one byte past each edge.

## Budget

| Harness | Seeds | Iterations | Notes |
| --- | --- | --- | --- |
| Python frames | 4 | 400 per seed per schema | 3 200 classifications |
| Python proof blobs | 4 | 64 per seed | Bounded by bytes, not iterations |
| TypeScript frames | 4 | 400 per seed per schema | Same space as Python |
| Rust pure codec | 4 | 400 per seed per schema | Allocation-free |
| Rust on-chain | 4 | 64 per seed per schema | Each iteration is a real contract invocation with a real budget |

Seeds are `1, 7, 1337, 20260727`. These numbers are deliberately fixed, not
time- or CI-derived: a fuzz suite whose cost varies run to run is a fuzz suite
that eventually gets disabled.

Raising coverage means adding seeds or mutators in a commit — reviewably, with
the budget change visible — not letting a random run drift.

## Regression corpus

`zk/vectors/fuzz_regressions_v1.json` is the permanent replay corpus. All three
layers replay it on every run.

**Policy — append only.** When a fuzz run finds an input that crashes, hangs,
leaks, or classifies inconsistently across layers:

1. Minimize it to the smallest input that still reproduces.
2. Add an entry with a stable `id`, the schema, a `description` naming the
   issue, and the `expect_reject_code` it must produce.
3. Never delete an entry. If a rule intentionally changes, bump `version` and
   record the migration here.

The current corpus carries ten minimized entries covering framing off-by-ones,
the doubled frame, the exact modulus, a single padding bit, a zero nullifier, a
final-byte domain difference, and both proof-size edges.

## Running the harnesses

```bash
# Backend
cd backend && python -m pytest test_verifier_fuzz.py -q

# Browser
cd frontend && npx vitest run src/verifierInputs.fuzz.test.ts

# Contract (pure codec and on-chain entry point)
cd contracts && cargo test --workspace fuzz
```

Reproduce a specific failure by reading the seed, schema, iteration, and mutator
index out of the assertion message and re-running that seed.

## Configuration

There is none by design. Seeds, iteration counts, and mutator sets are
constants in each harness. A fuzz budget that can be turned down by an
environment variable is a fuzz budget that gets turned down.

## Deployment impact

None. These are test-only additions: no runtime code path, no storage, no
contract entry point is introduced by the fuzzing work itself. The codec it
exercises is additive (see the compatibility section of
[`docs/zk-conformance-vectors.md`](zk-conformance-vectors.md)).

## Rollback

Delete the three harness files and the regression corpus. Nothing else depends
on them. The codec and the conformance corpus stand on their own.

## Limitations

- These are **structured mutation** fuzzers, not coverage-guided ones. They
  explore a deliberately shaped neighbourhood of well-formed input rather than
  discovering new shapes on their own. A coverage-guided fuzzer (`cargo-fuzz`,
  `atheris`) over the same codec would complement this and is not currently
  wired up — it needs a nightly toolchain and a CI budget that is not a
  constant.
- The fuzzers cover the **input codec**, not the proving system. They cannot
  find a soundness bug in UltraHonk; they find parser and boundary bugs in front
  of it.
- The contract harness runs against the Soroban test environment, not a live
  network. Host-level resource accounting differences on a real network are out
  of its reach.
