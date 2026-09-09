# ZK Proof Generation and Verification Benchmarks

Harpocrates needs reproducible performance and memory baselines for proof
generation and verification across browser, native, CI, and Soroban-adjacent
targets. Without them, a silent latency or memory regression can turn a
privacy-preserving path into an availability failure — or push operators to
log sensitive material while debugging.

This document covers the harness, threat assumptions, signals, configuration,
rollout/rollback, and limitations.

## Components

| Path | Role |
| --- | --- |
| `zk/bench/bench.lock.json` | Iterations, timeouts, size ceilings, concurrency, privacy policy |
| `zk/bench/zk_bench.py` | Schema, stats, privacy checks, runners, compare/trend CLI |
| `zk/bench/test_zk_bench.py` | Unit tests (no nargo/bb required) |
| `zk/bench/run.sh` | Hermetic environment wrapper |
| `zk/bench/browser_runner.mjs` | Node/bb.js prove+verify timings (browser-equivalent) |
| `zk/bench/results/` | Local reports (gitignored; never commit proof material) |
| `zk/bench/baselines.lock.json` | Optional committed thresholds (absent ⇒ compare is inert) |
| `.github/workflows/zk-ci.yml` | Runs `pytest zk/bench` alongside artifact tooling |

## Targets

| Target | What is measured |
| --- | --- |
| `native` | Host CLI path (`nargo`/`bb` when present; synthetic fallback only when `--synthetic`) |
| `browser` | Node + `@aztec/bb.js` UltraHonk prove/verify (same stack as the Evidence Studio worker) |
| `ci` | CI-tagged run; synthetic driver allowed so PR checks stay hermetic without the proving toolchain |
| `soroban_adjacent` | Host CPU/memory budget envelope for `register_anonymous_verified` / public-input classify (see `test_budget.rs`) |

Cold samples approximate a fresh process/worker. Warm samples discard
`warm_discard` iterations, then record `warm_samples`. Percentiles are computed
only over successful measured samples.

## Threat assumptions

The harness defends against:

- **Unbounded work.** Sample counts, proof/public-input/witness byte ceilings,
  concurrency, per-sample timeouts, and a wall-clock cap are enforced by
  `bench.lock.json`. Oversized or capacity-exceeding work fails with a typed
  reject code — never hangs.
- **Partial promotion.** A report is written only when `outcome=ok`. Timeouts,
  cancellations, rejections, and fatals abort without leaving a trusted report.
- **Evidence leakage.** Reports and stderr signals carry timings, percentiles,
  byte counts, digests/metadata, and machine codes. They never carry witness
  bytes, proof hex, public-input hex, credential/nullifier secrets, or
  signatures. This is pinned by `test_zk_bench.py` privacy cases.
- **Hostile duplicate load.** Concurrent bench slots above
  `min(limits.max_concurrency, target.max_concurrency)` are rejected with
  `capacity`.

It does **not** replace production admission control or on-chain verification.
It also does not claim cross-host wall-clock equality; reports include runtime
metadata so operators can compare like with like.

## Report schema

```text
format: "harpocrates.zk-bench"
version: 1
target: native | browser | ci | soroban_adjacent
fixture_id: silent_witness.synthetic.v1
toolchain: { nargo, bb, proving_scheme, oracle_hash }
runtime: { os, arch, cpu_count, python_version, ci, hostname_hash, ... }
phases[]:
  phase: prove | verify
  cold / warm: { samples_ms, percentiles?, states }
  percentiles?: { p50, p95, p99, min, max, mean, count }
  sizes: { proof_bytes, public_input_bytes, witness_bytes?, acir_bytes?, vk_bytes? }
  memory: { peak_rss_bytes? }
outcome: ok | timeout | cancelled | rejected | fatal
```

Fixture material is synthetic only. Real user evidence is out of scope.

## Local verification

```bash
# Tooling only — no proving toolchain required.
python -m pytest zk/bench -q
zk/bench/run.sh run --target ci --synthetic
zk/bench/run.sh metadata

# Optional: real browser-equivalent path after compiling circuits and
# installing frontend dependencies.
cd frontend && npm ci
# build ACIR via zk/noir scripts, then:
node zk/bench/browser_runner.mjs --cold 1 --warm 2
```

## Configuration

| Knob | Where | Purpose |
| --- | --- | --- |
| per-target sample counts / timeouts | `zk/bench/bench.lock.json` | Bound work |
| size ceilings | `limits.*` | Reject oversized proof/PI/witness/report |
| privacy forbidden keys | `privacy.*` | Fail closed if a report grows a sensitive field |
| baselines path | `thresholds.baselines_path` | Optional regression gate |

Hermetic env vars mirror the reproducible-build pipeline: `SOURCE_DATE_EPOCH=0`,
`TZ=UTC`, `LC_ALL=C`, `PYTHONHASHSEED=0`.

## Signals

Single-line JSON on **stderr**:

| Event | Meaning |
| --- | --- |
| `bench.start` / `bench.done` | Run boundaries |
| `bench.sample` | One sample terminal state (+ elapsed_ms when ok) |
| `bench.fallback` | Synthetic driver used (missing toolchain/artifacts) |
| `bench.report_written` | Successful promotion of an ok report |
| `bench.aborted` | Non-ok outcome; no report written |
| `bench.compare_inert` / `bench.compare_ok` / `bench.regression` | Threshold gate |
| `bench.cancelled` / `bench.fatal` | Terminal failure |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ok (or compare inert) |
| `1` | Threshold regression |
| `2` | Usage error |
| `3` | Fatal / timeout / cancel / reject |

## Deployment impact and rollout

1. Land harness + unit tests + docs. CI runs **unit tests only** (synthetic).
2. Collect reports manually or via optional workflows on pinned hardware.
3. Calibrate and commit `zk/bench/baselines.lock.json` with percentile/size caps.
4. From that commit on, `zk_bench.py compare` fails regressions.

Until baselines exist, compare prints `inert` and exits 0 — same pattern as the
artifact manifest drift check.

## Rollback

- **Disable threshold enforcement:** delete `zk/bench/baselines.lock.json`.
- **Discard local reports:** delete `zk/bench/results/`.
- **Revert the harness:** revert the `zk/bench/**` and docs commit; no contract,
  codec, or proof-format migration is involved.

No undocumented repair step is required.

## Troubleshooting

**`nargo/bb not available and synthetic disabled`** — install the pinned
toolchain from `zk/toolchain.lock.json`, or pass `--synthetic` for a CI-style
timing envelope.

**`missing_artifacts` from `browser_runner.mjs`** — compile circuits first
(`zk/noir/scripts/build-silent-witness.sh` or the reproducible build).

**Compare always inert** — expected until baselines are committed.

## Limitations

- Synthetic CI timings are deterministic envelopes for harness correctness, not
  substitutes for calibrated UltraHonk wall-clock on real hardware.
- Soroban-adjacent figures track host budget envelopes from `test_budget.rs`;
  they are not wall-clock UltraHonk verification inside the VM.
- Cross-architecture percentile equality is not guaranteed; use `runtime`
  metadata when comparing reports.
- Proof hex and witnesses are intentionally never stored in reports; artifact
  digests belong to the reproducible-build manifest, not this harness.
