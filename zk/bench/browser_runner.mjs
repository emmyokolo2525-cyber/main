#!/usr/bin/env node
/**
 * Browser-equivalent (Node + bb.js) prove/verify timing harness.
 *
 * Emits a privacy-safe JSON summary on stdout. Never prints proof hex,
 * public-input hex, witnesses, or credential/nullifier secrets.
 *
 * Usage (from repo root, after `cd frontend && npm ci` and circuit build):
 *   node zk/bench/browser_runner.mjs
 *   node zk/bench/browser_runner.mjs --cold 1 --warm 2
 *
 * When ACIR artifacts are missing, exits 3 with a structured stderr signal
 * (same convention as the Python harness).
 */
import { readFile, access } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import os from 'node:os'
import process from 'node:process'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const HELPER = join(ROOT, 'zk/noir/silent_witness_helper/target/silent_witness_helper.json')
const MAIN = join(ROOT, 'zk/noir/silent_witness/target/silent_witness.json')

const PUBLIC_INPUTS_LEN = 128
const MIN_PROOF_BYTES = 64
const MAX_PROOF_BYTES = 65536

function signal(event, fields = {}) {
  console.error(JSON.stringify({ event, ...fields }))
}

function parseArgs(argv) {
  const out = { cold: 1, warm: 2, discard: 1, timeoutMs: 180_000 }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--cold') out.cold = Number(argv[++i])
    else if (a === '--warm') out.warm = Number(argv[++i])
    else if (a === '--discard') out.discard = Number(argv[++i])
    else if (a === '--timeout-ms') out.timeoutMs = Number(argv[++i])
    else if (a === '--help') out.help = true
  }
  return out
}

function percentile(sorted, pct) {
  if (!sorted.length) throw new Error('empty samples')
  const rank = Math.max(1, Math.round((pct / 100) * sorted.length))
  return sorted[rank - 1]
}

function summarize(samples) {
  const ordered = [...samples].sort((a, b) => a - b)
  return {
    p50: percentile(ordered, 50),
    p95: percentile(ordered, 95),
    p99: percentile(ordered, 99),
    min: ordered[0],
    max: ordered.at(-1),
    mean: ordered.reduce((a, b) => a + b, 0) / ordered.length,
    count: ordered.length,
  }
}

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

async function withTimeout(promise, ms) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'timeout' })), ms)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function measureOnce({ Noir, UltraHonkBackend, helperCircuit, mainCircuit, cold }) {
  const videoHash = '1111111111111111111111111111111122222222222222222222222222222222'
  // Synthetic fixture only — never real media or production secrets.
  const baseInputs = {
    credential_secret: '123456789',
    nullifier_secret: '987654321',
    video_hash_hi: BigInt(`0x${videoHash.slice(0, 32)}`).toString(10),
    video_hash_lo: BigInt(`0x${videoHash.slice(32)}`).toString(10),
  }

  const t0 = performance.now()
  const helperResult = await new Noir(helperCircuit).execute(baseInputs)
  const [credentialRoot, nullifier] = helperResult.returnValue
  const mainInputs = {
    ...baseInputs,
    credential_root: credentialRoot,
    nullifier,
  }
  const { witness } = await new Noir(mainCircuit).execute(mainInputs)
  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proveMs = performance.now() - t0
    const proofBytes = proofData.proof.length
    if (proofBytes < MIN_PROOF_BYTES || proofBytes > MAX_PROOF_BYTES) {
      const err = new Error('proof size out of bounds')
      err.code = proofBytes > MAX_PROOF_BYTES ? 'proof_oversized' : 'proof_undersized'
      throw err
    }
    const v0 = performance.now()
    const verified = await backend.verifyProof(proofData, { keccak: true })
    const verifyMs = performance.now() - v0
    if (!verified) {
      const err = new Error('verification failed')
      err.code = 'verify_failed'
      throw err
    }
    return {
      prove_ms: proveMs,
      verify_ms: verifyMs,
      proof_bytes: proofBytes,
      public_input_bytes: PUBLIC_INPUTS_LEN,
      cold,
    }
  } finally {
    await backend.destroy()
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log('browser_runner.mjs [--cold N] [--warm N] [--discard N] [--timeout-ms MS]')
    process.exit(0)
  }

  if (!(await exists(MAIN)) || !(await exists(HELPER))) {
    signal('bench.fatal', { code: 'missing_artifacts', detail: 'compile circuits first' })
    process.exit(3)
  }

  // Dynamic import so the Python unit CI path does not require node_modules.
  let Noir
  let UltraHonkBackend
  try {
    ;({ Noir } = await import('@noir-lang/noir_js'))
    ;({ UltraHonkBackend } = await import('@aztec/bb.js'))
  } catch {
    // Resolve from frontend/node_modules when run from repo root.
    const frontendModules = join(ROOT, 'frontend/node_modules')
    ;({ Noir } = await import(join(frontendModules, '@noir-lang/noir_js/lib/esm/index.js')))
    ;({ UltraHonkBackend } = await import(join(frontendModules, '@aztec/bb.js/dest/node/index.js')))
  }

  const helperCircuit = JSON.parse(await readFile(HELPER, 'utf8'))
  const mainCircuit = JSON.parse(await readFile(MAIN, 'utf8'))

  signal('bench.start', { target: 'browser', fixture_id: 'silent_witness.synthetic.v1' })

  const proveSamples = []
  const verifySamples = []
  let sizes = null

  const runSample = async (cold) => {
    const sample = await withTimeout(
      measureOnce({ Noir, UltraHonkBackend, helperCircuit, mainCircuit, cold }),
      args.timeoutMs,
    )
    proveSamples.push(sample.prove_ms)
    verifySamples.push(sample.verify_ms)
    sizes = {
      proof_bytes: sample.proof_bytes,
      public_input_bytes: sample.public_input_bytes,
    }
    signal('bench.sample', {
      target: 'browser',
      mode: cold ? 'cold' : 'warm',
      state: 'ok',
      elapsed_ms: sample.prove_ms,
    })
  }

  try {
    for (let i = 0; i < args.cold; i++) await runSample(true)
    for (let i = 0; i < args.discard; i++) await runSample(false)
    // Discard warm-up samples from aggregates by resetting after discard.
    proveSamples.length = args.cold
    verifySamples.length = args.cold
    for (let i = 0; i < args.warm; i++) await runSample(false)
  } catch (err) {
    const code = err?.code || 'fatal'
    signal('bench.fatal', { code, reason: 'browser_runner_failed' })
    process.exit(code === 'timeout' ? 3 : 3)
  }

  const report = {
    format: 'harpocrates.zk-bench',
    version: 1,
    target: 'browser',
    fixture_id: 'silent_witness.synthetic.v1',
    circuit: 'silent_witness',
    runtime: {
      os: os.platform(),
      arch: os.arch(),
      node_version: process.version,
      cpu_count: os.cpus()?.length ?? 0,
      ci: Boolean(process.env.CI || process.env.GITHUB_ACTIONS),
    },
    phases: [
      {
        phase: 'prove',
        percentiles: summarize(proveSamples),
        samples_ms: proveSamples,
        sizes,
      },
      {
        phase: 'verify',
        percentiles: summarize(verifySamples),
        samples_ms: verifySamples,
        sizes,
      },
    ],
    outcome: 'ok',
    generated_at_unix: Math.floor(Date.now() / 1000),
  }

  signal('bench.done', { target: 'browser', outcome: 'ok' })
  console.log(JSON.stringify(report))
}

main().catch((err) => {
  signal('bench.fatal', { code: 'unhandled', reason: 'browser_runner_crashed' })
  process.exit(3)
})
