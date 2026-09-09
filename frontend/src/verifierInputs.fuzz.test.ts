/**
 * Structured fuzzing of the verifier-input boundary (browser layer).
 *
 * The browser parses proof material that may have been handed to it by an
 * untrusted peer (a shared manifest, a pasted blob, a hostile page). A
 * malformed frame must fail deterministically and cheaply, and the rejection
 * must never carry attacker bytes into a console log or an error report.
 *
 * The PRNG, the mutator set, and the seeds are mirrored byte-for-byte by
 * `backend/test_verifier_fuzz.py` and
 * `contracts/contracts/harpocrates-registry/src/test_fuzz.rs`, so all three
 * layers explore the same space and a divergence is attributable.
 *
 * See docs/zk-fuzzing.md.
 */

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  FIELD_LEN,
  MAX_HEX_CHARS,
  MAX_PROOF_BYTES,
  PUBLIC_INPUTS_LEN,
  VerifierInputError,
  classify,
  decodeHex,
  parsePublicInputs,
  type RejectCode,
} from './verifierInputs'

const here = dirname(fileURLToPath(import.meta.url))
const readJson = (relative: string) =>
  JSON.parse(readFileSync(resolve(here, relative), 'utf-8'))

const corpus = readJson('../../zk/vectors/verifier_conformance_v1.json') as {
  cases: {
    schema: string
    public_inputs_hex: string
    expect: { accept: boolean }
  }[]
}

const regressions = readJson('../../zk/vectors/fuzz_regressions_v1.json') as {
  format: string
  version: number
  entries: {
    id: string
    schema: string
    description: string
    public_inputs_hex: string
    proof_hex: string
    expect_reject_code: RejectCode
  }[]
}

/** Fixed, small, and shared with the other layers — the CI budget must not drift. */
const SEEDS = [1, 7, 1337, 20260727]
const ITERATIONS_PER_SEED = 400

const DECLARED_CODES = new Set<string>([
  'malformed_hex',
  'length',
  'padding',
  'non_canonical_field',
  'zero_field',
  'domain_mismatch',
  'proof_undersize',
  'proof_oversize',
  'unknown_schema',
])

const SCHEMAS = ['silent_witness/v1', 'revocation_witness/v1'] as const

const MUTATORS = [
  'truncate_tail',
  'extend_tail',
  'bit_flip',
  'byte_saturate',
  'field_zero',
  'field_saturate',
  'field_swap',
  'frame_duplicate',
  'frame_rotate',
  'field_modulus',
] as const

type Mutator = (typeof MUTATORS)[number]

const MODULUS_BE = decodeHex(
  '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',
)

/** Numerical Recipes LCG — chosen for exact reproducibility across layers. */
class Lcg {
  private state: number

  constructor(seed: number) {
    this.state = seed >>> 0
  }

  nextU32(): number {
    this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0
    return this.state
  }

  below(bound: number): number {
    return bound > 0 ? this.nextU32() % bound : 0
  }
}

const FIELD_COUNT = PUBLIC_INPUTS_LEN / FIELD_LEN

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function setField(data: Uint8Array, index: number, value: Uint8Array): void {
  data.set(value, index * FIELD_LEN)
}

/** Apply one structured mutation. Always returns a bounded byte string. */
function mutate(base: Uint8Array, mutator: Mutator, rng: Lcg): Uint8Array {
  const data = Uint8Array.from(base)

  switch (mutator) {
    case 'truncate_tail':
      return data.slice(0, rng.below(data.length + 1))

    case 'extend_tail': {
      const extra = new Uint8Array(1 + rng.below(64))
      for (let index = 0; index < extra.length; index += 1) {
        extra[index] = rng.below(256)
      }
      const out = new Uint8Array(data.length + extra.length)
      out.set(data, 0)
      out.set(extra, data.length)
      return out
    }

    case 'bit_flip': {
      if (data.length === 0) return data
      const index = rng.below(data.length)
      data[index] ^= 1 << rng.below(8)
      return data
    }

    case 'byte_saturate': {
      if (data.length === 0) return data
      const index = rng.below(data.length)
      data[index] = rng.below(2) ? 0xff : 0x00
      return data
    }

    case 'field_zero':
      setField(data, rng.below(FIELD_COUNT), new Uint8Array(FIELD_LEN))
      return data

    case 'field_saturate':
      setField(data, rng.below(FIELD_COUNT), new Uint8Array(FIELD_LEN).fill(0xff))
      return data

    case 'field_modulus':
      setField(data, rng.below(FIELD_COUNT), MODULUS_BE)
      return data

    case 'field_swap': {
      const left = rng.below(FIELD_COUNT)
      const right = rng.below(FIELD_COUNT)
      const leftField = data.slice(left * FIELD_LEN, (left + 1) * FIELD_LEN)
      const rightField = data.slice(right * FIELD_LEN, (right + 1) * FIELD_LEN)
      setField(data, left, rightField)
      setField(data, right, leftField)
      return data
    }

    case 'frame_duplicate': {
      const out = new Uint8Array(data.length * 2)
      out.set(data, 0)
      out.set(data, data.length)
      return out
    }

    case 'frame_rotate': {
      if (data.length === 0) return data
      const offset = rng.below(data.length)
      const out = new Uint8Array(data.length)
      out.set(data.slice(offset), 0)
      out.set(data.slice(0, offset), data.length - offset)
      return out
    }
  }

  // Unreachable: `mutator` is a closed union and every member returns above.
  return data
}

const positiveFrames = new Map<string, Uint8Array>()
for (const entry of corpus.cases) {
  if (entry.expect.accept && !positiveFrames.has(entry.schema)) {
    positiveFrames.set(entry.schema, decodeHex(entry.public_inputs_hex))
  }
}

const BASE_PROOF_HEX = 'ab'.repeat(64)

// ── 1. Totality ─────────────────────────────────────────────────────────────

describe('structured frame fuzzing', () => {
  for (const schema of SCHEMAS) {
    for (const seed of SEEDS) {
      it(`${schema} seed=${seed} always produces a declared verdict`, () => {
        const base = positiveFrames.get(schema)!
        const rng = new Lcg(seed)

        for (let iteration = 0; iteration < ITERATIONS_PER_SEED; iteration += 1) {
          const mutator = MUTATORS[rng.below(MUTATORS.length)]
          const mutant = mutate(base, mutator, rng)
          const verdict = classify(schema, toHex(mutant), BASE_PROOF_HEX)

          expect(
            verdict === null || DECLARED_CODES.has(verdict),
            `iteration=${iteration} mutator=${mutator} produced ${String(verdict)}`,
          ).toBe(true)
        }
      })
    }
  }

  it('handles proof blobs across the whole accepted range and past it', () => {
    const schema = SCHEMAS[0]
    const frameHex = toHex(positiveFrames.get(schema)!)
    const rng = new Lcg(SEEDS[0])

    for (let iteration = 0; iteration < 32; iteration += 1) {
      const length = rng.below(MAX_PROOF_BYTES + 2)
      const verdict = classify(schema, frameHex, 'cd'.repeat(length))
      expect(verdict === null || DECLARED_CODES.has(verdict)).toBe(true)
    }
  })
})

// ── 2. Determinism ──────────────────────────────────────────────────────────

describe('fuzz determinism', () => {
  it.each(SEEDS)('seed=%i replays exactly', (seed) => {
    const run = () => {
      const rng = new Lcg(seed)
      const base = positiveFrames.get(SCHEMAS[0])!
      const trace: string[] = []
      for (let index = 0; index < 64; index += 1) {
        const mutator = MUTATORS[rng.below(MUTATORS.length)]
        const mutant = mutate(base, mutator, rng)
        trace.push(`${mutator}:${String(classify(SCHEMAS[0], toHex(mutant), BASE_PROOF_HEX))}`)
      }
      return trace
    }

    expect(run()).toEqual(run())
  })

  it('explores distinct paths for distinct seeds', () => {
    const trace = (seed: number) => {
      const rng = new Lcg(seed)
      return Array.from({ length: 64 }, () => MUTATORS[rng.below(MUTATORS.length)])
    }
    expect(trace(SEEDS[0])).not.toEqual(trace(SEEDS[1]))
  })
})

// ── 3. Boundedness ──────────────────────────────────────────────────────────

describe('size bounds', () => {
  it('rejects oversized hex without decoding it', () => {
    try {
      decodeHex('a'.repeat(MAX_HEX_CHARS + 2), 'proof')
      throw new Error('expected a rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(VerifierInputError)
      expect((error as VerifierInputError).code).toBe('proof_oversize')
    }
  })

  it.each([0, 1, FIELD_LEN - 1, FIELD_LEN, PUBLIC_INPUTS_LEN - 1, PUBLIC_INPUTS_LEN + 1, 4096])(
    'rejects a %i-byte frame on length',
    (length) => {
      expect(classify(SCHEMAS[0], '11'.repeat(length), BASE_PROOF_HEX)).toBe('length')
    },
  )
})

// ── 4. Silence ──────────────────────────────────────────────────────────────

describe('rejection signals', () => {
  it.each(SEEDS)('seed=%i never echoes mutant bytes', (seed) => {
    const base = positiveFrames.get(SCHEMAS[0])!
    const rng = new Lcg(seed)

    for (let index = 0; index < 128; index += 1) {
      const mutator = MUTATORS[rng.below(MUTATORS.length)]
      const mutant = mutate(base, mutator, rng)

      try {
        parsePublicInputs(SCHEMAS[0], mutant)
      } catch (error) {
        const rejection = error as VerifierInputError
        const rendered = JSON.stringify(rejection.signal()) + rejection.message
        expect(Object.keys(rejection.signal()).sort()).toEqual(
          expect.arrayContaining(['codec', 'rejectCode']),
        )
        if (mutant.length >= 8) {
          expect(rendered).not.toContain(toHex(mutant.slice(0, 8)))
          expect(rendered).not.toContain(toHex(mutant.slice(-8)))
        }
      }
    }
  })
})

// ── 5. Minimized regression corpus ──────────────────────────────────────────

describe('fuzz regression corpus', () => {
  it('is versioned', () => {
    expect(regressions.format).toBe('harpocrates.fuzz-regressions')
    expect(regressions.version).toBe(1)
  })

  for (const entry of regressions.entries) {
    it(`${entry.id} — ${entry.description}`, () => {
      expect(classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)).toBe(
        entry.expect_reject_code,
      )
    })
  }
})
