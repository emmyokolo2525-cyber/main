/**
 * Cross-layer verifier conformance runner (browser side, codec `hpx-vi/1`).
 *
 * Drives the shared corpus in `zk/vectors/verifier_conformance_v1.json` through
 * `src/verifierInputs.ts`. The Python runner
 * (`backend/test_conformance_vectors.py`) and the Rust runner
 * (`contracts/contracts/harpocrates-registry/src/test_conformance.rs`) drive
 * the same file, so a divergence in any layer fails exactly one of the three
 * suites and names the offending case id.
 *
 * See docs/zk-conformance-vectors.md.
 */

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  BN254_SCALAR_FIELD_MODULUS,
  CODEC_ID,
  MAX_PROOF_BYTES,
  MIN_PROOF_BYTES,
  PUBLIC_INPUTS_LEN,
  REVOCATION_DOMAIN_SEPARATOR_HEX,
  VerifierInputError,
  classify,
  decodeHex,
  parsePublicInputs,
} from './verifierInputs'

type ConformanceCase = {
  id: string
  schema: string
  description: string
  public_inputs_hex: string
  proof_hex: string
  expect: { accept: boolean; reject_code: string | null }
}

type Corpus = {
  format: string
  version: number
  codec: string
  constants: Record<string, number | string>
  reject_codes: string[]
  cases: ConformanceCase[]
}

const here = dirname(fileURLToPath(import.meta.url))
const corpusPath = resolve(here, '../../zk/vectors/verifier_conformance_v1.json')
const corpus = JSON.parse(readFileSync(corpusPath, 'utf-8')) as Corpus

describe('conformance corpus integrity', () => {
  it('is versioned and matches this codec', () => {
    expect(corpus.format).toBe('harpocrates.verifier-conformance')
    expect(corpus.version).toBe(1)
    expect(corpus.codec).toBe(CODEC_ID)
  })

  it('declares constants matching the implementation', () => {
    expect(corpus.constants.public_inputs_len).toBe(PUBLIC_INPUTS_LEN)
    expect(corpus.constants.min_proof_bytes).toBe(MIN_PROOF_BYTES)
    expect(corpus.constants.max_proof_bytes).toBe(MAX_PROOF_BYTES)
    expect(BigInt(`0x${corpus.constants.bn254_scalar_field_modulus_hex}`)).toBe(
      BN254_SCALAR_FIELD_MODULUS,
    )
    expect(corpus.constants.revocation_domain_separator_hex).toBe(
      REVOCATION_DOMAIN_SEPARATOR_HEX,
    )
  })

  it('contains both positive and negative cases with unique ids', () => {
    expect(corpus.cases.length).toBeGreaterThanOrEqual(20)
    expect(corpus.cases.some((entry) => entry.expect.accept)).toBe(true)
    expect(corpus.cases.some((entry) => !entry.expect.accept)).toBe(true)
    expect(new Set(corpus.cases.map((entry) => entry.id)).size).toBe(corpus.cases.length)
  })
})

describe('conformance cases', () => {
  for (const entry of corpus.cases) {
    it(`${entry.id} — ${entry.description}`, () => {
      const expected = entry.expect.accept ? null : entry.expect.reject_code
      const actual = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(actual, `${entry.id} mismatched`).toBe(expected)
    })
  }

  it('classifies deterministically on repeat evaluation', () => {
    for (const entry of corpus.cases) {
      const first = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      const second = classify(entry.schema, entry.public_inputs_hex, entry.proof_hex)
      expect(second, `${entry.id} was not deterministic`).toBe(first)
    }
  })
})

describe('boundary behaviour outside the corpus', () => {
  const positive = corpus.cases.find((entry) => entry.expect.accept)!

  it('rejects an unknown schema', () => {
    expect(classify('silent_witness/v2', positive.public_inputs_hex, positive.proof_hex)).toBe(
      'unknown_schema',
    )
  })

  it.each(['0', '0x00', 'zz'.repeat(64), '00 11', '00\n11'])(
    'rejects malformed hex: %j',
    (value) => {
      expect(() => decodeHex(value, 'public_inputs', 'length')).toThrow(VerifierInputError)
      try {
        decodeHex(value, 'public_inputs', 'length')
      } catch (error) {
        expect((error as VerifierInputError).code).toBe('malformed_hex')
      }
    },
  )

  it('never carries input material in a rejection signal', () => {
    const tampered = 'ff'.repeat(32) + positive.public_inputs_hex.slice(64)

    let captured: VerifierInputError | undefined
    try {
      parsePublicInputs(positive.schema, decodeHex(tampered, 'public_inputs', 'length'))
    } catch (error) {
      captured = error as VerifierInputError
    }

    expect(captured).toBeInstanceOf(VerifierInputError)
    const signal = captured!.signal()
    const rendered = JSON.stringify(signal)
    expect(signal.codec).toBe(CODEC_ID)
    expect(rendered).not.toContain(tampered)
    expect(rendered).not.toContain('ff'.repeat(8))
    expect(Object.keys(signal).sort()).toEqual(['codec', 'field', 'rejectCode'])
  })
})
