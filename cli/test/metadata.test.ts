import { describe, it, expect } from 'vitest'
import { validateMetadata, canonicalMetadataHash } from '../src/metadata.js'

const VALID_METADATA = {
  protocol: 'harpocrates',
  version: 1,
  tier: 'silent',
  sourceHash: 'a'.repeat(64),
  proofId: 'b'.repeat(64),
  timestamp: '2026-07-24T12:00:00.000Z',
}

describe('validateMetadata', () => {
  it('accepts valid metadata', () => {
    expect(() => validateMetadata(VALID_METADATA)).not.toThrow()
  })

  it('rejects non-object input', () => {
    expect(() => validateMetadata(null)).toThrow('must be a JSON object')
    expect(() => validateMetadata('string')).toThrow('must be a JSON object')
  })

  it('rejects missing required fields', () => {
    const { proofId: _, ...missing } = VALID_METADATA
    expect(() => validateMetadata(missing)).toThrow('missing required field: proofId')
  })

  it('rejects wrong protocol', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, protocol: 'other' })).toThrow(
      'protocol must be',
    )
  })

  it('rejects invalid tier', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, tier: 'invalid' })).toThrow(
      'tier must be one of',
    )
  })

  it('rejects bad sourceHash', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, sourceHash: 'xyz' })).toThrow(
      'sourceHash must be a 32-byte hex',
    )
  })

  it('rejects bad proofId', () => {
    expect(() => validateMetadata({ ...VALID_METADATA, proofId: 'xyz' })).toThrow(
      'proofId must be a 32-byte hex',
    )
  })

  it('accepts all valid tiers', () => {
    for (const tier of ['silent', 'source', 'seal']) {
      expect(() => validateMetadata({ ...VALID_METADATA, tier })).not.toThrow()
    }
  })

  it('returns a typed object with the same values', () => {
    const result = validateMetadata(VALID_METADATA)
    expect(result.protocol).toBe('harpocrates')
    expect(result.tier).toBe('silent')
  })
})

describe('canonicalMetadataHash', () => {
  it('produces a 64-character hex string', () => {
    const result = canonicalMetadataHash(VALID_METADATA)
    expect(result).toHaveLength(64)
  })

  it('is deterministic for the same metadata', () => {
    expect(canonicalMetadataHash(VALID_METADATA)).toBe(canonicalMetadataHash(VALID_METADATA))
  })

  it('produces different hashes for different metadata', () => {
    const a = canonicalMetadataHash(VALID_METADATA)
    const b = canonicalMetadataHash({ ...VALID_METADATA, proofId: 'c'.repeat(64) })
    expect(a).not.toBe(b)
  })
})
