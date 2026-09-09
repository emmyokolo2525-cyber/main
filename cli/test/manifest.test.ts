import { describe, it, expect } from 'vitest'
import {
  createProofManifest,
  serializeManifest,
  parseManifest,
  type ProofManifest,
} from '../src/manifest.js'

const VALID_INPUT = {
  proofId: 'a'.repeat(64),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: 'b'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'e'.repeat(64),
  timestamp: '2026-07-24T12:00:00.000Z',
}

describe('createProofManifest', () => {
  it('returns a manifest with protocol and version', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(1)
  })

  it('copies all supplied fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(manifest.proofId).toBe(VALID_INPUT.proofId)
    expect(manifest.tier).toBe(VALID_INPUT.tier)
    expect(manifest.videoHash).toBe(VALID_INPUT.videoHash)
  })

  it('does not expose secret/private witness fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const keys = Object.keys(manifest)
    const forbidden = [/seed/i, /credential/i, /nullifier/i, /witness/i, /private/i, /secret/i]
    for (const key of keys) {
      for (const pattern of forbidden) {
        expect(key).not.toMatch(pattern)
      }
    }
  })

  it.each(['silent', 'source', 'seal'] as const)('accepts tier "%s"', (tier) => {
    const manifest = createProofManifest({ ...VALID_INPUT, tier })
    expect(manifest.tier).toBe(tier)
  })
})

describe('serializeManifest', () => {
  it('returns valid JSON', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    expect(() => JSON.parse(json)).not.toThrow()
  })

  it('sorts keys alphabetically', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest
    const keys = Object.keys(parsed)
    expect(keys).toEqual([...keys].sort())
  })

  it('is deterministic across invocations', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(serializeManifest(manifest)).toBe(serializeManifest(manifest))
  })

  it('produces different output for different inputs', () => {
    const a = serializeManifest(createProofManifest(VALID_INPUT))
    const b = serializeManifest(createProofManifest({ ...VALID_INPUT, proofId: 'f'.repeat(64) }))
    expect(a).not.toBe(b)
  })
})

describe('parseManifest', () => {
  it('parses a valid manifest JSON', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = parseManifest(json)
    expect(parsed).toEqual(manifest)
  })

  it('throws on non-JSON input', () => {
    expect(() => parseManifest('not json')).toThrow('not valid JSON')
  })

  it('throws on non-object JSON', () => {
    expect(() => parseManifest('"string"')).toThrow('must be a JSON object')
  })

  it('throws on non-harpocrates protocol', () => {
    const bad = serializeManifest({ ...createProofManifest(VALID_INPUT), protocol: 'other' as 'harpocrates' })
    expect(() => parseManifest(bad)).toThrow('protocol must be')
  })
})
