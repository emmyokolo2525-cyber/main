import { describe, it, expect } from 'vitest'
import {
  createProofManifest,
  serializeManifest,
  isLegacyManifest,
  type ProofManifest,
} from './proofManifest'

const VALID_INPUT = {
  proofId: 'a'.repeat(64),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: 'b'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'e'.repeat(64),
  timestamp: '2025-07-24T12:00:00.000Z',
  verifierScope: '0',
  epoch: 0,
}

// ── createProofManifest – positive cases ──────────────────────────────────

describe('createProofManifest', () => {
  it('returns a manifest with protocol and version 2', () => {
    const manifest = createProofManifest(VALID_INPUT)

    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(2)
  })

  it('copies all supplied fields into the manifest', () => {
    const manifest = createProofManifest(VALID_INPUT)

    expect(manifest.proofId).toBe(VALID_INPUT.proofId)
    expect(manifest.tier).toBe(VALID_INPUT.tier)
    expect(manifest.network).toBe(VALID_INPUT.network)
    expect(manifest.contractId).toBe(VALID_INPUT.contractId)
    expect(manifest.transactionRef).toBe(VALID_INPUT.transactionRef)
    expect(manifest.videoHash).toBe(VALID_INPUT.videoHash)
    expect(manifest.metadataHash).toBe(VALID_INPUT.metadataHash)
    expect(manifest.sourceHash).toBe(VALID_INPUT.sourceHash)
    expect(manifest.timestamp).toBe(VALID_INPUT.timestamp)
    expect(manifest.verifierScope).toBe('0')
    expect(manifest.epoch).toBe(0)
  })

  it('includes scope and epoch fields', () => {
    const manifest = createProofManifest({
      ...VALID_INPUT,
      verifierScope: '42',
      epoch: 5,
      scopeName: 'test-verifier',
    })

    expect(manifest.verifierScope).toBe('42')
    expect(manifest.epoch).toBe(5)
    expect(manifest.scopeName).toBe('test-verifier')
  })

  it('defaults verifierScope to "0" and epoch to 0 when omitted', () => {
    const manifest = createProofManifest({
      proofId: 'a'.repeat(64),
      tier: 'silent',
      network: 'test',
      contractId: 'CA',
      transactionRef: 'b'.repeat(64),
      videoHash: 'c'.repeat(64),
      metadataHash: 'd'.repeat(64),
      sourceHash: 'e'.repeat(64),
      timestamp: '2025-01-01T00:00:00Z',
    })

    expect(manifest.verifierScope).toBe('0')
    expect(manifest.epoch).toBe(0)
    expect(manifest.scopeName).toBeUndefined()
  })

  it('does not expose any secret or private witness fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const keys = Object.keys(manifest)

    const forbiddenPatterns = [
      /seed/i,
      /credential/i,
      /nullifier/i,
      /witness/i,
      /private/i,
      /secret/i,
      /proof(?!Id)/i,
    ]

    for (const key of keys) {
      for (const pattern of forbiddenPatterns) {
        expect(key).not.toMatch(pattern)
      }
    }
  })

  it.each(['silent', 'source', 'seal'] as const)('accepts tier "%s"', (tier) => {
    const manifest = createProofManifest({ ...VALID_INPUT, tier })
    expect(manifest.tier).toBe(tier)
  })
})

// ── createProofManifest – negative cases ──────────────────────────────────

describe('createProofManifest – negative cases', () => {
  it('produces a valid manifest even when input hashes are short hex strings', () => {
    const manifest = createProofManifest({
      ...VALID_INPUT,
      videoHash: 'abcd',
      metadataHash: '1234',
    })

    expect(manifest.videoHash).toBe('abcd')
    expect(manifest.metadataHash).toBe('1234')
  })
})

// ── serializeManifest – deterministic output ──────────────────────────────

describe('serializeManifest', () => {
  it('returns a JSON string', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)

    expect(typeof json).toBe('string')
    expect(() => JSON.parse(json)).not.toThrow()
  })

  it('sorts keys alphabetically for deterministic output', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest
    const keys = Object.keys(parsed)

    expect(keys).toEqual([...keys].sort())
  })

  it('produces identical output across multiple invocations', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const first = serializeManifest(manifest)
    const second = serializeManifest(manifest)

    expect(first).toBe(second)
  })

  it('produces different output when inputs differ', () => {
    const manifestA = createProofManifest(VALID_INPUT)
    const manifestB = createProofManifest({ ...VALID_INPUT, proofId: 'f'.repeat(64) })

    expect(serializeManifest(manifestA)).not.toBe(serializeManifest(manifestB))
  })

  it('includes all expected top-level keys in sorted order', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as Record<string, unknown>

    const expectedKeys = [
      'contractId',
      'epoch',
      'metadataHash',
      'network',
      'proofId',
      'protocol',
      'sourceHash',
      'tier',
      'timestamp',
      'transactionRef',
      'verifierScope',
      'version',
      'videoHash',
    ]

    expect(Object.keys(parsed)).toEqual(expectedKeys)
  })

  it('serializes scopeName when provided', () => {
    const manifest = createProofManifest({
      ...VALID_INPUT,
      scopeName: 'my-verifier',
    })
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as Record<string, unknown>

    expect(parsed.scopeName).toBe('my-verifier')
  })

  it('omits scopeName when not provided', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as Record<string, unknown>

    expect(parsed.scopeName).toBeUndefined()
  })
})

// ── isLegacyManifest ─────────────────────────────────────────────────────

describe('isLegacyManifest', () => {
  it('returns false for v2 manifests', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(isLegacyManifest(manifest)).toBe(false)
  })

  it('returns true for v1 manifests', () => {
    const v1Manifest = { ...VALID_INPUT, version: 1 } as ProofManifest
    expect(isLegacyManifest(v1Manifest)).toBe(true)
  })
})

// ── round-trip: create then serialize ─────────────────────────────────────

describe('manifest round-trip', () => {
  it('can be parsed back into an object with all fields intact', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest

    expect(parsed).toEqual(manifest)
  })

  it('round-trips with scope and epoch', () => {
    const manifest = createProofManifest({
      ...VALID_INPUT,
      verifierScope: '999',
      epoch: 42,
      scopeName: 'round-trip-test',
    })
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest

    expect(parsed.verifierScope).toBe('999')
    expect(parsed.epoch).toBe(42)
    expect(parsed.scopeName).toBe('round-trip-test')
  })

  it('supports optional selectiveDisclosure field', () => {
    const manifest: ProofManifest = {
      ...createProofManifest(VALID_INPUT),
      selectiveDisclosure: {
        schemaHash: 'aa'.repeat(32),
        publicInputs: 'bb'.repeat(352),
        predicateCommitment: 'cc'.repeat(32),
        circuitVersion: 1,
      },
    }
    expect(manifest.selectiveDisclosure?.schemaHash).toBe('aa'.repeat(32))
    expect(manifest.selectiveDisclosure?.circuitVersion).toBe(1)
  })
})
