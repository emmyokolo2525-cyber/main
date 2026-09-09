import { describe, it, expect } from 'vitest'
import { createReceipt, formatReceipt } from '../src/receipt.js'
import { createProofManifest } from '../src/manifest.js'

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

describe('createReceipt', () => {
  it('creates a receipt with version 1', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const receipt = createReceipt(manifest, { status: 'confirmed', txHash: 'abc' }, null, 'valid')
    expect(receipt.version).toBe(1)
  })

  it('includes verifiedAt as ISO-8601', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const receipt = createReceipt(manifest, { status: 'confirmed', txHash: 'abc' }, null, 'valid')
    expect(() => new Date(receipt.verifiedAt)).not.toThrow()
  })

  it('includes all fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const tx = { status: 'confirmed' as const, txHash: 'abc' }
    const receipt = createReceipt(manifest, tx, null, 'not_found')
    expect(receipt.manifest).toBe(manifest)
    expect(receipt.transaction).toBe(tx)
    expect(receipt.chainRecord).toBeNull()
    expect(receipt.result).toBe('not_found')
  })
})

describe('formatReceipt', () => {
  it('produces human-readable text', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const receipt = createReceipt(manifest, { status: 'confirmed', txHash: 'abc123' }, null, 'valid')
    const text = formatReceipt(receipt)
    expect(text).toContain('VALID')
    expect(text).toContain('abc123')
    expect(text).toContain(VALID_INPUT.proofId)
  })

  it('shows on-chain data when chainRecord is present', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const receipt = createReceipt(
      manifest,
      { status: 'confirmed', txHash: 'abc123' },
      {
        videoHash: 'c'.repeat(64),
        metadataHash: 'd'.repeat(64),
        tier: 0,
        status: 0,
        createdAt: '12345',
        source: 'GABC...',
        issuer: null,
      },
      'valid',
    )
    const text = formatReceipt(receipt)
    expect(text).toContain('On-chain status')
  })
})

describe('result labels', () => {
  it('has labels for all verification results', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const results = ['valid', 'expired', 'revoked', 'not_found', 'pending', 'failed', 'error'] as const
    for (const result of results) {
      const receipt = createReceipt(manifest, { status: 'confirmed', txHash: 'abc' }, null, result)
      const text = formatReceipt(receipt)
      expect(text).toContain('Result:')
    }
  })
})
