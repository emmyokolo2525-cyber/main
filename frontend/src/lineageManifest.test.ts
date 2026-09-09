import { describe, expect, it } from 'vitest'
import { createTransformationManifest, serializeTransformationManifest } from './lineageManifest'

describe('createTransformationManifest', () => {
  it('creates a canonical manifest with deterministic serialization', () => {
    const manifest = createTransformationManifest({
      parentProofIds: ['a'.repeat(64), 'b'.repeat(64)],
      operationType: 'crop',
      parametersDigest: 'c'.repeat(64),
      toolIdentity: 'harpocrates-studio',
      toolVersion: '1.2.3',
      outputDigest: 'd'.repeat(64),
      network: 'testnet',
      actorAddress: 'GABC123',
    })

    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(2)
    expect(manifest.parentProofIds).toEqual(['a'.repeat(64), 'b'.repeat(64)])
    expect(serializeTransformationManifest(manifest)).toContain('"operationType":"crop"')
  })

  it('rejects unsupported operation types', () => {
    expect(() => createTransformationManifest({
      parentProofIds: ['a'.repeat(64)],
      operationType: 'unknown' as never,
      parametersDigest: 'c'.repeat(64),
      toolIdentity: 'harpocrates-studio',
      toolVersion: '1.2.3',
      outputDigest: 'd'.repeat(64),
      network: 'testnet',
      actorAddress: 'GABC123',
    })).toThrow('Unsupported lineage operation')
  })
})
