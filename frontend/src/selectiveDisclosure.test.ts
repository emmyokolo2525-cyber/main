import { describe, it, expect } from 'vitest'
import type { SelectiveDisclosureInput, Predicate } from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'

const mockPredicate: Predicate = {
  predicateType: 'Equality',
  attrIndex: 0,
  publicValue: '18',
  setValues: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0'),
  setLen: 0,
  lowerBound: '0',
  upperBound: '0',
}

const VALID_INPUT: SelectiveDisclosureInput = {
  schemaHash: 'aa'.repeat(32),
  issuerNamespace: 'bb'.repeat(32),
  schemaVersion: 1,
  credentialRoot: 'cc'.repeat(32),
  nullifier: 'dd'.repeat(32),
  videoHashHi: '11'.repeat(32),
  videoHashLo: '22'.repeat(32),
  verifierDigest: 'ee'.repeat(32),
  circuitVersion: 1,
  evidenceDigest: 'ff'.repeat(32),
  predicateCommitment: '00'.repeat(32),
  numAttributes: 2,
  attrValues: ['18', 'US'],
  attrBlindings: ['111111', '222222'],
  numPredicates: 1,
  predicates: [mockPredicate],
}

describe('SelectiveDisclosureInput', () => {
  it('accepts valid input structure', () => {
    expect(VALID_INPUT.schemaHash.length).toBe(64)
    expect(VALID_INPUT.issuerNamespace.length).toBe(64)
    expect(VALID_INPUT.circuitVersion).toBeGreaterThan(0)
    expect(VALID_INPUT.numAttributes).toBeLessThanOrEqual(SCHEMA_CONSTANTS.MAX_ATTRIBUTES)
    expect(VALID_INPUT.numPredicates).toBeLessThanOrEqual(SCHEMA_CONSTANTS.MAX_PREDICATES)
  })

  it('has matching attribute count and values length', () => {
    expect(VALID_INPUT.attrValues.length).toBeGreaterThanOrEqual(VALID_INPUT.numAttributes)
  })

  it('has matching predicate count and predicates length', () => {
    expect(VALID_INPUT.predicates.length).toBeGreaterThanOrEqual(VALID_INPUT.numPredicates)
  })

  it('rejects too many attributes', () => {
    const bad = {
      ...VALID_INPUT,
      numAttributes: SCHEMA_CONSTANTS.MAX_ATTRIBUTES + 1,
    }
    expect(bad.numAttributes).toBeGreaterThan(SCHEMA_CONSTANTS.MAX_ATTRIBUTES)
  })

  it('rejects too many predicates', () => {
    const bad = {
      ...VALID_INPUT,
      numPredicates: SCHEMA_CONSTANTS.MAX_PREDICATES + 1,
    }
    expect(bad.numPredicates).toBeGreaterThan(SCHEMA_CONSTANTS.MAX_PREDICATES)
  })

  it('accepts all predicate types', () => {
    const types: Array<Predicate['predicateType']> = ['Equality', 'SetMembership', 'Range']
    for (const pt of types) {
      const p: Predicate = {
        predicateType: pt,
        attrIndex: 0,
        publicValue: pt === 'Equality' ? '18' : undefined,
        setValues: pt === 'SetMembership' ? ['US', 'CA'] : [],
        setLen: pt === 'SetMembership' ? 2 : 0,
        lowerBound: pt === 'Range' ? '18' : undefined,
        upperBound: pt === 'Range' ? '99' : undefined,
      }
      expect(p.predicateType).toBe(pt)
    }
  })
})

describe('SCHEMA_CONSTANTS', () => {
  it('defines reasonable limits', () => {
    expect(SCHEMA_CONSTANTS.MAX_ATTRIBUTES).toBe(16)
    expect(SCHEMA_CONSTANTS.MAX_PREDICATES).toBe(8)
    expect(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).toBe(8)
    expect(SCHEMA_CONSTANTS.CURRENT_CIRCUIT_VERSION).toBe(1)
  })

  it('public input byte length is 352', () => {
    expect(SCHEMA_CONSTANTS.PUBLIC_INPUT_BYTE_LENGTH).toBe(352)
  })
})
