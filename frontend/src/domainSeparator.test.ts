import { describe, it, expect } from 'vitest'
import {
  buildDomain,
  serialiseDomain,
  domainString,
  PROTOCOL_NAME,
  CIRCUIT_VERSION,
} from './domainSeparator'

// ── buildDomain ───────────────────────────────────────────────────────────────

describe('buildDomain', () => {
  it('sets the canonical protocol name', () => {
    expect(buildDomain('testnet').protocol).toBe('harpocrates')
  })

  it('sets the current circuit version', () => {
    expect(buildDomain('testnet').circuitVersion).toBe(CIRCUIT_VERSION)
  })

  it('preserves the network for testnet', () => {
    expect(buildDomain('testnet').network).toBe('testnet')
  })

  it('preserves the network for mainnet', () => {
    expect(buildDomain('mainnet').network).toBe('mainnet')
  })
})

// ── serialiseDomain ───────────────────────────────────────────────────────────

describe('serialiseDomain', () => {
  it('produces the canonical colon-separated format for testnet', () => {
    expect(serialiseDomain(buildDomain('testnet'))).toBe('harpocrates:1:testnet')
  })

  it('produces the canonical colon-separated format for mainnet', () => {
    expect(serialiseDomain(buildDomain('mainnet'))).toBe('harpocrates:1:mainnet')
  })

  it('testnet and mainnet serialisations differ (cross-network separation)', () => {
    expect(serialiseDomain(buildDomain('testnet'))).not.toBe(
      serialiseDomain(buildDomain('mainnet')),
    )
  })

  it('different circuit versions produce different serialisations (cross-version separation)', () => {
    const v1 = serialiseDomain({ protocol: PROTOCOL_NAME, circuitVersion: '1', network: 'testnet' })
    const v2 = serialiseDomain({ protocol: PROTOCOL_NAME, circuitVersion: '2', network: 'testnet' })
    expect(v1).not.toBe(v2)
  })

  it('different protocols produce different serialisations (cross-protocol separation)', () => {
    const harpocrates = serialiseDomain({ protocol: 'harpocrates', circuitVersion: '1', network: 'testnet' })
    const other = serialiseDomain({ protocol: 'other', circuitVersion: '1', network: 'testnet' })
    expect(harpocrates).not.toBe(other)
  })

  it('is deterministic — same inputs always produce same string', () => {
    const a = serialiseDomain(buildDomain('testnet'))
    const b = serialiseDomain(buildDomain('testnet'))
    expect(a).toBe(b)
  })
})

// ── domainString ─────────────────────────────────────────────────────────────

describe('domainString', () => {
  it('returns harpocrates:1:testnet for testnet', () => {
    expect(domainString('testnet')).toBe('harpocrates:1:testnet')
  })

  it('returns harpocrates:1:mainnet for mainnet', () => {
    expect(domainString('mainnet')).toBe('harpocrates:1:mainnet')
  })

  it('testnet and mainnet strings differ (cross-network mismatch detection)', () => {
    expect(domainString('testnet')).not.toBe(domainString('mainnet'))
  })
})
