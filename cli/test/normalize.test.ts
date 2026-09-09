import { describe, it, expect } from 'vitest'
import { computeResult, networkName } from '../src/normalize.js'

describe('computeResult', () => {
  it('returns not_found when tx is missing', () => {
    expect(computeResult(null, 'missing')).toBe('not_found')
  })

  it('returns failed when tx failed', () => {
    expect(computeResult(null, 'failed')).toBe('failed')
  })

  it('returns pending when tx is pending', () => {
    expect(computeResult(null, 'pending')).toBe('pending')
  })

  it('returns not_found when tx confirmed but no chain record', () => {
    expect(computeResult(null, 'confirmed')).toBe('not_found')
  })

  it('returns valid for status 0', () => {
    expect(computeResult({ status: 0 }, 'confirmed')).toBe('valid')
  })

  it('returns revoked for status 1', () => {
    expect(computeResult({ status: 1 }, 'confirmed')).toBe('revoked')
  })

  it('returns expired for status 2', () => {
    expect(computeResult({ status: 2 }, 'confirmed')).toBe('expired')
  })

  it('returns not_found for unknown status', () => {
    expect(computeResult({ status: 99 }, 'confirmed')).toBe('not_found')
  })
})

describe('networkName', () => {
  it('returns human-readable name for known passphrases', () => {
    expect(networkName('Test SDF Network ; September 2015')).toBe('Testnet')
    expect(networkName('Public Global Stellar Network ; September 2015')).toBe('Mainnet')
  })

  it('returns raw passphrase for unknown ones', () => {
    expect(networkName('Custom Network')).toBe('Custom Network')
  })
})
