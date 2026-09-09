import { describe, expect, it } from 'vitest'
import { COMPATIBILITY_NETWORK, COMPATIBILITY_RELEASE_ID } from './releaseCompatibility'

describe('release compatibility constants', () => {
  it('binds the v1 release to testnet', () => {
    expect(COMPATIBILITY_RELEASE_ID).toBe('harpocrates-1.0.0')
    expect(COMPATIBILITY_NETWORK).toBe('testnet')
  })
})
