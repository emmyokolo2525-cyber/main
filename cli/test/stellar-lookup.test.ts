import { describe, it, expect } from 'vitest'
import { checkContractMatch } from '../src/stellar-lookup.js'

describe('checkContractMatch', () => {
  it('returns true when contract ID is present in envelope', () => {
    const contractId = 'CA7B3F8E2D9146A5091C2F3E8D7B6A5F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B'
    const envelope = new Uint8Array([
      /* ... random bytes ... */
      0x00, 0x01, 0x02,
      /* contract ID bytes */
      0xca, 0x7b, 0x3f, 0x8e, 0x2d, 0x91, 0x46, 0xa5,
      0x09, 0x1c, 0x2f, 0x3e, 0x8d, 0x7b, 0x6a, 0x5f,
      0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0x9f, 0x8e, 0x7d,
      0x6c, 0x5b, 0x4a, 0x3f, 0x2e, 0x1d, 0x0c, 0x9b,
    ])
    expect(checkContractMatch(envelope, contractId)).toBe(true)
  })

  it('returns true when contract ID has 0x prefix', () => {
    const contractId = 'CA7B3F8E2D9146A5091C2F3E8D7B6A5F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B'
    const envelope = new Uint8Array([
      0xcA, 0x7B, 0x3f, 0x8e, 0x2d, 0x91, 0x46, 0xa5,
      0x09, 0x1c, 0x2f, 0x3e, 0x8d, 0x7b, 0x6a, 0x5f,
      0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0x9f, 0x8e, 0x7d,
      0x6c, 0x5b, 0x4a, 0x3f, 0x2e, 0x1d, 0x0c, 0x9b,
    ])
    expect(checkContractMatch(envelope, `0x${contractId}`)).toBe(true)
  })

  it('returns false when contract ID is not in envelope', () => {
    const envelope = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    expect(checkContractMatch(envelope, 'CA7B3F8E2D9146A5091C2F3E8D7B6A5F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B')).toBe(false)
  })

  it('handles empty envelope', () => {
    const envelope = new Uint8Array([])
    expect(checkContractMatch(envelope, 'CA7B3F8E2D9146A5091C2F3E8D7B6A5F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B')).toBe(false)
  })
})
