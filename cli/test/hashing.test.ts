import { describe, it, expect } from 'vitest'
import { sha256, canonicalHash, asHex32, asHexBytes, bytesToHex, hexToBytes } from '../src/hashing.js'

describe('sha256', () => {
  it('produces a 64-character hex string', () => {
    const result = sha256('hello world')
    expect(result).toHaveLength(64)
    expect(/^[0-9a-f]{64}$/.test(result)).toBe(true)
  })

  it('is deterministic', () => {
    expect(sha256('test')).toBe(sha256('test'))
  })

  it('produces different hashes for different inputs', () => {
    expect(sha256('a')).not.toBe(sha256('b'))
  })

  it('handles Uint8Array input', () => {
    const result = sha256(new Uint8Array([1, 2, 3]))
    expect(result).toHaveLength(64)
  })
})

describe('canonicalHash', () => {
  it('produces same hash for objects with differently-ordered keys', () => {
    const a = { b: 1, a: 2 }
    const b = { a: 2, b: 1 }
    expect(canonicalHash(a)).toBe(canonicalHash(b))
  })

  it('produces a 64-char hex string', () => {
    const result = canonicalHash({ foo: 'bar' })
    expect(result).toHaveLength(64)
  })
})

describe('asHex32', () => {
  it('accepts valid 64-char hex', () => {
    const valid = 'a'.repeat(64)
    expect(asHex32(valid)).toBe(valid.toLowerCase())
  })

  it('lowercases mixed-case input', () => {
    expect(asHex32('A'.repeat(64))).toBe('a'.repeat(64))
  })

  it('throws on short input', () => {
    expect(() => asHex32('abc')).toThrow('must be a 32-byte hex string')
  })

  it('throws on invalid chars', () => {
    expect(() => asHex32('g'.repeat(64))).toThrow('must be a 32-byte hex string')
  })
})

describe('asHexBytes', () => {
  it('accepts valid even-length hex', () => {
    expect(asHexBytes('abcd')).toBe('abcd')
  })

  it('throws on odd-length input', () => {
    expect(() => asHexBytes('abc')).toThrow('even-length')
  })
})

describe('bytesToHex', () => {
  it('converts a Uint8Array to hex', () => {
    const bytes = new Uint8Array([0xab, 0xcd, 0xef])
    expect(bytesToHex(bytes)).toBe('abcdef')
  })

  it('returns empty string for empty array', () => {
    expect(bytesToHex(new Uint8Array([]))).toBe('')
  })
})

describe('hexToBytes', () => {
  it('converts hex to Uint8Array', () => {
    const result = hexToBytes('abcdef')
    expect(result).toEqual(new Uint8Array([0xab, 0xcd, 0xef]))
  })

  it('round-trips with bytesToHex', () => {
    const original = new Uint8Array([0x11, 0x22, 0x33, 0xff])
    expect(hexToBytes(bytesToHex(original))).toEqual(original)
  })
})
