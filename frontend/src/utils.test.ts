import { describe, it, expect } from 'vitest'
import { hex, sha256, shortHash, fieldSecret } from './utils'

// ── hex ───────────────────────────────────────────────────────────────────

describe('hex', () => {
  it('converts an empty buffer to an empty string', () => {
    expect(hex(new ArrayBuffer(0))).toBe('')
  })

  it('converts a single-byte buffer to two hex chars', () => {
    const buf = new Uint8Array([0xca]).buffer
    expect(hex(buf)).toBe('ca')
  })

  it('pads single-digit hex values with a leading zero', () => {
    const buf = new Uint8Array([0x0f]).buffer
    expect(hex(buf)).toBe('0f')
  })

  it('converts a multi-byte buffer to a concatenated hex string', () => {
    const buf = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer
    expect(hex(buf)).toBe('deadbeef')
  })
})

// ── sha256 ────────────────────────────────────────────────────────────────

describe('sha256', () => {
  it('returns a 64-character lowercase hex string', async () => {
    const result = await sha256('hello')
    expect(result).toHaveLength(64)
    expect(result).toMatch(/^[0-9a-f]+$/)
  })

  it('returns the well-known SHA-256 of the empty string', async () => {
    // echo -n "" | sha256sum
    const result = await sha256('')
    expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('returns the same hash for the same input (determinism)', async () => {
    const [a, b] = await Promise.all([sha256('abc'), sha256('abc')])
    expect(a).toBe(b)
  })

  it('accepts an ArrayBuffer input and produces the same result as a string', async () => {
    const str = 'hello world'
    const bytes = new TextEncoder().encode(str)
    const [fromStr, fromBuf] = await Promise.all([sha256(str), sha256(bytes.buffer)])
    expect(fromStr).toBe(fromBuf)
  })

  it('produces different hashes for different inputs', async () => {
    const [a, b] = await Promise.all([sha256('foo'), sha256('bar')])
    expect(a).not.toBe(b)
  })
})

// ── shortHash ─────────────────────────────────────────────────────────────

describe('shortHash', () => {
  it('returns "Not generated" for an empty string', () => {
    expect(shortHash('')).toBe('Not generated')
  })

  it('abbreviates a long hash with ellipsis', () => {
    const hash = 'a'.repeat(64)
    const result = shortHash(hash)
    expect(result).toContain('...')
    expect(result.startsWith('a'.repeat(12))).toBe(true)
    expect(result.endsWith('a'.repeat(10))).toBe(true)
  })

  it('includes exactly the first 12 and last 10 characters', () => {
    const hash = '0123456789abcdef'.repeat(4) // 64 chars
    const result = shortHash(hash)
    expect(result).toBe(`${hash.slice(0, 12)}...${hash.slice(-10)}`)
  })
})

// ── fieldSecret ───────────────────────────────────────────────────────────

describe('fieldSecret', () => {
  it('returns a decimal string', async () => {
    const result = await fieldSecret('credential', 'my-seed')
    expect(result).toMatch(/^\d+$/)
  })

  it('returns a non-zero value', async () => {
    const result = await fieldSecret('credential', 'my-seed')
    expect(BigInt(result)).toBeGreaterThan(0n)
  })

  it('produces different values for different labels', async () => {
    const [a, b] = await Promise.all([
      fieldSecret('credential', 'same-seed'),
      fieldSecret('nullifier', 'same-seed'),
    ])
    expect(a).not.toBe(b)
  })

  it('produces different values for different seeds', async () => {
    const [a, b] = await Promise.all([
      fieldSecret('credential', 'seed-a'),
      fieldSecret('credential', 'seed-b'),
    ])
    expect(a).not.toBe(b)
  })

  it('is deterministic — same inputs always produce the same output', async () => {
    const [first, second] = await Promise.all([
      fieldSecret('nullifier', 'determinism-test'),
      fieldSecret('nullifier', 'determinism-test'),
    ])
    expect(first).toBe(second)
  })
})
