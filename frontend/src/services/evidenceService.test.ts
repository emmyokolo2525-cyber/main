/**
 * Tests for the evidence service layer.
 * fetch is mocked via vi.stubGlobal so no real network calls are made.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { embedVideo, persistRegistration, fetchRecentEvents } from './evidenceService'
import type { ProofPackage } from '../types'
import type { RegisterProofResult } from '../stellarTypes'

// ── helpers ───────────────────────────────────────────────────────────────

function makeMockBlob(content = 'fake-video-bytes') {
  return new Blob([content], { type: 'video/mp4' })
}

function makeFile(name = 'test.mp4') {
  return new File([makeMockBlob()], name, { type: 'video/mp4' })
}

// Build a fetch mock that returns an embedded-video response with the
// X-Harpocrates-* headers that the service validates.
async function makeEmbedFetchMock(overrides: {
  ok?: boolean
  embeddedHashOverride?: string
  missingHeader?: boolean
}) {
  const blob = makeMockBlob('embedded-video-bytes')
  // We need the real hash of the blob to pass the integrity check.
  const { hex } = await import('../utils')
  const realHash = hex(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()))
  const embeddedHash = overrides.embeddedHashOverride ?? realHash
  const metadataHash = overrides.missingHeader ? null : 'a'.repeat(64)

  return vi.fn().mockResolvedValueOnce({
    ok: overrides.ok ?? true,
    blob: () => Promise.resolve(blob),
    headers: {
      get: (key: string) => {
        if (key === 'X-Harpocrates-Embedded-Hash') return embeddedHash
        if (key === 'X-Harpocrates-Metadata-Hash') return metadataHash
        return null
      },
    },
  })
}

// ── embedVideo ────────────────────────────────────────────────────────────

describe('embedVideo', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns embeddedHash and metadataHash on success', async () => {
    const mockFetch = await makeEmbedFetchMock({})
    vi.stubGlobal('fetch', mockFetch)

    const file = makeFile()
    const result = await embedVideo(file, 'source', 'a'.repeat(64), 'b'.repeat(64), new Date().toISOString())

    expect(result.embeddedHash).toHaveLength(64)
    expect(result.metadataHash).toHaveLength(64)
    expect(result.embeddedBlob).toBeInstanceOf(Blob)
  })

  it('throws when the server returns a non-OK response', async () => {
    const mockFetch = await makeEmbedFetchMock({ ok: false })
    vi.stubGlobal('fetch', mockFetch)

    const file = makeFile()
    await expect(
      embedVideo(file, 'source', 'a'.repeat(64), 'b'.repeat(64), new Date().toISOString()),
    ).rejects.toThrow('Steganography service did not accept')
  })

  it('surfaces the API error message on non-OK responses with a JSON body', async () => {
    const blob = makeMockBlob('embedded-video-bytes')
    const { hex } = await import('../utils')
    const realHash = hex(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()))

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'video payload exceeds size limit' }),
        headers: { get: () => null },
      }),
    )

    const file = makeFile()
    await expect(
      embedVideo(file, 'source', 'a'.repeat(64), 'b'.repeat(64), new Date().toISOString()),
    ).rejects.toThrow('video payload exceeds size limit')
  })

  it('throws when the header hash does not match the blob hash', async () => {
    const mockFetch = await makeEmbedFetchMock({ embeddedHashOverride: 'f'.repeat(64) })
    vi.stubGlobal('fetch', mockFetch)

    const file = makeFile()
    await expect(
      embedVideo(file, 'source', 'a'.repeat(64), 'b'.repeat(64), new Date().toISOString()),
    ).rejects.toThrow('invalid evidence package')
  })

  it('throws when the metadata hash header is missing', async () => {
    const mockFetch = await makeEmbedFetchMock({ missingHeader: true })
    vi.stubGlobal('fetch', mockFetch)

    const file = makeFile()
    await expect(
      embedVideo(file, 'source', 'a'.repeat(64), 'b'.repeat(64), new Date().toISOString()),
    ).rejects.toThrow('invalid evidence package')
  })
})

// ── fetchRecentEvents ─────────────────────────────────────────────────────

describe('fetchRecentEvents', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the events array from the API response', async () => {
    const events = [{ id: 1, event_type: 'registered' }]
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ events }),
      }),
    )

    const result = await fetchRecentEvents()
    expect(result).toEqual(events)
  })

  it('returns an empty array when the response has no events field', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      }),
    )

    const result = await fetchRecentEvents()
    expect(result).toEqual([])
  })

  it('throws when the server returns a non-OK response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({ ok: false }),
    )

    await expect(fetchRecentEvents()).rejects.toThrow('unavailable')
  })

  it('surfaces the API error message on non-OK responses with a JSON body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'rate limit exceeded' }),
      }),
    )

    await expect(fetchRecentEvents()).rejects.toThrow('rate limit exceeded')
  })
})

// ── persistRegistration ───────────────────────────────────────────────────

describe('persistRegistration', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('posts to /api/proofs/register with the correct fields', async () => {
    const proof: ProofPackage = {
      fileName: 'evidence.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2024-01-01T00:00:00.000Z',
      tier: 'source',
    }
    const result: RegisterProofResult = { hash: 'txhash', status: 'PENDING' }

    await persistRegistration(proof, result, 'GWALLET')

    const mockFetch = vi.mocked(fetch)
    const [url, options] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/api/proofs/register')
    const body = JSON.parse(options.body as string) as Record<string, unknown>
    expect(body.videoHash).toBe(proof.videoHash)
    expect(body.txHash).toBe('txhash')
    expect(body.sourceAddress).toBe('GWALLET')
  })

  it('includes silentWitness fields for silent tier proofs', async () => {
    const proof: ProofPackage = {
      fileName: 'sw.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2024-01-01T00:00:00.000Z',
      tier: 'silent',
      silentWitness: {
        credentialRoot: 'e'.repeat(64),
        nullifier: 'f'.repeat(64),
        proof: '00',
        publicInputs: '00',
        proofBytes: 1,
        publicInputBytes: 1,
      },
    }
    const result: RegisterProofResult = { hash: 'txhash', status: 'PENDING' }

    await persistRegistration(proof, result, 'GWALLET')

    const mockFetch = vi.mocked(fetch)
    const [, options] = mockFetch.mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(options.body as string) as Record<string, unknown>
    expect(body.silentWitness).toBeDefined()
    const sw = body.silentWitness as Record<string, unknown>
    expect(sw.credentialRoot).toBe('e'.repeat(64))
    expect(sw.nullifier).toBe('f'.repeat(64))
  })

  it('omits silentWitness for non-silent tiers', async () => {
    const proof: ProofPackage = {
      fileName: 'src.mp4',
      sourceHash: 'a'.repeat(64),
      videoHash: 'b'.repeat(64),
      metadataHash: 'c'.repeat(64),
      proofId: 'd'.repeat(64),
      timestamp: '2024-01-01T00:00:00.000Z',
      tier: 'source',
    }
    const result: RegisterProofResult = { hash: 'txhash', status: 'PENDING' }

    await persistRegistration(proof, result, 'GWALLET')

    const mockFetch = vi.mocked(fetch)
    const [, options] = mockFetch.mock.calls[0] as [string, RequestInit]
    const body = JSON.parse(options.body as string) as Record<string, unknown>
    expect(body.silentWitness).toBeUndefined()
  })
})
