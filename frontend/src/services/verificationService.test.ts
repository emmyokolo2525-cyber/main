/**
 * Tests for the verification service layer.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { extractMetadata, fetchProofEventsByVideo } from './verificationService'

function makeVideoFile(name = 'test.mp4') {
  return new File([new Blob(['fake-video'], { type: 'video/mp4' })], name, { type: 'video/mp4' })
}

// ── extractMetadata ───────────────────────────────────────────────────────

describe('extractMetadata', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns hasHarpocratesMetadata=true when protocol is "harpocrates"', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ metadata: { protocol: 'harpocrates' } }),
      }),
    )

    const result = await extractMetadata(makeVideoFile())
    expect(result.hasHarpocratesMetadata).toBe(true)
  })

  it('returns hasHarpocratesMetadata=false when protocol is absent', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ metadata: null }),
      }),
    )

    const result = await extractMetadata(makeVideoFile())
    expect(result.hasHarpocratesMetadata).toBe(false)
  })

  it('returns hasHarpocratesMetadata=false for a different protocol string', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ metadata: { protocol: 'other' } }),
      }),
    )

    const result = await extractMetadata(makeVideoFile())
    expect(result.hasHarpocratesMetadata).toBe(false)
  })

  it('throws with the API error message on non-OK responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'video is required' }),
      }),
    )

    await expect(extractMetadata(makeVideoFile())).rejects.toThrow('video is required')
  })
})

// ── fetchProofEventsByVideo ───────────────────────────────────────────────

describe('fetchProofEventsByVideo', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the events array on success', async () => {
    const events = [{ id: 1, event_type: 'registered', video_hash: 'abc' }]
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ events }),
      }),
    )

    const result = await fetchProofEventsByVideo('a'.repeat(64))
    expect(result).toEqual(events)
  })

  it('returns an empty array when the response contains no events', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      }),
    )

    const result = await fetchProofEventsByVideo('b'.repeat(64))
    expect(result).toEqual([])
  })

  it('includes the video hash in the request URL', async () => {
    const hash = 'c'.repeat(64)
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ events: [] }),
    })
    vi.stubGlobal('fetch', mockFetch)

    await fetchProofEventsByVideo(hash)

    const calledUrl = mockFetch.mock.calls[0][0] as string
    expect(calledUrl).toContain(hash)
  })

  it('throws with the API error message on non-OK responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'video hash must be 32 bytes' }),
      }),
    )

    await expect(fetchProofEventsByVideo('x'.repeat(64))).rejects.toThrow('video hash must be 32 bytes')
  })

  it('falls back to generic message when JSON parsing fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: false,
        json: () => Promise.reject(new SyntaxError('bad')),
      }),
    )

    await expect(fetchProofEventsByVideo('a'.repeat(64))).rejects.toThrow('Database lookup failed')
  })
})
