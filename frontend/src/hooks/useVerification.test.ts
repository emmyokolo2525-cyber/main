/**
 * Tests for useVerification hook.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useVerification } from './useVerification'

// We stub the verificationService and evidenceService dynamic imports
vi.mock('../services/verificationService', () => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

vi.mock('../services/evidenceService', () => ({
  fetchRecentEvents: vi.fn(),
}))

async function getVerifMock() {
  const mod = await import('../services/verificationService')
  return mod as unknown as {
    extractMetadata: ReturnType<typeof vi.fn>
    fetchProofEventsByVideo: ReturnType<typeof vi.fn>
    getOnChainProof: ReturnType<typeof vi.fn>
  }
}

async function getEvidMock() {
  const mod = await import('../services/evidenceService')
  return mod as unknown as { fetchRecentEvents: ReturnType<typeof vi.fn> }
}

function makeVideoFile() {
  return new File([new Uint8Array([1, 2, 3])], 'evidence.mp4', { type: 'video/mp4' })
}

beforeEach(async () => {
  vi.clearAllMocks()
  const vm = await getVerifMock()
  vm.extractMetadata.mockResolvedValue({ hasHarpocratesMetadata: true })
  vm.fetchProofEventsByVideo.mockResolvedValue([])
  vm.getOnChainProof.mockResolvedValue(null)
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ── verifyEvidence – positive path ────────────────────────────────────────

describe('useVerification.verifyEvidence – harpocrates metadata found', () => {
  it('sets verifyResult containing "Harpocrates metadata found"', async () => {
    const { result } = renderHook(() => useVerification())
    const file = makeVideoFile()

    await act(async () => {
      await result.current.verifyEvidence(file)
    })

    expect(result.current.verifyResult).toContain('Harpocrates metadata found')
  })

  it('populates verifyHash with a 64-char hex string', async () => {
    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyHash).toHaveLength(64)
    expect(result.current.verifyHash).toMatch(/^[0-9a-f]+$/)
  })

  it('reflects NeonDB event count in result message', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
      { id: 2, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toContain('2 event')
    expect(result.current.events).toHaveLength(2)
  })

  it('shows "confirmed" when on-chain proof is found', async () => {
    const vm = await getVerifMock()
    vm.getOnChainProof.mockResolvedValue({
      videoHash: 'a'.repeat(64),
      metadataHash: 'b'.repeat(64),
      tier: 1,
      status: 1,
      createdAt: '1000',
      source: null,
      issuer: null,
    })

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toContain('confirmed')
    expect(result.current.chainProof).not.toBeNull()
  })
})

// ── verifyEvidence – no metadata path ────────────────────────────────────

describe('useVerification.verifyEvidence – no harpocrates metadata', () => {
  it('sets verifyResult containing "No embedded Harpocrates metadata"', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockResolvedValue({ hasHarpocratesMetadata: false })

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toContain('No embedded Harpocrates metadata found')
  })
})

// ── verifyEvidence – service failure ─────────────────────────────────────

describe('useVerification.verifyEvidence – service unavailable', () => {
  it('surfaces the API error message when service throws an Error', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue(new Error('Extraction service is unavailable.'))

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toBe('Verification failed: Extraction service is unavailable.')
  })

  it('surfaces the error message from fetchProofEventsByVideo', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockRejectedValue(new Error('Database lookup failed.'))

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toBe('Verification failed: Database lookup failed.')
  })

  it('falls back to generic message when error is not an Error instance', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue('something weird')

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toContain('Verification services are unavailable')
  })

  it('falls back to generic message when error is undefined', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue(undefined)

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toContain('Verification services are unavailable')
  })
})

// ── verifyEvidence – null file ────────────────────────────────────────────

describe('useVerification.verifyEvidence – null file', () => {
  it('does nothing when called with null', async () => {
    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(null)
    })

    expect(result.current.verifyResult).toBe('')
    expect(result.current.verifyHash).toBe('')
  })
})

// ── loadEvents ────────────────────────────────────────────────────────────

describe('useVerification.loadEvents', () => {
  it('populates events from fetchRecentEvents', async () => {
    const em = await getEvidMock()
    em.fetchRecentEvents.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.loadEvents()
    })

    expect(result.current.events).toHaveLength(1)
  })
})
