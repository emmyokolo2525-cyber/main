/**
 * Unit tests for useA11y hooks.
 *
 * Covers:
 *   - sanitizeAnnouncement (via useLiveRegion.announce): strips hex, addresses, paths
 *   - useLiveRegion: announce updates message; short safe text passes through unchanged
 *   - useA11yStage: correct statusLabel and isBusy per Stage value
 *   - useSkipLink: handleSkip focuses the mainRef element
 *   - useFocusReturn: calls focus() on ref when shouldReturn transitions true→false
 *
 * Negative paths:
 *   - announce with full SHA-256 hex must be redacted
 *   - announce with Stellar G/C addresses must be redacted
 *   - announce with unix paths must be redacted
 *   - announce with empty string is safe
 *   - useA11yStage with every Stage value
 */

import React from 'react'
import { renderHook, act } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { useLiveRegion, useA11yStage, useFocusReturn, useSkipLink } from './useA11y'
import type { Stage } from './useA11y'

// ── Helpers ──────────────────────────────────────────────────────────────────

// Build a deterministic 55-char Stellar-safe (base32 A-Z 2-7) suffix for testing.
// Cycles through the full base32 alphabet so the string is never all valid hex.
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const STELLAR_SUFFIX = Array.from({ length: 55 }, (_, i) => BASE32[i % BASE32.length]).join('')

// ── useLiveRegion ────────────────────────────────────────────────────────────

describe('useLiveRegion', () => {
  it('starts with an empty message', () => {
    const { result } = renderHook(() => useLiveRegion())
    expect(result.current.message).toBe('')
  })

  it('sets a short safe message verbatim', () => {
    const { result } = renderHook(() => useLiveRegion())
    act(() => result.current.announce('Hashing video locally in the browser.'))
    expect(result.current.message).toBe('Hashing video locally in the browser.')
  })

  it('strips SHA-256 hex hashes (64 hex chars) from announcements', () => {
    const { result } = renderHook(() => useLiveRegion())
    const hash = 'a'.repeat(64)
    act(() => result.current.announce(`Evidence hash: ${hash} computed.`))
    expect(result.current.message).not.toContain(hash)
    expect(result.current.message).toContain('[redacted]')
  })

  it('strips any hex string longer than 8 characters', () => {
    const { result } = renderHook(() => useLiveRegion())
    act(() => result.current.announce('Proof id: deadbeef01234567 loaded.'))
    expect(result.current.message).toContain('[redacted]')
    expect(result.current.message).not.toContain('deadbeef01234567')
  })

  it('does NOT redact hex strings of 8 chars or fewer', () => {
    const { result } = renderHook(() => useLiveRegion())
    act(() => result.current.announce('Code: deadbeef accepted.'))
    expect(result.current.message).toContain('deadbeef')
    expect(result.current.message).not.toContain('[redacted]')
  })

  it('strips Stellar public keys (G... 56 char base32)', () => {
    const { result } = renderHook(() => useLiveRegion())
    const stellarKey = 'G' + STELLAR_SUFFIX
    act(() => result.current.announce(`Wallet: ${stellarKey} connected.`))
    expect(result.current.message).not.toContain(stellarKey)
    expect(result.current.message).toContain('[address]')
  })

  it('strips Stellar contract IDs (C... 56 char base32)', () => {
    const { result } = renderHook(() => useLiveRegion())
    const contractId = 'C' + STELLAR_SUFFIX
    act(() => result.current.announce(`Contract: ${contractId} invoked.`))
    expect(result.current.message).not.toContain(contractId)
    expect(result.current.message).toContain('[address]')
  })

  it('strips unix-style file paths', () => {
    const { result } = renderHook(() => useLiveRegion())
    act(() => result.current.announce('Processing /home/user/evidence/video.mp4'))
    expect(result.current.message).not.toContain('/home/user/evidence/video.mp4')
    expect(result.current.message).toContain('[path]')
  })

  it('handles an empty string without throwing', () => {
    const { result } = renderHook(() => useLiveRegion())
    expect(() => act(() => result.current.announce(''))).not.toThrow()
    expect(result.current.message).toBe('')
  })

  it('handles a message with multiple sensitive values', () => {
    const { result } = renderHook(() => useLiveRegion())
    const hash = 'f'.repeat(64)
    const key = 'G' + STELLAR_SUFFIX
    act(() => result.current.announce(`Hash ${hash} from wallet ${key} at /tmp/proof/data`))
    const msg = result.current.message
    expect(msg).not.toContain(hash)
    expect(msg).not.toContain(key)
    expect(msg).not.toContain('/tmp/proof/data')
    expect(msg).toContain('[redacted]')
    expect(msg).toContain('[address]')
    expect(msg).toContain('[path]')
  })

  it('calling announce does not throw for any safe string', () => {
    const { result } = renderHook(() => useLiveRegion())
    expect(() => act(() => result.current.announce('Alert!'))).not.toThrow()
  })
})

// ── useA11yStage ─────────────────────────────────────────────────────────────

describe('useA11yStage', () => {
  const cases: Array<[Stage, string, boolean]> = [
    ['idle', 'Ready', false],
    ['hashing', 'Hashing video…', true],
    ['embedding', 'Embedding metadata…', true],
    ['proving', 'Generating proof…', true],
    ['ready', 'Evidence package ready', false],
    ['registered', 'Registration submitted', false],
    ['error', 'An error occurred', false],
  ]

  it.each(cases)(
    'stage "%s" → statusLabel "%s", isBusy %s',
    (stage, expectedLabel, expectedBusy) => {
      const { result } = renderHook(() => useA11yStage(stage))
      expect(result.current.statusLabel).toBe(expectedLabel)
      expect(result.current.isBusy).toBe(expectedBusy)
    },
  )

  it('updates when stage changes', () => {
    let stage: Stage = 'idle'
    const { result, rerender } = renderHook(() => useA11yStage(stage))
    expect(result.current.isBusy).toBe(false)

    stage = 'hashing'
    rerender()
    expect(result.current.isBusy).toBe(true)
    expect(result.current.statusLabel).toBe('Hashing video…')

    stage = 'ready'
    rerender()
    expect(result.current.isBusy).toBe(false)
    expect(result.current.statusLabel).toBe('Evidence package ready')
  })
})

// ── useFocusReturn ────────────────────────────────────────────────────────────

describe('useFocusReturn', () => {
  it('calls focus() on the ref when shouldReturn transitions true → false', () => {
    const focusMock = vi.fn()
    const ref = { current: { focus: focusMock } as unknown as HTMLElement }

    let shouldReturn = true
    const { rerender } = renderHook(() => useFocusReturn(ref, shouldReturn))

    // Transition true → false
    shouldReturn = false
    rerender()
    expect(focusMock).toHaveBeenCalledTimes(1)
  })

  it('does NOT call focus() when shouldReturn stays false', () => {
    const focusMock = vi.fn()
    const ref = { current: { focus: focusMock } as unknown as HTMLElement }

    let shouldReturn = false
    const { rerender } = renderHook(() => useFocusReturn(ref, shouldReturn))

    shouldReturn = false
    rerender()
    expect(focusMock).not.toHaveBeenCalled()
  })

  it('does NOT call focus() on false → true transition', () => {
    const focusMock = vi.fn()
    const ref = { current: { focus: focusMock } as unknown as HTMLElement }

    let shouldReturn = false
    const { rerender } = renderHook(() => useFocusReturn(ref, shouldReturn))

    shouldReturn = true
    rerender()
    expect(focusMock).not.toHaveBeenCalled()
  })

  it('does not throw when ref.current is null', () => {
    const ref = { current: null }
    let shouldReturn = true
    const { rerender } = renderHook(() => useFocusReturn(ref, shouldReturn))
    shouldReturn = false
    expect(() => rerender()).not.toThrow()
  })
})

// ── useSkipLink ───────────────────────────────────────────────────────────────

describe('useSkipLink', () => {
  it('returns a mainRef and handleSkip', () => {
    const { result } = renderHook(() => useSkipLink())
    expect(result.current.mainRef).toBeDefined()
    expect(typeof result.current.handleSkip).toBe('function')
  })

  it('handleSkip focuses the mainRef element and prevents default', () => {
    const { result } = renderHook(() => useSkipLink())
    const focusMock = vi.fn()
    const element = { focus: focusMock, tabIndex: 0 } as unknown as HTMLElement
    ;(result.current.mainRef as React.MutableRefObject<HTMLElement | null>).current = element

    const fakeEvent = { preventDefault: vi.fn() } as unknown as React.MouseEvent
    act(() => result.current.handleSkip(fakeEvent))

    expect(fakeEvent.preventDefault).toHaveBeenCalled()
    expect(focusMock).toHaveBeenCalled()
  })

  it('handleSkip sets tabIndex to -1 before focusing', () => {
    const { result } = renderHook(() => useSkipLink())
    const element = { focus: vi.fn(), tabIndex: 0 } as unknown as HTMLElement & { tabIndex: number }
    ;(result.current.mainRef as React.MutableRefObject<HTMLElement | null>).current = element

    const fakeEvent = { preventDefault: vi.fn() } as unknown as React.MouseEvent
    act(() => result.current.handleSkip(fakeEvent))

    expect(element.tabIndex).toBe(-1)
  })

  it('handleSkip does not throw when mainRef.current is null', () => {
    const { result } = renderHook(() => useSkipLink())
    const fakeEvent = { preventDefault: vi.fn() } as unknown as React.MouseEvent
    expect(() => act(() => result.current.handleSkip(fakeEvent))).not.toThrow()
  })
})
