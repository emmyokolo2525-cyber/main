import { useCallback, useEffect, useRef, useState } from 'react'

/** Strip values that could leak private evidence data from live-region text. */
function sanitizeAnnouncement(raw: string): string {
  return raw
    // Remove Stellar public keys and contract IDs (G.../C... 56 chars) BEFORE hex
    // so that uppercase base32 addresses are not partially matched as hex first.
    .replace(/\b[GC][A-Z2-7]{55}\b/g, '[address]')
    // Remove hex strings longer than 8 characters (hashes, proofs, nullifiers)
    .replace(/\b[0-9a-f]{9,}\b/gi, '[redacted]')
    // Remove unix-style file paths
    .replace(/(\/[\w.-]+){2,}/g, '[path]')
    // Remove Windows-style file paths
    .replace(/[A-Za-z]:\\[\S]+/g, '[path]')
    .trim()
}

/**
 * Manages a sanitised live-region message.
 * The politeness level (polite vs assertive) is controlled by the `aria-live`
 * attribute on the rendered element. Call `announce(msg)` to update the message;
 * the text is sanitised before storage so no evidence hashes or addresses leak.
 */
export function useLiveRegion() {
  const [message, setMessage] = useState('')

  const announce = useCallback((raw: string) => {
    setMessage(sanitizeAnnouncement(raw))
  }, [])

  return { message, announce }
}

export type Stage = 'idle' | 'hashing' | 'embedding' | 'proving' | 'ready' | 'registered' | 'error'

const STAGE_LABELS: Record<Stage, string> = {
  idle: 'Ready',
  hashing: 'Hashing video\u2026',
  embedding: 'Embedding metadata\u2026',
  proving: 'Generating proof\u2026',
  ready: 'Evidence package ready',
  registered: 'Registration submitted',
  error: 'An error occurred',
}

export function useA11yStage(stage: Stage) {
  const isBusy = stage === 'hashing' || stage === 'embedding' || stage === 'proving'
  const statusLabel = STAGE_LABELS[stage]
  return { statusLabel, isBusy }
}

export function useFocusReturn(triggerRef: React.RefObject<HTMLElement | null>, shouldReturn: boolean) {
  const prevShouldReturn = useRef(shouldReturn)
  useEffect(() => {
    if (prevShouldReturn.current && !shouldReturn) {
      triggerRef.current?.focus()
    }
    prevShouldReturn.current = shouldReturn
  }, [shouldReturn, triggerRef])
}

export function useSkipLink() {
  const mainRef = useRef<HTMLElement | null>(null)
  const handleSkip = useCallback((e: React.MouseEvent | React.KeyboardEvent) => {
    e.preventDefault()
    if (mainRef.current) {
      mainRef.current.tabIndex = -1
      mainRef.current.focus()
    }
  }, [])
  return { mainRef, handleSkip }
}
