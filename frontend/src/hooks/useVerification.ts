/**
 * useVerification — manages the verification portal flow:
 * local hash → stego extract → NeonDB lookup → on-chain query.
 */

import { useState } from 'react'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'

export type UseVerificationReturn = {
  verifyHash: string
  verifyResult: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  verifyEvidence: (file: File | null, walletAddress?: string) => Promise<void>
  loadEvents: () => Promise<void>
}

export function useVerification(): UseVerificationReturn {
  const [verifyHash, setVerifyHash] = useState('')
  const [verifyResult, setVerifyResult] = useState('')
  const [events, setEvents] = useState<ProofEvent[]>([])
  const [chainProof, setChainProof] = useState<ChainProofRecord | null>(null)

  async function verifyEvidence(file: File | null, walletAddress?: string) {
    if (!file) return

    setVerifyResult('Inspecting evidence...')

    const { sha256 } = await import('../utils')
    const videoHash = await sha256(await file.arrayBuffer())
    setVerifyHash(videoHash)

    try {
      const { extractMetadata, fetchProofEventsByVideo, getOnChainProof } = await import(
        '../services/verificationService'
      )

      const [extractResult, dbMatches, onChain] = await Promise.all([
        extractMetadata(file),
        fetchProofEventsByVideo(videoHash),
        getOnChainProof(videoHash, walletAddress),
      ])

      setVerifyResult(
        extractResult.hasHarpocratesMetadata
          ? `Harpocrates metadata found. NeonDB has ${dbMatches.length} event(s). Chain registry: ${
              onChain ? 'confirmed' : 'not found'
            }.`
          : `No embedded Harpocrates metadata found. NeonDB has ${dbMatches.length} event(s). Chain registry: ${
              onChain ? 'confirmed' : 'not found'
            }.`,
      )
      setEvents(dbMatches)
      setChainProof(onChain)
    } catch (error) {
      const detail = error instanceof Error ? error.message : ''
      setVerifyResult(
        detail
          ? `Verification failed: ${detail}`
          : 'Local hash complete. Verification services are unavailable.',
      )
    }
  }

  async function loadEvents() {
    const { fetchRecentEvents } = await import('../services/evidenceService')
    const loaded = await fetchRecentEvents(6)
    setEvents(loaded)
  }

  return { verifyHash, verifyResult, events, chainProof, verifyEvidence, loadEvents }
}
