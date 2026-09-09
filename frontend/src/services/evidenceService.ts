/**
 * evidenceService — network calls for the evidence embedding flow.
 *
 * Responsibility: talk to the Flask steganography API and NeonDB persistence
 * endpoint. Returns plain data objects; no React state.
 */

import type { IdentityTier, ProofPackage } from '../types'
import type { RegisterProofResult } from '../stellarTypes'
import type { TimeAttestation } from '../timeAttestation'
import { parseApiError } from './apiError'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'
const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

export type EmbedResult = {
  embeddedBlob: Blob
  embeddedHash: string
  metadataHash: string
}

/**
 * Send the raw video file to the steganography backend.
 * Returns the embedded blob and its hashes on success.
 */
export async function embedVideo(
  file: File,
  tier: IdentityTier,
  sourceHash: string,
  proofId: string,
  timestamp: string,
): Promise<EmbedResult> {
  const metadata = {
    protocol: 'harpocrates',
    version: 1,
    tier,
    sourceHash,
    proofId,
    timestamp,
    fileName: file.name,
  }

  const form = new FormData()
  form.append('video', file)
  form.append('metadata', JSON.stringify(metadata))

  const response = await fetch(`${API_BASE}/api/stego/embed`, {
    method: 'POST',
    body: form,
  })

  if (!response.ok) {
    throw new Error(await parseApiError(response, 'Steganography service did not accept the video.'))
  }

  const embeddedBlob = await response.blob()

  // Hash the received blob locally to verify integrity.
  const { sha256 } = await import('../utils')
  const embeddedHash = await sha256(await embeddedBlob.arrayBuffer())
  const headerHash = response.headers.get('X-Harpocrates-Embedded-Hash')
  const metadataHash = response.headers.get('X-Harpocrates-Metadata-Hash')

  if (!headerHash || headerHash !== embeddedHash || !metadataHash) {
    throw new Error('Steganography service returned an invalid evidence package.')
  }

  return { embeddedBlob, embeddedHash, metadataHash }
}

/**
 * Write a completed Stellar registration event to NeonDB.
 * Fire-and-forget from the UI perspective; errors are surfaced to the caller.
 */
export async function persistRegistration(
  proof: ProofPackage,
  result: RegisterProofResult,
  sourceAddress: string,
): Promise<void> {
  const payload: any = {
    fileName: proof.fileName,
    videoHash: proof.videoHash,
    metadataHash: proof.metadataHash,
    proofId: proof.proofId,
    tier: proof.tier,
    txHash: result.hash,
    txStatus: result.status,
    sourceAddress,
    contractId: CONTRACT_ID,
    silentWitness:
      proof.silentWitness && proof.tier === 'silent'
        ? {
            credentialRoot: proof.silentWitness.credentialRoot,
            nullifier: proof.silentWitness.nullifier,
            proofBytes: proof.silentWitness.proofBytes,
            publicInputBytes: proof.silentWitness.publicInputBytes,
          }
        : undefined,
  }

  // Include time attestation if present
  if (proof.timeAttestation) {
    payload.timeAttestation = proof.timeAttestation
  }

  await fetch(`${API_BASE}/api/proofs/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

/**
 * Create a time attestation for evidence with claimed capture time.
 */
export async function createEvidenceTimeAttestation(
  videoHash: string,
  claimedTimeMs?: number,
): Promise<TimeAttestation> {
  const { createTimeAttestation } = await import('../timeAttestation')
  
  const response = await createTimeAttestation({
    evidenceDigest: videoHash,
    claimedTimeMs,
    claimedSourceLabel: 'device_clock',
    uncertaintyMs: 1000,
  })

  return response.timeAttestation
}

/**
 * Add Stellar anchor to time attestation after transaction confirmation.
 */
export async function addStellarAnchorToAttestation(
  attestation: TimeAttestation,
  txHash: string,
  ledgerSequence: number,
  ledgerTimestamp: number,
  networkPassphrase: string,
): Promise<TimeAttestation> {
  const { anchorTimeAttestation } = await import('../timeAttestation')
  
  const response = await anchorTimeAttestation({
    timeAttestation: attestation,
    stellarAnchor: {
      ledgerSequence,
      ledgerTimestamp,
      transactionHash: txHash,
      networkPassphrase,
    },
  })

  return response.timeAttestation
}

/** Fetch recent proof events from NeonDB (up to `limit`). */
export async function fetchRecentEvents(limit = 6) {
  const response = await fetch(`${API_BASE}/api/proofs?limit=${limit}`)
  if (!response.ok) throw new Error(await parseApiError(response, 'Database event feed is unavailable.'))
  const data = await response.json()
  return data.events ?? []
}
