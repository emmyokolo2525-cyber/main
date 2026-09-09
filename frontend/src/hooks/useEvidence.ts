/**
 * useEvidence — manages the full evidence creation flow:
 * hashing → embedding → (optional) Noir proving → Stellar registration.
 */

import { useMemo, useState } from 'react'
import { Building2, Fingerprint, KeyRound } from 'lucide-react'
import type { IdentityTier, ProofPackage, Stage } from '../types'
import type { RegisterProofResult } from '../stellarTypes'

export const TIERS = [
  {
    id: 'silent' as IdentityTier,
    title: 'Silent Witness',
    label: 'Anonymous Credential',
    icon: Fingerprint,
    description: 'Noir ZK proof, nullifier replay protection, no public creator identity.',
  },
  {
    id: 'source' as IdentityTier,
    title: 'Consistent Source',
    label: 'Pseudonymous Wallet',
    icon: KeyRound,
    description: 'Freighter signature links evidence to a recurring Stellar source.',
  },
  {
    id: 'seal' as IdentityTier,
    title: 'Public Seal',
    label: 'Institutional Issuer',
    icon: Building2,
    description:
      'Verified issuer account signs the evidence as an official source. The connected wallet must be registered by the admin first.',
  },
]

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

export type UseEvidenceReturn = {
  selectedTier: IdentityTier
  setSelectedTier: (tier: IdentityTier) => void
  selectedTierMeta: (typeof TIERS)[number]
  stage: Stage
  file: File | null
  proof: ProofPackage | null
  processedVideoUrl: string
  credentialSeed: string
  setCredentialSeed: (v: string) => void
  nullifierSeed: string
  setNullifierSeed: (v: string) => void
  message: string
  registration: RegisterProofResult | null
  networkMismatch: string | null
  handleEvidence: (nextFile: File | null) => Promise<void>
  registerProof: (wallet: string) => Promise<void>
}

export function useEvidence(): UseEvidenceReturn {
  const [selectedTier, setSelectedTier] = useState<IdentityTier>('silent')
  const [stage, setStage] = useState<Stage>('idle')
  const [file, setFile] = useState<File | null>(null)
  const [proof, setProof] = useState<ProofPackage | null>(null)
  const [processedVideoUrl, setProcessedVideoUrl] = useState('')
  const [credentialSeed, setCredentialSeed] = useState('')
  const [nullifierSeed, setNullifierSeed] = useState('')
  const [message, setMessage] = useState('Upload evidence to begin.')
  const [registration, setRegistration] = useState<RegisterProofResult | null>(null)
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)

  const selectedTierMeta = useMemo(
    () => TIERS.find((t) => t.id === selectedTier) ?? TIERS[0],
    [selectedTier],
  )

  async function handleEvidence(nextFile: File | null) {
    if (!nextFile) return

    setFile(nextFile)
    setStage('hashing')
    setMessage('Hashing video locally in the browser.')

    try {
      const { sha256 } = await import('../utils')
      const sourceHash = await sha256(await nextFile.arrayBuffer())
      const proofId = await sha256(`${sourceHash}:${crypto.randomUUID()}`)
      const timestamp = new Date().toISOString()

      setStage('embedding')
      setMessage('Embedding portable Harpocrates metadata into the video.')

      const { embedVideo } = await import('../services/evidenceService')
      const { embeddedBlob, embeddedHash, metadataHash } = await embedVideo(
        nextFile,
        selectedTier,
        sourceHash,
        proofId,
        timestamp,
      )

      if (processedVideoUrl) URL.revokeObjectURL(processedVideoUrl)
      setProcessedVideoUrl(URL.createObjectURL(embeddedBlob))
      setProof({
        fileName: `harpocrates-${nextFile.name.replace(/\.[^.]+$/, '')}.mp4`,
        sourceHash,
        videoHash: embeddedHash,
        metadataHash,
        proofId,
        timestamp,
        tier: selectedTier,
      })
      setStage('ready')
      setMessage('Embedded evidence package is ready for Stellar registration.')
    } catch (error) {
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Evidence processing failed.')
    }
  }

  async function registerProof(wallet: string) {
    if (!proof) return

    if (!CONTRACT_ID) {
      setMessage('Set VITE_HARPOCRATES_REGISTRY_ID after deploying the Soroban contract.')
      return
    }

    if (!wallet) {
      setMessage('Connect Freighter before registering evidence.')
      return
    }

    // Re-check network immediately before submission.
    try {
      const { getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
      const { checkNetworkMatch } = await import('../networkGuard')
      const walletPassphrase = await getWalletNetwork()
      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!check.ok) {
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        setMessage(check.reason)
        return
      }
      setNetworkMismatch(null)
    } catch {
      setMessage('Could not verify wallet network before submitting. Reconnect Freighter and try again.')
      return
    }

    setMessage(`Submitting ${selectedTierMeta.title} proof to Stellar Testnet.`)

    try {
      const proofForRegistration =
        selectedTier === 'silent' && !proof.silentWitness
          ? await attachSilentWitnessProof(proof)
          : proof

      const { registerProofOnStellar } = await import('../stellar')
      const result = await registerProofOnStellar({
        contractId: CONTRACT_ID,
        publicKey: wallet,
        tier: selectedTier,
        videoHash: proofForRegistration.videoHash,
        metadataHash: proofForRegistration.metadataHash,
        proofId: proofForRegistration.proofId,
        silentWitness: proofForRegistration.silentWitness
          ? {
              publicInputs: proofForRegistration.silentWitness.publicInputs,
              proof: proofForRegistration.silentWitness.proof,
            }
          : undefined,
      })

      const { persistRegistration } = await import('../services/evidenceService')
      await persistRegistration(proofForRegistration, result, wallet)

      setRegistration(result)
      setStage('registered')
      setMessage(`Registration submitted with Stellar status: ${result.status}.`)
    } catch (error) {
      setStage('error')
      setMessage(error instanceof Error ? error.message : 'Stellar registration failed.')
    }
  }

  async function attachSilentWitnessProof(nextProof: ProofPackage): Promise<ProofPackage> {
    if (!credentialSeed.trim() || !nullifierSeed.trim()) {
      throw new Error('Silent Witness requires your credential and nullifier seeds.')
    }

    setStage('proving')
    setMessage('Generating Noir UltraHonk proof in this browser.')

    const { fieldSecret } = await import('../utils')
    const [credentialSecret, nullifierSecret] = await Promise.all([
      fieldSecret('credential', credentialSeed.trim()),
      fieldSecret('nullifier', nullifierSeed.trim()),
    ])

    const { generateSilentWitnessProof } = await import('../noirClient')
    const silentWitness = await generateSilentWitnessProof({
      videoHash: nextProof.videoHash,
      credentialSecret,
      nullifierSecret,
    })

    const nextWithProof: ProofPackage = { ...nextProof, silentWitness }
    setProof(nextWithProof)
    return nextWithProof
  }

  return {
    selectedTier,
    setSelectedTier,
    selectedTierMeta,
    stage,
    file,
    proof,
    processedVideoUrl,
    credentialSeed,
    setCredentialSeed,
    nullifierSeed,
    setNullifierSeed,
    message,
    registration,
    networkMismatch,
    handleEvidence,
    registerProof,
  }
}
