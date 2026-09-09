import type { ChainProofRecord, IdentityTier } from '../stellarTypes'
import type { ProofManifest } from '../proofManifest'
import { networkFromPassphrase, transactionExplorerUrl, contractExplorerUrl } from './explorerLinks'

export const NOIR_CIRCUIT_VERSION = '1' as const

export type ProvenanceMismatch = {
  field: 'videoHash' | 'metadataHash' | 'tier'
  manifestValue: string
  chainValue: string
}

export type ProvenanceStaleness =
  | { stale: false }
  | { stale: true; reason: 'no-chain-record' | 'fetch-error' | 'fetched-long-ago' }

export type ProvenanceRecord = {
  circuit: {
    name: 'silent_witness'
    version: string
  }
  verifier: {
    contractId: string
    method: string
  }
  network: {
    passphrase: string
    rpcUrl: string
    label: string
  }
  ledger: {
    transactionHash: string | null
    status: number | null
    createdAt: string | null
  }
  metadata: {
    videoHash: string
    metadataHash: string
    sourceHash: string
  }
  links: {
    transaction: string | null
    contract: string
  }
  mismatches: ProvenanceMismatch[]
  staleness: ProvenanceStaleness
  fetchedAt: string
}

const STALE_AFTER_MS = 5 * 60 * 1000

type BuildProvenanceInput = {
  manifest: ProofManifest
  chainProof: ChainProofRecord | null
  rpcUrl: string
  transactionHash: string | null
  method: string
  fetchedAt?: Date
}

const TIER_TO_NUMBER: Record<IdentityTier, number> = {
  silent: 0,
  source: 1,
  seal: 2,
}

export function buildProvenanceRecord(input: BuildProvenanceInput): ProvenanceRecord {
  const fetchedAt = input.fetchedAt ?? new Date()
  const network = networkFromPassphrase(input.manifest.network)

  const mismatches = detectMismatches(input.manifest, input.chainProof)
  const staleness = computeStaleness(input.chainProof, fetchedAt)

  return {
    circuit: {
      name: 'silent_witness',
      version: NOIR_CIRCUIT_VERSION,
    },
    verifier: {
      contractId: input.manifest.contractId,
      method: input.method,
    },
    network: {
      passphrase: input.manifest.network,
      rpcUrl: input.rpcUrl,
      label: network === 'public' ? 'Stellar Public Network' : 'Stellar Testnet',
    },
    ledger: {
      transactionHash: input.transactionHash,
      status: input.chainProof?.status ?? null,
      createdAt: input.chainProof?.createdAt ?? null,
    },
    metadata: {
      videoHash: input.manifest.videoHash,
      metadataHash: input.manifest.metadataHash,
      sourceHash: input.manifest.sourceHash,
    },
    links: {
      transaction: input.transactionHash
        ? transactionExplorerUrl(network, input.transactionHash)
        : null,
      contract: contractExplorerUrl(network, input.manifest.contractId),
    },
    mismatches,
    staleness,
    fetchedAt: fetchedAt.toISOString(),
  }
}

function detectMismatches(
  manifest: ProofManifest,
  chainProof: ChainProofRecord | null,
): ProvenanceMismatch[] {
  if (!chainProof) return []

  const mismatches: ProvenanceMismatch[] = []

  if (manifest.videoHash !== chainProof.videoHash) {
    mismatches.push({
      field: 'videoHash',
      manifestValue: manifest.videoHash,
      chainValue: chainProof.videoHash,
    })
  }

  if (manifest.metadataHash !== chainProof.metadataHash) {
    mismatches.push({
      field: 'metadataHash',
      manifestValue: manifest.metadataHash,
      chainValue: chainProof.metadataHash,
    })
  }

  const manifestTierNumber = TIER_TO_NUMBER[manifest.tier]
  if (manifestTierNumber !== chainProof.tier) {
    mismatches.push({
      field: 'tier',
      manifestValue: String(manifestTierNumber),
      chainValue: String(chainProof.tier),
    })
  }

  return mismatches
}

function computeStaleness(
  chainProof: ChainProofRecord | null,
  fetchedAt: Date,
): ProvenanceStaleness {
  if (!chainProof) {
    return { stale: true, reason: 'no-chain-record' }
  }

  const createdAt = new Date(chainProof.createdAt)
  if (Number.isNaN(createdAt.getTime())) {
    return { stale: false }
  }

  if (fetchedAt.getTime() - createdAt.getTime() > STALE_AFTER_MS && chainProof.status === 0) {
    // Pending for a long time is worth flagging; confirmed old records are fine.
    return { stale: true, reason: 'fetched-long-ago' }
  }

  return { stale: false }
}