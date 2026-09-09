import type { IdentityTier } from './metadata.js'
import { validateMetadata, ALLOWED_TIERS } from './metadata.js'

/**
 * Portable, versioned proof manifest matching the frontend `ProofManifest` type.
 *
 * Keys are alphabetically ordered so `JSON.stringify` is deterministic across
 * engines – critical for downstream hash verification.
 */
export type ProofManifest = {
  contractId: string
  metadataHash: string
  network: string
  proofId: string
  protocol: 'harpocrates'
  sourceHash: string
  tier: IdentityTier
  timestamp: string
  transactionRef: string
  version: number
  videoHash: string
}

const MANIFEST_VERSION = 1

export type ManifestInput = {
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
}

/**
 * Create a portable, versioned proof manifest from the supplied input.
 *
 * The output is a plain JSON-safe object with deterministic key ordering
 * (alphabetical) so that `JSON.stringify` always produces the same byte
 * sequence for identical inputs.  No seeds, private witness data, or other
 * secret material is included.
 */
export function createProofManifest(input: ManifestInput): ProofManifest {
  return {
    contractId: input.contractId,
    metadataHash: input.metadataHash,
    network: input.network,
    proofId: input.proofId,
    protocol: 'harpocrates',
    sourceHash: input.sourceHash,
    tier: input.tier,
    timestamp: input.timestamp,
    transactionRef: input.transactionRef,
    version: MANIFEST_VERSION,
    videoHash: input.videoHash,
  }
}

/**
 * Serialise a proof manifest to a deterministic JSON string.
 *
 * Keys are sorted alphabetically so the output is stable across runs and
 * engines, which is critical for downstream hash verification.
 */
export function serializeManifest(manifest: ProofManifest): string {
  return JSON.stringify(manifest, Object.keys(manifest).sort())
}

/**
 * Parse and validate a serialised proof manifest.
 *
 * Returns the typed manifest on success or throws on invalid input.
 */
export function parseManifest(json: string): ProofManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('manifest is not valid JSON')
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('manifest must be a JSON object')
  }

  const m = parsed as Record<string, unknown>

  if (m.protocol !== 'harpocrates') {
    throw new Error('manifest protocol must be "harpocrates"')
  }
  if (typeof m.version !== 'number') {
    throw new TypeError('manifest version must be a number')
  }

  // Reuse metadata validation for overlapping fields (tier, hex32 format).
  const tier = m.tier
  if (typeof tier !== 'string' || !ALLOWED_TIERS.has(tier)) {
    throw new Error(`manifest tier must be one of: ${[...ALLOWED_TIERS].join(', ')}`)
  }

  for (const field of ['proofId', 'network', 'contractId', 'transactionRef', 'videoHash', 'metadataHash', 'sourceHash', 'timestamp']) {
    if (typeof m[field] !== 'string') {
      throw new Error(`manifest.${field} must be a string`)
    }
  }

  return m as ProofManifest
}
