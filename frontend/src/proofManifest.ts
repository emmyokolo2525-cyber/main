import type { IdentityTier } from './stellarTypes'

const MANIFEST_VERSION = 2

export type ProofManifest = {
  protocol: 'harpocrates'
  version: number
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
  /** Scope field element (BN254) for scoped nullifier derivation. '0' = global. */
  verifierScope: string
  /** Epoch number for scoped nullifier. 0 = unscoped/legacy. */
  epoch: number
  /** Human-readable scope name (optional, for display only). */
  scopeName?: string
  /** Selective disclosure proof (optional, added by holder when proving predicates). */
  selectiveDisclosure?: SelectiveDisclosureManifest
}

/**
 * Selective disclosure manifest: embedded in a ProofManifest when the holder
 * proves bounded predicates over issuer-certified attributes.
 */
export type SelectiveDisclosureManifest = {
  schemaHash: string
  publicInputs: string
  predicateCommitment: string
  circuitVersion: number
}

export type ProofManifestInput = {
  proofId: string
  tier: IdentityTier
  network: string
  contractId: string
  transactionRef: string
  videoHash: string
  metadataHash: string
  sourceHash: string
  timestamp: string
  /** Scope field element. Defaults to '0' (global) for backward compatibility. */
  verifierScope?: string
  /** Epoch number. Defaults to 0 for backward compatibility. */
  epoch?: number
  /** Human-readable scope name (optional, for display only). */
  scopeName?: string
  /** Selective disclosure proof (optional, added by holder when proving predicates). */
  selectiveDisclosure?: SelectiveDisclosureManifest
}

/**
 * Create a portable, versioned proof manifest from the supplied input.
 *
 * The output is a plain JSON-safe object with deterministic key ordering
 * (alphabetical) so that `JSON.stringify` always produces the same byte
 * sequence for identical inputs.  No seeds, private witness data, or other
 * secret material is included.
 */
export function createProofManifest(input: ProofManifestInput): ProofManifest {
  const manifest: ProofManifest = {
    protocol: 'harpocrates',
    version: MANIFEST_VERSION,
    proofId: input.proofId,
    tier: input.tier,
    network: input.network,
    contractId: input.contractId,
    transactionRef: input.transactionRef,
    videoHash: input.videoHash,
    metadataHash: input.metadataHash,
    sourceHash: input.sourceHash,
    timestamp: input.timestamp,
    verifierScope: input.verifierScope ?? '0',
    epoch: input.epoch ?? 0,
  }

  if (input.scopeName) {
    manifest.scopeName = input.scopeName
  }

  if (input.selectiveDisclosure) {
    manifest.selectiveDisclosure = input.selectiveDisclosure
  }

  return manifest
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
 * Check whether a manifest is a v1 (legacy) or v2+ (scoped) manifest.
 * V1 manifests do not have verifierScope or epoch fields.
 */
export function isLegacyManifest(manifest: ProofManifest): boolean {
  return manifest.version < 2
}
