/**
 * @harpocrates/cli
 *
 * Headless verification CLI and reusable SDK for the Harpocrates
 * privacy-preserving evidence protocol.
 *
 * ## SDK usage
 *
 * ```ts
 * import { createProofManifest, serializeManifest } from '@harpocrates/cli/manifest'
 * import { validateMetadata, canonicalMetadataHash } from '@harpocrates/cli/metadata'
 * import { lookupByVideoHash } from '@harpocrates/cli/stellar-lookup'
 * ```
 *
 * ## CLI usage
 *
 * ```sh
 * harpocrates verify --contract-id CC... --manifest proof.json
 * harpocrates manifest --input metadata.json --tx-hash abc... --contract-id CC...
 * harpocrates hash --file video.mp4
 * ```
 */

export { sha256, canonicalHash, asHex32, asHexBytes, bytesToHex, hexToBytes } from './hashing.js'
export {
  validateMetadata,
  canonicalMetadataHash,
  fileHash,
  ALLOWED_TIERS,
  REQUIRED_EMBED_METADATA,
} from './metadata.js'
export type { HarpocratesMetadata, IdentityTier } from './metadata.js'
export { createProofManifest, serializeManifest, parseManifest } from './manifest.js'
export type { ProofManifest, ManifestInput } from './manifest.js'
export { lookupByVideoHash, verifyTransaction } from './stellar-lookup.js'
export type { ChainProofRecord, StellarLookupOptions, TransactionVerification } from './stellar-lookup.js'
export { createReceipt, formatReceipt } from './receipt.js'
export type { VerificationReceipt, VerificationResult } from './receipt.js'
export { computeResult, networkName } from './normalize.js'
