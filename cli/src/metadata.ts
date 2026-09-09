import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { pipeline } from 'node:stream/promises'

/**
 * Metadata validation rules shared across the Harpocrates protocol.
 * These mirror the backend `validate_embed_metadata` / `REQUIRED_EMBED_METADATA`
 * constants so the CLI and SDK produce identical results.
 */

export const ALLOWED_TIERS = new Set(['silent', 'source', 'seal'])
export const REQUIRED_EMBED_METADATA = [
  'protocol',
  'version',
  'tier',
  'sourceHash',
  'proofId',
  'timestamp',
] as const

export type IdentityTier = 'silent' | 'source' | 'seal'

export type HarpocratesMetadata = {
  protocol: 'harpocrates'
  version: number
  tier: IdentityTier
  sourceHash: string
  proofId: string
  timestamp: string
  [key: string]: unknown
}

/**
 * Validate that `value` is a well-formed Harpocrates metadata object.
 * Throws with a descriptive message on failure; returns the typed object
 * on success so callers can use the narrowed type.
 */
export function validateMetadata(value: unknown): HarpocratesMetadata {
  if (!value || typeof value !== 'object') {
    throw new TypeError('metadata must be a JSON object')
  }

  const meta = value as Record<string, unknown>

  for (const field of REQUIRED_EMBED_METADATA) {
    if (!(field in meta)) {
      throw new Error(`metadata missing required field: ${field}`)
    }
  }

  if (meta.protocol !== 'harpocrates') {
    throw new Error('metadata protocol must be "harpocrates"')
  }

  if (typeof meta.version !== 'number') {
    throw new TypeError('metadata version must be a number')
  }

  if (!ALLOWED_TIERS.has(meta.tier as string)) {
    throw new Error(`metadata tier must be one of: ${[...ALLOWED_TIERS].join(', ')}`)
  }

  if (typeof meta.sourceHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(meta.sourceHash)) {
    throw new Error('metadata sourceHash must be a 32-byte hex string')
  }

  if (typeof meta.proofId !== 'string' || !/^[0-9a-fA-F]{64}$/.test(meta.proofId)) {
    throw new Error('metadata proofId must be a 32-byte hex string')
  }

  return meta as HarpocratesMetadata
}

/**
 * Compute a canonical SHA-256 hash of a metadata object.
 * Identical to the backend `canonical_metadata_hash` function.
 */
export function canonicalMetadataHash(metadata: HarpocratesMetadata): string {
  const canonical = JSON.stringify(metadata, Object.keys(metadata).sort())
  return createHash('sha256').update(canonical).digest('hex')
}

/**
 * Compute the SHA-256 hash of a file on disk using chunked streaming
 * to avoid buffering large files in memory.  This matches the behaviour
 * of the backend's ``sha256_file`` (1 MiB chunks).
 */
export async function fileHash(filePath: string): Promise<string> {
  const hash = createHash('sha256')
  await pipeline(createReadStream(filePath, { highWaterMark: 1024 * 1024 }), hash)
  return hash.digest('hex')
}
