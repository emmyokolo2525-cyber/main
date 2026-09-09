import type { IdentityTier } from './stellarTypes'

const RECEIPT_PROTOCOL = 'harpocrates-verification-receipt'
const RECEIPT_VERSION = 1
const RECEIPT_ALGORITHM = 'ECDSA_P256_SHA256'
const MAX_RECEIPT_BYTES = 8_192
const MAX_QR_PAYLOAD_BYTES = 4_096

export type VerificationReceiptPayload = {
  protocol: typeof RECEIPT_PROTOCOL
  version: typeof RECEIPT_VERSION
  result: 'verified' | 'unverified'
  verifiedAt: string
  proofId: string
  videoHash: string
  metadataHash: string
  tier: IdentityTier
  networkPassphrase: string
  contractId: string
  ledgerSequence: number | null
  transactionHash: string | null
  circuitVersion: string
  verifierVersion: string
  signer: {
    keyId: string
    algorithm: typeof RECEIPT_ALGORITHM
  }
}

export type SignedVerificationReceipt = VerificationReceiptPayload & {
  signature: string
}

export type VerificationReceiptInput = Omit<VerificationReceiptPayload, 'protocol' | 'version' | 'signer'>

export type ReceiptVerificationOptions = {
  keys: Record<string, JsonWebKey>
  expectedNetworkPassphrase?: string
  expectedProofId?: string
  now?: Date
  keyValidity?: Record<string, { notBefore?: string; notAfter?: string }>
}

export type ReceiptVerificationResult =
  | { valid: true; receipt: SignedVerificationReceipt }
  | { valid: false; reason: string }

export async function signVerificationReceipt(
  input: VerificationReceiptInput,
  keyId: string,
  signingKey: CryptoKey,
): Promise<SignedVerificationReceipt> {
  const payload: VerificationReceiptPayload = {
    ...input,
    protocol: RECEIPT_PROTOCOL,
    version: RECEIPT_VERSION,
    signer: { keyId, algorithm: RECEIPT_ALGORITHM },
  }
  assertPayload(payload)
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKey,
    toArrayBuffer(utf8(canonicalize(payload))),
  )
  const receipt = { ...payload, signature: base64UrlEncode(new Uint8Array(signature)) }
  assertReceiptSize(receipt, MAX_RECEIPT_BYTES)
  return receipt
}

/** Encode a signed receipt as portable JSON suitable for a downloaded file. */
export function serializeVerificationReceipt(receipt: SignedVerificationReceipt): string {
  assertReceiptSize(receipt, MAX_RECEIPT_BYTES)
  return canonicalize(receipt)
}

/** Encode a compact, URL-safe receipt for a QR payload. */
export function encodeReceiptForQr(receipt: SignedVerificationReceipt): string {
  const encoded = base64UrlEncode(utf8(serializeVerificationReceipt(receipt)))
  if (encoded.length > MAX_QR_PAYLOAD_BYTES) {
    throw new Error('receipt exceeds the QR payload size limit')
  }
  return encoded
}

export function decodeReceiptFromQr(encoded: string): SignedVerificationReceipt {
  if (encoded.length > MAX_QR_PAYLOAD_BYTES) {
    throw new Error('receipt exceeds the QR payload size limit')
  }
  try {
    const receipt = JSON.parse(new TextDecoder().decode(base64UrlDecode(encoded))) as SignedVerificationReceipt
    assertReceiptSize(receipt, MAX_RECEIPT_BYTES)
    return receipt
  } catch (error) {
    throw new Error(
      `invalid receipt encoding: ${error instanceof Error ? error.message : 'unknown error'}`,
      { cause: error },
    )
  }
}

/** Verify the receipt itself offline. It does not verify or reveal the underlying proof. */
export async function verifyVerificationReceipt(
  receipt: SignedVerificationReceipt,
  options: ReceiptVerificationOptions,
): Promise<ReceiptVerificationResult> {
  try {
    assertReceiptSize(receipt, MAX_RECEIPT_BYTES)
    assertPayload(receipt)
    if (typeof receipt.signature !== 'string' || !receipt.signature) throw new Error('missing signature')
    if (options.expectedNetworkPassphrase && receipt.networkPassphrase !== options.expectedNetworkPassphrase) {
      throw new Error('receipt network does not match the expected network')
    }
    if (options.expectedProofId && receipt.proofId !== options.expectedProofId) {
      throw new Error('receipt proof does not match the expected proof')
    }
    assertKeyValidity(receipt, options.keyValidity?.[receipt.signer.keyId], options.now ?? new Date())
    const key = options.keys[receipt.signer.keyId]
    if (!key) throw new Error('signer key is unknown')
    const publicKey = await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      toArrayBuffer(base64UrlDecode(receipt.signature)),
      toArrayBuffer(utf8(canonicalize(unsignedReceipt(receipt)))),
    )
    return valid ? { valid: true, receipt } : { valid: false, reason: 'receipt signature is invalid' }
  } catch (error) {
    return { valid: false, reason: error instanceof Error ? error.message : 'invalid receipt' }
  }
}

function unsignedReceipt(receipt: SignedVerificationReceipt): VerificationReceiptPayload {
  const payload = { ...receipt } as Partial<SignedVerificationReceipt>
  delete payload.signature
  return payload as VerificationReceiptPayload
}

function assertPayload(payload: VerificationReceiptPayload): void {
  if (payload.protocol !== RECEIPT_PROTOCOL || payload.version !== RECEIPT_VERSION) throw new Error('unsupported receipt version')
  if (payload.result !== 'verified' && payload.result !== 'unverified') throw new Error('receipt result is invalid')
  if (!isHex32(payload.proofId) || !isHex32(payload.videoHash) || !isHex32(payload.metadataHash)) throw new Error('receipt digests must be 32-byte hex strings')
  if (!['silent', 'source', 'seal'].includes(payload.tier)) throw new Error('receipt tier is invalid')
  if (!isNonEmptyString(payload.networkPassphrase) || !isNonEmptyString(payload.contractId) || !isNonEmptyString(payload.circuitVersion) || !isNonEmptyString(payload.verifierVersion)) throw new Error('receipt metadata is incomplete')
  if (!isNonEmptyString(payload.signer.keyId) || payload.signer.algorithm !== RECEIPT_ALGORITHM) throw new Error('receipt signer is invalid')
  if (!Number.isInteger(payload.ledgerSequence) && payload.ledgerSequence !== null) throw new Error('receipt ledger sequence is invalid')
  if (payload.transactionHash !== null && !isHex32(payload.transactionHash)) throw new Error('receipt transaction hash is invalid')
  const verifiedAt = new Date(payload.verifiedAt)
  if (!isNonEmptyString(payload.verifiedAt) || Number.isNaN(verifiedAt.getTime())) throw new Error('receipt verification time is invalid')
}

function assertKeyValidity(receipt: VerificationReceiptPayload, validity: { notBefore?: string; notAfter?: string } | undefined, now: Date): void {
  if (!validity) return
  const verifiedAt = new Date(receipt.verifiedAt)
  const notBefore = validity.notBefore ? new Date(validity.notBefore) : undefined
  const notAfter = validity.notAfter ? new Date(validity.notAfter) : undefined
  if ((notBefore && verifiedAt < notBefore) || (notAfter && verifiedAt > notAfter) || (notAfter && now > notAfter)) {
    throw new Error('receipt signer key is stale or was not valid at verification time')
  }
}

function assertReceiptSize(value: unknown, limit: number): void {
  if (utf8(canonicalize(value)).byteLength > limit) throw new Error('receipt exceeds the size limit')
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url data')
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function isHex32(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}
