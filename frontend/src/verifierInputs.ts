/**
 * Canonical verifier-input codec for Harpocrates (codec `hpx-vi/1`).
 *
 * Browser/TypeScript side of a three-way codec that must agree byte for byte
 * with:
 *
 *   backend/verifier_inputs.py                          (Python)
 *   contracts/contracts/harpocrates-registry/src/lib.rs (Soroban / Rust)
 *
 * Agreement is enforced by the shared corpus in
 * `zk/vectors/verifier_conformance_v1.json`; see docs/zk-conformance-vectors.md.
 *
 * Every entry point is bounded, deterministic, and silent: rejections carry a
 * stable machine code and at most a field *name* — never witness material,
 * proof bytes, or public-input bytes.
 */

export const CODEC_ID = 'hpx-vi/1'

export const FIELD_LEN = 32
export const FIELD_COUNT = 4
export const PUBLIC_INPUTS_LEN = FIELD_LEN * FIELD_COUNT

export const MIN_PROOF_BYTES = 64
export const MAX_PROOF_BYTES = 65536

/**
 * Hard ceiling on accepted hex input length. Anything longer is rejected on the
 * string itself, before decoding, so a hostile caller cannot force a large
 * allocation just to be told the value is too big.
 */
export const MAX_HEX_CHARS = 2 * (MAX_PROOF_BYTES + 1024)

/** BN254 scalar field modulus. Canonical encodings are strictly below this. */
export const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * Byte-for-byte identical to `REVOCATION_DOMAIN_SEPARATOR` in the Soroban
 * registry: seven bytes of BN254 padding followed by 25 ASCII bytes.
 */
export const REVOCATION_DOMAIN_SEPARATOR_HEX =
  '00000000000000484152504f4352415445535f5245564f434154494f4e5f5631'

export const SCHEMA_SILENT_WITNESS = 'silent_witness/v1'
export const SCHEMA_REVOCATION_WITNESS = 'revocation_witness/v1'

export type VerifierSchema =
  | typeof SCHEMA_SILENT_WITNESS
  | typeof SCHEMA_REVOCATION_WITNESS

export type RejectCode =
  | 'malformed_hex'
  | 'length'
  | 'padding'
  | 'non_canonical_field'
  | 'zero_field'
  | 'domain_mismatch'
  | 'proof_undersize'
  | 'proof_oversize'
  | 'unknown_schema'

/** Rejection carrying a stable machine code and, at most, a field name. */
export class VerifierInputError extends Error {
  readonly code: RejectCode
  readonly field?: string

  constructor(code: RejectCode, field?: string) {
    super(field === undefined ? code : `${code}:${field}`)
    this.name = 'VerifierInputError'
    this.code = code
    this.field = field
  }

  /** Privacy-safe structured payload for logs and metrics. */
  signal(): Record<string, string> {
    const payload: Record<string, string> = { codec: CODEC_ID, rejectCode: this.code }
    if (this.field !== undefined) {
      payload.field = this.field
    }
    return payload
  }
}

export type SilentWitnessInputs = {
  videoHash: Uint8Array
  credentialRoot: Uint8Array
  nullifier: Uint8Array
}

export type RevocationWitnessInputs = {
  revocationRoot: Uint8Array
  nullifier: Uint8Array
  domainSeparator: Uint8Array
  credentialRoot: Uint8Array
}

const HEX_PATTERN = /^[0-9a-fA-F]*$/

/**
 * Decode an even-length, bounded hex string. Rejects odd lengths, non-hex
 * characters, and anything past {@link MAX_HEX_CHARS} without decoding it.
 */
export function decodeHex(
  value: string,
  field = 'value',
  oversizeCode: RejectCode = 'proof_oversize',
): Uint8Array {
  if (typeof value !== 'string') {
    throw new VerifierInputError('malformed_hex', field)
  }
  if (value.length > MAX_HEX_CHARS) {
    throw new VerifierInputError(oversizeCode, field)
  }
  if (value.length % 2 !== 0 || !HEX_PATTERN.test(value)) {
    throw new VerifierInputError('malformed_hex', field)
  }

  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function toBigInt(element: Uint8Array): bigint {
  let accumulator = 0n
  for (const byte of element) {
    accumulator = (accumulator << 8n) | BigInt(byte)
  }
  return accumulator
}

/** Is this 32-byte big-endian encoding strictly below the BN254 modulus? */
export function isCanonicalField(element: Uint8Array): boolean {
  return element.length === FIELD_LEN && toBigInt(element) < BN254_SCALAR_FIELD_MODULUS
}

/** Enforce the accepted proof-blob size window. */
export function checkProofBounds(proof: Uint8Array): void {
  if (proof.length < MIN_PROOF_BYTES) {
    throw new VerifierInputError('proof_undersize', 'proof')
  }
  if (proof.length > MAX_PROOF_BYTES) {
    throw new VerifierInputError('proof_oversize', 'proof')
  }
}

function splitFields(publicInputs: Uint8Array): Uint8Array[] {
  if (publicInputs.length !== PUBLIC_INPUTS_LEN) {
    throw new VerifierInputError('length', 'public_inputs')
  }
  const fields: Uint8Array[] = []
  for (let index = 0; index < FIELD_COUNT; index += 1) {
    fields.push(publicInputs.slice(index * FIELD_LEN, (index + 1) * FIELD_LEN))
  }
  return fields
}

function requireCanonical(fields: Uint8Array[], names: readonly string[]): void {
  for (let index = 0; index < fields.length; index += 1) {
    if (!isCanonicalField(fields[index])) {
      throw new VerifierInputError('non_canonical_field', names[index])
    }
  }
}

function requireNonZero(field: Uint8Array, name: string): void {
  if (field.every((byte) => byte === 0)) {
    throw new VerifierInputError('zero_field', name)
  }
}

/** A 128-bit half lives in the low 16 bytes; the high 16 must be zero. */
function requireHalfPadding(field: Uint8Array, name: string): Uint8Array {
  for (let index = 0; index < 16; index += 1) {
    if (field[index] !== 0) {
      throw new VerifierInputError('padding', name)
    }
  }
  return field.slice(16)
}

function concat(high: Uint8Array, low: Uint8Array): Uint8Array {
  const out = new Uint8Array(high.length + low.length)
  out.set(high, 0)
  out.set(low, high.length)
  return out
}

const SILENT_WITNESS_FIELDS = [
  'video_hash_hi',
  'video_hash_lo',
  'credential_root',
  'nullifier',
] as const

const REVOCATION_FIELDS = [
  'revocation_root',
  'nullifier',
  'domain_separator',
  'credential_root',
] as const

/** Parse `silent_witness/v1` public inputs in canonical check order. */
export function parseSilentWitnessInputs(publicInputs: Uint8Array): SilentWitnessInputs {
  const fields = splitFields(publicInputs)

  const high = requireHalfPadding(fields[0], 'video_hash_hi')
  const low = requireHalfPadding(fields[1], 'video_hash_lo')

  requireCanonical(fields, SILENT_WITNESS_FIELDS)

  requireNonZero(fields[2], 'credential_root')
  requireNonZero(fields[3], 'nullifier')

  return {
    videoHash: concat(high, low),
    credentialRoot: fields[2],
    nullifier: fields[3],
  }
}

/** Parse `revocation_witness/v1` public inputs in canonical check order. */
export function parseRevocationWitnessInputs(
  publicInputs: Uint8Array,
): RevocationWitnessInputs {
  const fields = splitFields(publicInputs)

  requireCanonical(fields, REVOCATION_FIELDS)

  requireNonZero(fields[0], 'revocation_root')
  requireNonZero(fields[1], 'nullifier')
  requireNonZero(fields[3], 'credential_root')

  const expectedDomain = decodeHex(REVOCATION_DOMAIN_SEPARATOR_HEX, 'domain_separator')
  const domain = fields[2]
  for (let index = 0; index < FIELD_LEN; index += 1) {
    if (domain[index] !== expectedDomain[index]) {
      throw new VerifierInputError('domain_mismatch', 'domain_separator')
    }
  }

  return {
    revocationRoot: fields[0],
    nullifier: fields[1],
    domainSeparator: domain,
    credentialRoot: fields[3],
  }
}

/** Dispatch to the parser for `schema`. */
export function parsePublicInputs(
  schema: string,
  publicInputs: Uint8Array,
): SilentWitnessInputs | RevocationWitnessInputs {
  if (schema === SCHEMA_SILENT_WITNESS) {
    return parseSilentWitnessInputs(publicInputs)
  }
  if (schema === SCHEMA_REVOCATION_WITNESS) {
    return parseRevocationWitnessInputs(publicInputs)
  }
  throw new VerifierInputError('unknown_schema', 'schema')
}

/**
 * Classify one conformance case. Returns `null` when the material is accepted,
 * otherwise the stable reject code. The check order — public inputs first,
 * then the proof blob — is part of the codec contract.
 */
export function classify(
  schema: string,
  publicInputsHex: string,
  proofHex: string,
): RejectCode | null {
  try {
    const publicInputs = decodeHex(publicInputsHex, 'public_inputs', 'length')
    parsePublicInputs(schema, publicInputs)
    const proof = decodeHex(proofHex, 'proof')
    checkProofBounds(proof)
  } catch (error) {
    if (error instanceof VerifierInputError) {
      return error.code
    }
    throw error
  }
  return null
}
