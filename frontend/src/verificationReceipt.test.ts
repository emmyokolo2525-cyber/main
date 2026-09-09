import { beforeAll, describe, expect, it } from 'vitest'
import {
  decodeReceiptFromQr,
  encodeReceiptForQr,
  signVerificationReceipt,
  serializeVerificationReceipt,
  verifyVerificationReceipt,
  type VerificationReceiptInput,
} from './verificationReceipt'

const input: VerificationReceiptInput = {
  result: 'verified',
  verifiedAt: '2026-07-26T12:00:00.000Z',
  proofId: 'a'.repeat(64),
  videoHash: 'b'.repeat(64),
  metadataHash: 'c'.repeat(64),
  tier: 'silent',
  networkPassphrase: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHK3M',
  ledgerSequence: 12345,
  transactionHash: 'd'.repeat(64),
  circuitVersion: 'silent-witness-v1',
  verifierVersion: 'registry-v1',
}

let privateKey: CryptoKey
let publicKey: JsonWebKey

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  privateKey = pair.privateKey
  publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey)
})

describe('signed verification receipts', () => {
  it('creates stable file and QR encodings that verify offline', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    expect(serializeVerificationReceipt(receipt)).toBe(serializeVerificationReceipt(receipt))
    expect(decodeReceiptFromQr(encodeReceiptForQr(receipt))).toEqual(receipt)
    await expect(verifyVerificationReceipt(receipt, {
      keys: { 'verifier-2026-07': publicKey },
      expectedNetworkPassphrase: input.networkPassphrase,
      expectedProofId: input.proofId,
    })).resolves.toMatchObject({ valid: true })
  })

  it('rejects tampered, substituted-proof, wrong-network, and unknown-key receipts', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    await expect(verifyVerificationReceipt({ ...receipt, result: 'unverified' }, { keys: { 'verifier-2026-07': publicKey } })).resolves.toMatchObject({ valid: false })
    await expect(verifyVerificationReceipt(receipt, { keys: { 'verifier-2026-07': publicKey }, expectedProofId: 'e'.repeat(64) })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/proof/) })
    await expect(verifyVerificationReceipt(receipt, { keys: { 'verifier-2026-07': publicKey }, expectedNetworkPassphrase: 'Public Global Stellar Network ; September 2015' })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/network/) })
    await expect(verifyVerificationReceipt(receipt, { keys: {} })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/unknown/) })
  })

  it('rejects stale signing keys', async () => {
    const receipt = await signVerificationReceipt(input, 'verifier-2026-07', privateKey)
    await expect(verifyVerificationReceipt(receipt, {
      keys: { 'verifier-2026-07': publicKey },
      keyValidity: { 'verifier-2026-07': { notAfter: '2026-07-25T00:00:00.000Z' } },
      now: new Date('2026-07-26T12:00:00.000Z'),
    })).resolves.toMatchObject({ valid: false, reason: expect.stringMatching(/stale/) })
  })
})
