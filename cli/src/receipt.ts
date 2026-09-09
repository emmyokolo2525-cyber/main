import type { ProofManifest } from './manifest.js'
import type { ChainProofRecord, TransactionVerification } from './stellar-lookup.js'

/**
 * Normalised verification result that combines on-chain proof data with
 * the corresponding proof manifest into a single, portable record.
 */
export type VerificationReceipt = {
  /** Version of the receipt format. */
  version: 1
  /** When the verification was performed (ISO-8601). */
  verifiedAt: string
  /** The manifest that was verified. */
  manifest: ProofManifest
  /** Status of the on-chain registration transaction. */
  transaction: TransactionVerification
  /** The on-chain proof record (null if not found). */
  chainRecord: ChainProofRecord | null
  /** Overall verification result. */
  result: VerificationResult
}

/**
 * Discrete, machine-readable verification outcome.
 */
export type VerificationResult =
  | 'valid'
  | 'expired'
  | 'revoked'
  | 'not_found'
  | 'network_mismatch'
  | 'contract_mismatch'
  | 'pending'
  | 'failed'
  | 'error'

/**
 * Create a normalised verification receipt.
 */
export function createReceipt(
  manifest: ProofManifest,
  transaction: TransactionVerification,
  chainRecord: ChainProofRecord | null,
  result: VerificationResult,
): VerificationReceipt {
  return {
    version: 1,
    verifiedAt: new Date().toISOString(),
    manifest,
    transaction,
    chainRecord,
    result,
  }
}

/**
 * Render a human-readable summary of a verification receipt.
 */
export function formatReceipt(receipt: VerificationReceipt): string {
  const lines = [
    '═══════════════════════════════════════════',
    '  Harpocrates Verification Receipt',
    '═══════════════════════════════════════════',
    '',
    `  Result:       ${resultLabel(receipt.result)}`,
    `  Verified at:  ${receipt.verifiedAt}`,
    `  Proof ID:     ${receipt.manifest.proofId}`,
    `  Tier:         ${receipt.manifest.tier}`,
    `  Network:      ${receipt.manifest.network}`,
    `  Contract:     ${receipt.manifest.contractId}`,
    `  TX Hash:      ${receipt.transaction.txHash}`,
    `  TX Status:    ${receipt.transaction.status}`,
    '',
  ]

  if (receipt.chainRecord) {
    lines.push(
      `  On-chain status: ${receipt.chainRecord.status}`,
      `  Created at:      ${receipt.chainRecord.createdAt}`,
      `  Video hash:      ${receipt.chainRecord.videoHash}`,
      '',
    )
  }

  lines.push('═══════════════════════════════════════════')
  return lines.join('\n')
}

function resultLabel(result: VerificationResult): string {
  const labels: Record<VerificationResult, string> = {
    valid: '✅ VALID',
    expired: '⏱️  EXPIRED',
    revoked: '🚫 REVOKED',
    not_found: '❓ NOT FOUND',
    network_mismatch: '⚠️  NETWORK MISMATCH',
    contract_mismatch: '⚠️  CONTRACT MISMATCH',
    pending: '⏳ PENDING',
    failed: '❌ FAILED',
    error: '❗ ERROR',
  }
  return labels[result]
}
