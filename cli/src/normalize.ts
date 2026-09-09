import type { VerificationResult } from './receipt.js'

/**
 * Compute the overall verification result from a chain record's status
 * and the transaction state.
 */
export function computeResult(
  chainRecord: { status: number } | null,
  txStatus: string,
): VerificationResult {
  if (txStatus === 'missing') return 'not_found'
  if (txStatus === 'failed') return 'failed'
  if (txStatus === 'pending') return 'pending'

  if (!chainRecord) return 'not_found'

  // Chain proof status values (matching the Soroban contract):
  //   0 = Active, 1 = Revoked, 2 = Expired, 3 = Not Found
  switch (chainRecord.status) {
    case 0:
      return 'valid'
    case 1:
      return 'revoked'
    case 2:
      return 'expired'
    default:
      return 'not_found'
  }
}

/**
 * Known Stellar network passphrases mapped to human-readable names.
 */
const KNOWN_PASSPHRASES: Record<string, string> = {
  'Public Global Stellar Network ; September 2015': 'Mainnet',
  'Test SDF Network ; September 2015': 'Testnet',
  'Test SDF Future Network ; October 2022': 'Futurenet',
  'Local Sandbox Stellar Network ; September 2022': 'Sandbox',
  'Standalone Network ; February 2017': 'Standalone',
}

/**
 * Return a human-readable name for a network passphrase.
 */
export function networkName(passphrase: string): string {
  return KNOWN_PASSPHRASES[passphrase] ?? passphrase
}
