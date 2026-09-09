export type StellarNetwork = 'testnet' | 'public'

const EXPLORER_BASE: Record<StellarNetwork, string> = {
  testnet: 'https://stellar.expert/explorer/testnet',
  public: 'https://stellar.expert/explorer/public',
}

/**
 * Map a network passphrase to the stellar.expert network segment.
 * Falls back to 'testnet' for unrecognized passphrases rather than
 * throwing, since explorer links are a convenience, not a correctness
 * boundary — an unrecognized passphrase should never block rendering
 * the rest of the provenance panel.
 */
export function networkFromPassphrase(passphrase: string): StellarNetwork {
  if (passphrase.toLowerCase().includes('public')) return 'public'
  return 'testnet'
}

export function transactionExplorerUrl(network: StellarNetwork, txHash: string): string {
  return `${EXPLORER_BASE[network]}/tx/${txHash}`
}

export function contractExplorerUrl(network: StellarNetwork, contractId: string): string {
  return `${EXPLORER_BASE[network]}/contract/${contractId}`
}

export function accountExplorerUrl(network: StellarNetwork, publicKey: string): string {
  return `${EXPLORER_BASE[network]}/account/${publicKey}`
}
