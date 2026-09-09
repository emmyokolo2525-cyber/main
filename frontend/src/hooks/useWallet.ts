/**
 * useWallet — manages Freighter wallet connection and network validation.
 */

import { useState } from 'react'

export type UseWalletReturn = {
  wallet: string
  networkMismatch: string | null
  connectWallet: () => Promise<void>
}

export function useWallet(): UseWalletReturn {
  const [wallet, setWallet] = useState('')
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)

  async function connectWallet() {
    const { connectFreighter, getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE } = await import('../stellar')
    const { checkNetworkMatch } = await import('../networkGuard')

    const publicKey = await connectFreighter()
    setWallet(publicKey)

    const walletPassphrase = await getWalletNetwork()
    const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
    if (check.ok) {
      setNetworkMismatch(null)
    } else {
      setNetworkMismatch(`${check.reason} ${check.remediation}`)
      throw new Error(check.reason)
    }
  }

  return { wallet, networkMismatch, connectWallet }
}
