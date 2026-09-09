/**
 * Tests for useWallet hook.
 * Mocks stellar and networkGuard dynamic imports via vi.mock.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useWallet } from './useWallet'

const TESTNET = 'Test SDF Network ; September 2015'
const MAINNET = 'Public Global Stellar Network ; September 2015'

// Mock the modules that useWallet imports dynamically
vi.mock('../stellar', () => ({
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
  CONTRACT_NETWORK_PASSPHRASE: TESTNET,
}))

vi.mock('../networkGuard', () => ({
  checkNetworkMatch: vi.fn(),
}))

async function getStellarMock() {
  const mod = await import('../stellar')
  return mod as unknown as {
    connectFreighter: ReturnType<typeof vi.fn>
    getWalletNetwork: ReturnType<typeof vi.fn>
    CONTRACT_NETWORK_PASSPHRASE: string
  }
}

async function getNetworkGuardMock() {
  const mod = await import('../networkGuard')
  return mod as unknown as { checkNetworkMatch: ReturnType<typeof vi.fn> }
}

beforeEach(async () => {
  vi.clearAllMocks()
  const stellar = await getStellarMock()
  stellar.connectFreighter.mockResolvedValue('GPUBLIC_KEY_123')
  stellar.getWalletNetwork.mockResolvedValue(TESTNET)

  const guard = await getNetworkGuardMock()
  guard.checkNetworkMatch.mockReturnValue({ ok: true })
})

// ── successful connection ─────────────────────────────────────────────────

describe('useWallet – successful connection', () => {
  it('sets wallet address after connecting', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
  })

  it('clears networkMismatch on a matching network', async () => {
    const { result } = renderHook(() => useWallet())

    await act(async () => {
      await result.current.connectWallet()
    })

    expect(result.current.networkMismatch).toBeNull()
  })
})

// ── network mismatch ──────────────────────────────────────────────────────

describe('useWallet – network mismatch', () => {
  it('sets networkMismatch when the wallet is on the wrong network', async () => {
    const stellar = await getStellarMock()
    stellar.getWalletNetwork.mockResolvedValue(MAINNET)

    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch.mockReturnValue({
      ok: false,
      reason: 'Wallet is on Mainnet but the contract is deployed on Testnet.',
      remediation: 'Open Freighter, switch to Testnet, then reconnect.',
    })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      try {
        await result.current.connectWallet()
      } catch {
        // expected — mismatch throws
      }
    })

    expect(result.current.networkMismatch).toContain('Mainnet')
    expect(result.current.networkMismatch).toContain('Testnet')
  })

  it('still stores the wallet address even on mismatch', async () => {
    const guard = await getNetworkGuardMock()
    guard.checkNetworkMatch.mockReturnValue({
      ok: false,
      reason: 'Wrong network.',
      remediation: 'Switch.',
    })

    const { result } = renderHook(() => useWallet())

    await act(async () => {
      try {
        await result.current.connectWallet()
      } catch {
        // expected
      }
    })

    expect(result.current.wallet).toBe('GPUBLIC_KEY_123')
  })
})

// ── connectFreighter failure ──────────────────────────────────────────────

describe('useWallet – Freighter unavailable', () => {
  it('propagates the error from connectFreighter', async () => {
    const stellar = await getStellarMock()
    stellar.connectFreighter.mockRejectedValue(new Error('Freighter is not installed.'))

    const { result } = renderHook(() => useWallet())

    await expect(
      act(async () => {
        await result.current.connectWallet()
      }),
    ).rejects.toThrow('Freighter is not installed.')

    expect(result.current.wallet).toBe('')
  })
})
