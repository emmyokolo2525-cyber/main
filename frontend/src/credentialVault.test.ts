import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { CredentialVault } from './credentialVault'

describe('CredentialVault', () => {
  let vault: CredentialVault

  beforeEach(() => {
    window.localStorage.clear()
    vi.useFakeTimers()
    vault = new CredentialVault()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('should initially be locked and empty', () => {
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
    expect(vault.hasVault()).toBe(false)
  })

  it('should setup, unlock, and return seeds', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('myPassword123!', seeds)

    expect(vault.isLocked()).toBe(false)
    expect(vault.hasVault()).toBe(true)
    expect(vault.getSeeds()).toEqual(seeds)
  })

  it('should lock the vault on demand', async () => {
    const seeds = { credentialSeed: 'cred123', nullifierSeed: 'null456' }
    await vault.setup('pass', seeds)
    expect(vault.isLocked()).toBe(false)

    vault.lock()
    expect(vault.isLocked()).toBe(true)
    expect(vault.getSeeds()).toBeNull()
  })

  it('should lock automatically after inactivity timeout', async () => {
    const seeds = { credentialSeed: 'test', nullifierSeed: 'test2' }
    // 1 minute timeout for test
    const fastVault = new CredentialVault(60 * 1000)
    await fastVault.setup('pass', seeds)

    expect(fastVault.isLocked()).toBe(false)

    vi.advanceTimersByTime(30 * 1000)
    expect(fastVault.isLocked()).toBe(false) // 30s elapsed

    // Reset timeout by fetching seeds
    fastVault.getSeeds()

    vi.advanceTimersByTime(45 * 1000)
    expect(fastVault.isLocked()).toBe(false) // 45s elapsed since reset

    vi.advanceTimersByTime(20 * 1000)
    expect(fastVault.isLocked()).toBe(true) // 65s elapsed since reset, should lock
  })

  it('should restore from localStorage correctly with valid password', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    // Simulate page reload
    const restoredVault = new CredentialVault()
    expect(restoredVault.hasVault()).toBe(true)
    expect(restoredVault.isLocked()).toBe(true)

    const success = await restoredVault.unlock('secret')
    expect(success).toBe(true)
    expect(restoredVault.isLocked()).toBe(false)
    expect(restoredVault.getSeeds()).toEqual(seeds)
  })

  it('should fail to unlock with invalid password', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    const restoredVault = new CredentialVault()
    const success = await restoredVault.unlock('wrong')
    
    expect(success).toBe(false)
    expect(restoredVault.isLocked()).toBe(true)
  })

  it('should completely destroy vault data', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    expect(vault.hasVault()).toBe(true)

    vault.destroy()
    expect(vault.hasVault()).toBe(false)
    expect(vault.isLocked()).toBe(true)
    expect(window.localStorage.getItem('harpocrates:credential-vault')).toBeNull()
  })

  it('should detect unsupported vault versions', async () => {
    const seeds = { credentialSeed: 'a', nullifierSeed: 'b' }
    await vault.setup('secret', seeds)
    
    // Mutate version in localStorage
    const stored = JSON.parse(window.localStorage.getItem('harpocrates:credential-vault')!)
    stored.v = 999
    window.localStorage.setItem('harpocrates:credential-vault', JSON.stringify(stored))

    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Unsupported vault version: 999')
  })

  it('should detect completely corrupted envelopes', async () => {
    window.localStorage.setItem('harpocrates:credential-vault', 'this is not valid json')
    const restoredVault = new CredentialVault()
    await expect(restoredVault.unlock('secret')).rejects.toThrow('Vault corrupted: unable to parse envelope')
  })
})
