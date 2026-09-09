import { beforeEach, describe, expect, it, vi } from 'vitest'
import { safeLocalStorage, safeSessionStorage } from './safeStorage'

const STORAGE_KEY = 'harpocrates:ui-preferences'

describe.each([
  ['localStorage', safeLocalStorage],
  ['sessionStorage', safeSessionStorage],
] as const)('%s safety boundary', (storageName, safeStorage) => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
    vi.restoreAllMocks()
  })

  it('persists only the documented public UI preferences', () => {
    const setItem = vi.spyOn(window[storageName as 'localStorage' | 'sessionStorage'], 'setItem')

    safeStorage.setUiPreferences({
      currentView: 'studio',
      selectedTier: 'silent',
    })

    expect(setItem).toHaveBeenCalledOnce()
    expect(setItem).toHaveBeenCalledWith(
      STORAGE_KEY,
      JSON.stringify({ currentView: 'studio', selectedTier: 'silent' }),
    )
    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'studio',
      selectedTier: 'silent',
    })
    expect(setItem.mock.instances[0]).toBe(window[storageName])
  })

  it('excludes seeds, proof witnesses, proofs, and raw private inputs', () => {
    const setItem = vi.spyOn(window[storageName as 'localStorage' | 'sessionStorage'], 'setItem')
    const sensitive = {
      currentView: 'verify',
      selectedTier: 'source',
      credentialSeed: 'credential-seed-secret',
      nullifierSeed: 'nullifier-seed-secret',
      witness: 'proof-witness-secret',
      proof: 'generated-proof-secret',
      privateInputs: {
        credential_secret: 'raw-credential-secret',
        nullifier_secret: 'raw-nullifier-secret',
      },
    }

    safeStorage.setUiPreferences(sensitive)

    expect(setItem).toHaveBeenCalledOnce()
    const serialized = setItem.mock.calls[0][1]
    expect(JSON.parse(serialized)).toEqual({
      currentView: 'verify',
      selectedTier: 'source',
    })
    expect(serialized).not.toContain('seed-secret')
    expect(serialized).not.toContain('witness-secret')
    expect(serialized).not.toContain('proof-secret')
    expect(serialized).not.toContain('raw-')
  })

  it('filters untrusted stored values on read', () => {
    window[storageName].setItem(
      STORAGE_KEY,
      JSON.stringify({
        currentView: 'landing',
        selectedTier: 'seal',
        credentialSeed: 'previously-stored-secret',
        witness: 'previously-stored-witness',
      }),
    )

    expect(safeStorage.getUiPreferences()).toEqual({
      currentView: 'landing',
      selectedTier: 'seal',
    })
  })
})
