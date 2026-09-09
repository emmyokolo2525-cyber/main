import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { CheckpointStorage, type EvidenceStateData } from './checkpointStorage'

describe('CheckpointStorage', () => {
  beforeEach(() => {
    CheckpointStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    CheckpointStorage.clear()
  })

  it('saves and loads a valid checkpoint', async () => {
    const state: EvidenceStateData = {
      stage: 'hashing',
      tier: 'silent',
      fileName: 'test.mp4',
      updatedAt: Date.now(),
    }
    const password = 'test-password'

    await CheckpointStorage.save(password, state)
    expect(CheckpointStorage.hasCheckpoint()).toBe(true)

    const loaded = await CheckpointStorage.load(password)
    expect(loaded).toBeDefined()
    expect(loaded?.stage).toBe('hashing')
    expect(loaded?.fileName).toBe('test.mp4')
  })

  it('fails to load with incorrect password', async () => {
    const state: EvidenceStateData = {
      stage: 'hashing',
      tier: 'silent',
      fileName: 'test.mp4',
      updatedAt: Date.now(),
    }

    await CheckpointStorage.save('correct-password', state)

    await expect(CheckpointStorage.load('wrong-password')).rejects.toThrow('Invalid checkpoint password')
  })

  it('expires old checkpoints', async () => {
    const state: EvidenceStateData = {
      stage: 'hashing',
      tier: 'silent',
      fileName: 'test.mp4',
      updatedAt: Date.now() - 2 * 60 * 60 * 1000, // 2 hours ago
    }

    await CheckpointStorage.save('pwd', state)
    
    // Max age 1 hour
    const loaded = await CheckpointStorage.load('pwd', 60 * 60 * 1000)
    expect(loaded).toBeNull()
    expect(CheckpointStorage.hasCheckpoint()).toBe(false)
  })
})
