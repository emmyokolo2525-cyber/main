import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { TransactionStateMachine } from '../transactionStateMachine'

describe('TransactionStateMachine', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('starts in idle state', () => {
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('idle')
  })

  it('transitions to submitting on SUBMIT event', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    expect(machine.getState().status).toBe('submitting')
  })

  it('transitions to awaiting_confirmation and persists when TX_HASH_RECEIVED', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    machine.send({ type: 'TX_HASH_RECEIVED', hash: 'abc' })
    
    expect(machine.getState().status).toBe('awaiting_confirmation')
    expect(machine.getState().hash).toBe('abc')
    
    // Check persistence
    const stored = localStorage.getItem('harpocrates_pending_tx')
    expect(stored).toBeTruthy()
    expect(JSON.parse(stored!).hash).toBe('abc')
  })

  it('recovers from localStorage if awaiting_confirmation', () => {
    localStorage.setItem(
      'harpocrates_pending_tx',
      JSON.stringify({ status: 'awaiting_confirmation', hash: 'def', error: null, updatedAt: Date.now() })
    )
    
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('awaiting_confirmation')
    expect(machine.getState().hash).toBe('def')
  })

  it('clears localStorage when confirmed or failed', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    machine.send({ type: 'TX_HASH_RECEIVED', hash: 'abc' })
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeTruthy()

    machine.send({ type: 'CONFIRMED' })
    expect(machine.getState().status).toBe('confirmed')
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeNull()
  })
  
  it('times out old transactions when recovering', () => {
    localStorage.setItem(
      'harpocrates_pending_tx',
      JSON.stringify({ status: 'awaiting_confirmation', hash: 'def', error: null, updatedAt: Date.now() - 2 * 60 * 60 * 1000 })
    )
    
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('idle') // It fell back to initial state because the old one timed out
    // and storage should be cleared by the persist logic since it timed out
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeNull()
  })
})
