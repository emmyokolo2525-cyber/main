import { describe, expect, it } from 'vitest'
import { describeTxState } from './stellarTypes'

describe('describeTxState', () => {
  it('returns "Not submitted" for idle', () => {
    expect(describeTxState('idle')).toBe('Not submitted')
  })

  it('returns "Pending" for submitting', () => {
    expect(describeTxState('submitting')).toBe('Pending')
  })

  it('returns "Pending" for awaiting_confirmation', () => {
    expect(describeTxState('awaiting_confirmation')).toBe('Pending')
  })

  it('returns "Confirmed" for confirmed', () => {
    expect(describeTxState('confirmed')).toBe('Confirmed')
  })

  it('returns "Failed" for failed', () => {
    expect(describeTxState('failed')).toBe('Failed')
  })

  it('returns "Timed out" for timeout', () => {
    expect(describeTxState('timeout')).toBe('Timed out')
  })
})