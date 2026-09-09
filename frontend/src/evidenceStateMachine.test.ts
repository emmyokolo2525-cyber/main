import { describe, it, expect, beforeEach } from 'vitest'
import { EvidenceStateMachine } from './evidenceStateMachine'

describe('EvidenceStateMachine', () => {
  let machine: EvidenceStateMachine

  beforeEach(() => {
    machine = new EvidenceStateMachine()
  })

  it('initializes in idle state', () => {
    expect(machine.getState().stage).toBe('idle')
  })

  it('transitions from idle to hashing', () => {
    machine.send({ type: 'START', tier: 'source', fileName: 'test.mp4' })
    const state = machine.getState()
    expect(state.stage).toBe('hashing')
    expect(state.tier).toBe('source')
    expect(state.fileName).toBe('test.mp4')
  })

  it('transitions through the normal flow for silent tier', () => {
    machine.send({ type: 'START', tier: 'silent', fileName: 'test.mp4' })
    expect(machine.getState().stage).toBe('hashing')

    machine.send({ type: 'HASHED', sourceHash: 'hash1' })
    expect(machine.getState().stage).toBe('embedding')
    expect(machine.getState().sourceHash).toBe('hash1')

    machine.send({
      type: 'EMBEDDED',
      videoHash: 'vh',
      metadataHash: 'mh',
      proofId: 'pId',
      timestamp: 'ts',
    })
    expect(machine.getState().stage).toBe('proving') // 'silent' goes to proving

    machine.send({
      type: 'PROVED',
      silentWitness: {
        credentialRoot: 'r',
        nullifier: 'n',
        proof: 'p',
        publicInputs: 'pi',
        proofBytes: 1,
        publicInputBytes: 1,
      },
    })
    expect(machine.getState().stage).toBe('ready')

    machine.send({ type: 'REGISTERING' })
    expect(machine.getState().stage).toBe('registering')

    machine.send({ type: 'REGISTERED', txHash: 'tx1' })
    expect(machine.getState().stage).toBe('registered')
    expect(machine.getState().txHash).toBe('tx1')
    expect(machine.getState().txStatus).toBe('confirmed')
  })

  it('transitions from embedding to ready for non-silent tier', () => {
    machine.send({ type: 'START', tier: 'source', fileName: 'test.mp4' })
    machine.send({ type: 'HASHED', sourceHash: 'hash1' })
    machine.send({
      type: 'EMBEDDED',
      videoHash: 'vh',
      metadataHash: 'mh',
      proofId: 'pId',
      timestamp: 'ts',
    })
    expect(machine.getState().stage).toBe('ready') // Skips proving
  })

  it('handles errors', () => {
    machine.send({ type: 'START', tier: 'source', fileName: 'test.mp4' })
    machine.send({ type: 'ERROR', error: 'Something went wrong' })
    expect(machine.getState().stage).toBe('error')
    expect(machine.getState().error).toBe('Something went wrong')
  })

  it('allows restart from error', () => {
    machine.send({ type: 'START', tier: 'source', fileName: 'test.mp4' })
    machine.send({ type: 'ERROR', error: 'err' })
    machine.send({ type: 'START', tier: 'silent', fileName: 'new.mp4' })
    expect(machine.getState().stage).toBe('hashing')
    expect(machine.getState().tier).toBe('silent')
  })
})
