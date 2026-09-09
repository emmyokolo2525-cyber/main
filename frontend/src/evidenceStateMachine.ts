import type { EvidenceStateData, SilentWitnessProofData } from './checkpointStorage'
import { CheckpointStorage } from './checkpointStorage'
import type { IdentityTier } from './stellar'

export type EvidenceEvent =
  | { type: 'START'; tier: IdentityTier; fileName: string }
  | { type: 'HASHED'; sourceHash: string }
  | {
      type: 'EMBEDDED'
      videoHash: string
      metadataHash: string
      proofId: string
      timestamp: string
    }
  | { type: 'PROVED'; silentWitness: SilentWitnessProofData }
  | { type: 'REGISTERING' }
  | { type: 'REGISTERED'; txHash: string }
  | { type: 'ERROR'; error: string }
  | { type: 'RESET' }

export type EvidenceState = EvidenceStateData

export class EvidenceStateMachine {
  private state: EvidenceState
  private password?: string
  private listeners: Set<(state: EvidenceState) => void> = new Set()

  constructor(initialState?: EvidenceState, password?: string) {
    this.password = password
    this.state = initialState ?? this.getInitialState()
  }

  public setPassword(password: string) {
    this.password = password
  }

  private getInitialState(): EvidenceState {
    return {
      stage: 'idle',
      tier: 'silent', // Default, will be overwritten by START
      updatedAt: Date.now(),
    }
  }

  public getState(): EvidenceState {
    return this.state
  }

  public subscribe(listener: (state: EvidenceState) => void): () => void {
    this.listeners.add(listener)
    listener(this.state) // Immediately call with current state
    return () => this.listeners.delete(listener)
  }

  public send(event: EvidenceEvent): void {
    const nextState = this.transition(this.state, event)
    if (nextState !== this.state) {
      this.state = { ...nextState, updatedAt: Date.now() }
      this.notifyListeners()
      this.persistState()
    }
  }

  private transition(state: EvidenceState, event: EvidenceEvent): EvidenceState {
    if (event.type === 'RESET') {
      return this.getInitialState()
    }

    if (event.type === 'ERROR') {
      return { ...state, stage: 'error', error: event.error }
    }

    switch (state.stage) {
      case 'idle':
      case 'error':
        if (event.type === 'START') {
          return {
            stage: 'hashing',
            tier: event.tier,
            fileName: event.fileName,
            error: undefined,
            updatedAt: Date.now(),
          }
        }
        break

      case 'hashing':
        if (event.type === 'HASHED') {
          return { ...state, stage: 'embedding', sourceHash: event.sourceHash }
        }
        break

      case 'embedding':
        if (event.type === 'EMBEDDED') {
          return {
            ...state,
            stage: state.tier === 'silent' ? 'proving' : 'ready',
            videoHash: event.videoHash,
            metadataHash: event.metadataHash,
            proofId: event.proofId,
            timestamp: event.timestamp,
          }
        }
        break

      case 'proving':
        if (event.type === 'PROVED') {
          return { ...state, stage: 'ready', silentWitness: event.silentWitness }
        }
        break

      case 'ready':
        if (event.type === 'REGISTERING') {
          return { ...state, stage: 'registering' }
        }
        break

      case 'registering':
        if (event.type === 'REGISTERED') {
          return { ...state, stage: 'registered', txHash: event.txHash, txStatus: 'confirmed' }
        }
        break
    }
    return state
  }

  private notifyListeners() {
    for (const listener of this.listeners) {
      listener(this.state)
    }
  }

  private async persistState() {
    if (!this.password) return

    // Do not persist idle state
    if (this.state.stage === 'idle' || this.state.stage === 'registered') {
      CheckpointStorage.clear()
      return
    }

    try {
      await CheckpointStorage.save(this.password, this.state)
    } catch {
      // Ignore storage errors in restricted environments
    }
  }
}
