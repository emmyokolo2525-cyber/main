import type { TxState } from './stellarTypes'

export type TxEvent =
  | { type: 'SUBMIT' }
  | { type: 'TX_HASH_RECEIVED'; hash: string }
  | { type: 'CONFIRMED' }
  | { type: 'FAILED'; error: string }
  | { type: 'TIMEOUT' }
  | { type: 'RESET' }

export type TransactionMachineState = {
  status: TxState
  hash: string | null
  error: string | null
  updatedAt: number
}

const STORAGE_KEY = 'harpocrates_pending_tx'

export class TransactionStateMachine {
  private state: TransactionMachineState
  private listeners: Set<(state: TransactionMachineState) => void> = new Set()

  constructor(initialState?: TransactionMachineState) {
    if (initialState) {
      this.state = initialState
    } else {
      const stored = this.loadFromStorage()
      this.state = stored ?? this.getInitialState()
    }
  }

  private getInitialState(): TransactionMachineState {
    return {
      status: 'idle',
      hash: null,
      error: null,
      updatedAt: Date.now(),
    }
  }

  public getState(): TransactionMachineState {
    return this.state
  }

  public subscribe(listener: (state: TransactionMachineState) => void): () => void {
    this.listeners.add(listener)
    listener(this.state) // Immediately call with current state
    return () => this.listeners.delete(listener)
  }

  public send(event: TxEvent): void {
    const nextState = this.transition(this.state, event)
    if (nextState !== this.state) {
      this.state = { ...nextState, updatedAt: Date.now() }
      this.persistToStorage(this.state)
      this.notifyListeners()
    }
  }

  private transition(state: TransactionMachineState, event: TxEvent): TransactionMachineState {
    switch (state.status) {
      case 'idle':
      case 'failed':
      case 'timeout':
      case 'confirmed':
        if (event.type === 'SUBMIT') {
          return { ...state, status: 'submitting', error: null, hash: null }
        }
        if (event.type === 'RESET') {
          return this.getInitialState()
        }
        break

      case 'submitting':
        if (event.type === 'TX_HASH_RECEIVED') {
          return { ...state, status: 'awaiting_confirmation', hash: event.hash }
        }
        if (event.type === 'FAILED') {
          return { ...state, status: 'failed', error: event.error }
        }
        if (event.type === 'TIMEOUT') {
          return { ...state, status: 'timeout' }
        }
        break

      case 'awaiting_confirmation':
        if (event.type === 'CONFIRMED') {
          return { ...state, status: 'confirmed' }
        }
        if (event.type === 'FAILED') {
          return { ...state, status: 'failed', error: event.error }
        }
        if (event.type === 'TIMEOUT') {
          return { ...state, status: 'timeout' }
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

  private persistToStorage(state: TransactionMachineState) {
    if (state.status === 'awaiting_confirmation') {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
      } catch {
        // Ignore storage errors in restricted environments
      }
    } else {
      try {
        localStorage.removeItem(STORAGE_KEY)
      } catch {
        // Ignore
      }
    }
  }

  private loadFromStorage(): TransactionMachineState | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        const parsed = JSON.parse(stored) as TransactionMachineState
        // Only recover if it was actually awaiting confirmation recently
        // (Optional: add a threshold so old transactions aren't polling forever)
        if (parsed.status === 'awaiting_confirmation' && parsed.hash) {
           // check if older than say 1 hour, if so, timeout
           if (Date.now() - parsed.updatedAt > 60 * 60 * 1000) {
               parsed.status = 'timeout'
               this.persistToStorage(parsed) // this will remove it actually
               return null // treat as no valid pending state
           }
           return parsed
        }
      }
    } catch {
      // ignore
    }
    return null
  }
}
