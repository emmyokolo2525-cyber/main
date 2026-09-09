import { useEffect, useRef, useState, useCallback } from 'react'
import { EvidenceStateMachine, type EvidenceState, type EvidenceEvent } from '../evidenceStateMachine'
import { CheckpointStorage } from '../checkpointStorage'

export function useEvidenceState() {
  const machineRef = useRef<EvidenceStateMachine | null>(null)
  if (!machineRef.current) {
    machineRef.current = new EvidenceStateMachine()
  }

  const [state, setState] = useState<EvidenceState>(machineRef.current.getState())
  const [hasCheckpoint, setHasCheckpoint] = useState(CheckpointStorage.hasCheckpoint())

  useEffect(() => {
    const unsubscribe = machineRef.current!.subscribe((nextState) => {
      setState(nextState)
    })
    return unsubscribe
  }, [])

  const send = useCallback((event: EvidenceEvent) => {
    machineRef.current!.send(event)
  }, [])

  const setPassword = useCallback((password: string) => {
    machineRef.current!.setPassword(password)
  }, [])

  const loadCheckpoint = useCallback(async (password: string) => {
    try {
      const stored = await CheckpointStorage.load(password)
      if (stored) {
        machineRef.current = new EvidenceStateMachine(stored, password)
        setState(machineRef.current.getState())
        setHasCheckpoint(false) // Loaded, no longer just "has" it
        return true
      }
    } catch (e) {
      console.error(e)
    }
    return false
  }, [])

  const clearCheckpoint = useCallback(() => {
    CheckpointStorage.clear()
    setHasCheckpoint(false)
  }, [])

  return { state, send, setPassword, loadCheckpoint, clearCheckpoint, hasCheckpoint }
}
