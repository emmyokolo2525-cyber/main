import { useEffect, useState } from 'react'
import { TransactionStateMachine, type TransactionMachineState, type TxEvent } from '../transactionStateMachine'

export function useTransactionState() {
  // Hold the machine instance in state so it's stable across renders
  const [machine] = useState(() => new TransactionStateMachine())
  const [state, setState] = useState<TransactionMachineState>(() => machine.getState())

  useEffect(() => {
    const unsubscribe = machine.subscribe((nextState) => {
      setState(nextState)
    })
    return unsubscribe
  }, [machine])

  const send = (event: TxEvent) => {
    machine.send(event)
  }

  return { state, send }
}
