/// <reference lib="webworker" />
import { generateSilentWitnessProof } from '../noirClient'
import type { WorkerRequest, WorkerResponse, TransferableProofInput } from './proofWorker.types'

let activeRequestId: string | null = null

function post(msg: WorkerResponse) {
  ;(self as unknown as Worker).postMessage(msg)
}

function bufToStr(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf)
}

function zero(buf: ArrayBuffer) {
  new Uint8Array(buf).fill(0)
}

async function handleGenerate(requestId: string, input: TransferableProofInput) {
  if (activeRequestId !== null) {
    post({ type: 'ERROR', requestId, code: 'BUSY', message: 'A proof is already being generated.' })
    return
  }
  activeRequestId = requestId
  const credentialSecret = bufToStr(input.credentialSecret)
  const nullifierSecret = bufToStr(input.nullifierSecret)
  try {
    post({ type: 'PROGRESS', requestId, stage: 'loading_circuits' })
    post({ type: 'PROGRESS', requestId, stage: 'executing_helper' })
    const proof = await generateSilentWitnessProof({
      videoHash: input.videoHash,
      credentialSecret,
      nullifierSecret,
    })
    post({ type: 'RESULT', requestId, proof })
  } catch (err) {
    post({
      type: 'ERROR',
      requestId,
      code: 'PROOF_GENERATION_FAILED',
      message: err instanceof Error ? err.message : 'Unknown error during proof generation.',
    })
  } finally {
    zero(input.credentialSecret)
    zero(input.nullifierSecret)
    activeRequestId = null
  }
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data
  if (msg.type === 'GENERATE_PROOF') {
    void handleGenerate(msg.requestId, msg.input)
  }
  // CANCEL is handled by the main thread terminating this worker outright —
  // no in-worker cancel logic needed since generateProof can't be interrupted mid-flight.
}

post({ type: 'READY' })