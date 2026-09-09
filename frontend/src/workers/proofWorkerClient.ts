import type {
  WorkerRequest,
  WorkerResponse,
  SilentWitnessProof,
  ProofErrorCode,
} from './proofWorker.types'
const PROOF_TIMEOUT_MS = 60_000
const HEX64 = /^[0-9a-fA-F]{64}$/
const MAX_SECRET_BYTES = 256

function validateInput(input: GenerateSilentWitnessInput): ProofWorkerError | null {
  if (!HEX64.test(input.videoHash)) {
    return new ProofWorkerError('INVALID_INPUT', 'videoHash must be a 64-character hex string.')
  }
  if (!input.credentialSecret || !input.nullifierSecret) {
    return new ProofWorkerError('INVALID_INPUT', 'credentialSecret and nullifierSecret are required.')
  }
  const credBytes = new TextEncoder().encode(input.credentialSecret).length
  const nullBytes = new TextEncoder().encode(input.nullifierSecret).length
  if (credBytes > MAX_SECRET_BYTES || nullBytes > MAX_SECRET_BYTES) {
    return new ProofWorkerError('INVALID_INPUT', 'Secret input exceeds maximum allowed size.')
  }
  return null
}

export type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
}

export class ProofWorkerError extends Error {
  code: ProofErrorCode
  constructor(code: ProofErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

type PendingJob = {
  resolve: (proof: SilentWitnessProof) => void
  reject: (err: ProofWorkerError) => void
  onProgress?: (stage: string) => void
}

export class ProofWorkerClient {
  private worker: Worker
  private pending: Map<string, PendingJob> = new Map()

  constructor() {
    this.worker = this.spawn()
  }

  private spawn(): Worker {
    const worker = new Worker(new URL('./proofWorker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => this.handleMessage(event.data)
    worker.onerror = () => this.handleCrash()
    worker.onmessageerror = () => this.handleCrash()
    return worker
  }

  private handleMessage(msg: WorkerResponse) {
    if (msg.type === 'READY') return
    const job = this.pending.get('requestId' in msg ? msg.requestId : '')
    if (!job) return
    if (msg.type === 'PROGRESS') {
      job.onProgress?.(msg.stage)
    } else if (msg.type === 'RESULT') {
      this.pending.delete(msg.requestId)
      job.resolve(msg.proof)
    } else if (msg.type === 'ERROR') {
      this.pending.delete(msg.requestId)
      job.reject(new ProofWorkerError(msg.code, msg.message))
    } else if (msg.type === 'CANCELLED') {
      this.pending.delete(msg.requestId)
      job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
    }
  }

  private handleCrash() {
    for (const [, job] of this.pending) {
      job.reject(new ProofWorkerError('CRASHED', 'The proof worker crashed unexpectedly.'))
    }
    this.pending.clear()
    this.worker.terminate()
    this.worker = this.spawn()
  }
  private timeoutJob(requestId: string) {
    const job = this.pending.get(requestId)
    if (!job) return
    this.pending.delete(requestId)
    job.reject(new ProofWorkerError('TIMEOUT', 'Proof generation timed out.'))
    this.worker.terminate()
    this.worker = this.spawn()
  }

generate(
    input: GenerateSilentWitnessInput,
    onProgress?: (stage: string) => void,
  ): { requestId: string; result: Promise<SilentWitnessProof> } {
    const validationError = validateInput(input)
    if (validationError) {
      return { requestId: '', result: Promise.reject(validationError) }
    }
    const requestId = crypto.randomUUID()
    const credentialSecret = new TextEncoder().encode(input.credentialSecret).buffer
    const nullifierSecret = new TextEncoder().encode(input.nullifierSecret).buffer

const result = new Promise<SilentWitnessProof>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.timeoutJob(requestId)
      }, PROOF_TIMEOUT_MS)

      this.pending.set(requestId, {
        resolve: (proof) => {
          clearTimeout(timeoutId)
          resolve(proof)
        },
        reject: (err) => {
          clearTimeout(timeoutId)
          reject(err)
        },
        onProgress,
      })

      const msg: WorkerRequest = {
        type: 'GENERATE_PROOF',
        requestId,
        input: { videoHash: input.videoHash, credentialSecret, nullifierSecret },
      }
      this.worker.postMessage(msg, [credentialSecret, nullifierSecret])
    })

    return { requestId, result }
  }

  cancel(requestId: string) {
    const job = this.pending.get(requestId)
    if (!job) return
    this.pending.delete(requestId)
    job.reject(new ProofWorkerError('CANCELLED', 'Proof generation was cancelled.'))
    this.worker.terminate()
    this.worker = this.spawn()
  }

  destroy() {
    this.worker.terminate()
  }
}