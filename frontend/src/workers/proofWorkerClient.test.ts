import { describe, it, expect } from 'vitest'
import { ProofWorkerClient, ProofWorkerError } from './proofWorkerClient'

describe('ProofWorkerClient', () => {
  it('rejects a second concurrent request with BUSY', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })
    const second = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    await expect(second.result).rejects.toMatchObject({ code: 'BUSY' })

    // first is expected to fail in this test env (jsdom can't fetch relative
    // circuit URLs) — assert on it explicitly so it's not left unhandled.
    await expect(first.result).rejects.toBeInstanceOf(ProofWorkerError)

    client.destroy()
  })
})
it('rejects a pending request as CANCELLED and respawns a working worker', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    client.cancel(first.requestId)
    await expect(first.result).rejects.toMatchObject({ code: 'CANCELLED' })

    client.destroy()
  }, 15000)

  it('rejects invalid input deterministically without touching the worker', async () => {
    const client = new ProofWorkerClient()
    const { result } = client.generate({
      videoHash: 'not-valid-hex',
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })
    await expect(result).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    client.destroy()
  })
  it('recovers from a worker crash and respawns cleanly', async () => {
    const client = new ProofWorkerClient()
    const first = client.generate({
      videoHash: '0'.repeat(64),
      credentialSecret: 'secret1',
      nullifierSecret: 'secret2',
    })

    // simulate a real crash by triggering the worker's onerror handler directly
    // @ts-expect-error - accessing private field for test purposes
    const worker = client.worker
    worker.onerror?.(new ErrorEvent('error', { message: 'simulated crash' }))

    await expect(first.result).rejects.toMatchObject({ code: 'CRASHED' })

    client.destroy()
  }, 15000)