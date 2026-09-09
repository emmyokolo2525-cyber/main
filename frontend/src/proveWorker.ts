import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
}

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null

self.addEventListener('message', async (event: MessageEvent<GenerateSilentWitnessInput>) => {
  const { videoHash, credentialSecret, nullifierSecret } = event.data

  try {
    const proof = await generateSilentWitnessProof({ videoHash, credentialSecret, nullifierSecret })
    self.postMessage({ type: 'success', proof })
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error instanceof Error ? error.message : 'Unknown error during proof generation',
    })
  }
})

async function generateSilentWitnessProof({
  videoHash,
  credentialSecret,
  nullifierSecret,
}: GenerateSilentWitnessInput): Promise<SilentWitnessProof> {
  const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])
  const video_hash_hi = BigInt(`0x${videoHash.slice(0, 32)}`).toString(10)
  const video_hash_lo = BigInt(`0x${videoHash.slice(32)}`).toString(10)
  const privateInputs = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
    video_hash_hi,
    video_hash_lo,
  }

  const helperResult = await new Noir(helperCircuit).execute(privateInputs)
  const [credentialRoot, nullifier] = helperResult.returnValue as string[]
  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
  }

  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = proofData.publicInputs.map(fieldToBytes32Hex).join('')

    return {
      credentialRoot: fieldToBytes32Hex(credentialRoot),
      nullifier: fieldToBytes32Hex(nullifier),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
  }
}

async function loadHelperCircuit() {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit() {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadCircuit(path: string) {
  const response = await fetch(path, { cache: 'no-store' }) // cache prohibition
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function fieldToBytes32Hex(value: string) {
  const normalized = value.startsWith('0x') ? value.slice(2) : BigInt(value).toString(16)
  if (normalized.length > 64) {
    throw new Error('Noir field is larger than 32 bytes.')
  }
  return normalized.padStart(64, '0')
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
