import {
  Address,
  BASE_FEE,
  Contract,
  nativeToScVal,
  Networks,
  TransactionBuilder,
  scValToNative,
} from '@stellar/stellar-sdk'
import { rpc } from '@stellar/stellar-sdk'
import { signTransaction } from '@stellar/freighter-api'
import { asHex32, asHexBytes, bytesToHex, scBytes, scBytes32 } from './stellarEncoding'
import type {
  ChainProofRecord,
  IdentityTier,
  NormalizedRegisterProofInput,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
} from './stellarTypes'

const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

/**
 * The network passphrase the deployed contract was built against.
 * Exported so network-guard code can compare it with the wallet's
 * reported network without duplicating the constant.
 */
export const CONTRACT_NETWORK_PASSPHRASE: string = Networks.TESTNET

const NETWORK_PASSPHRASE = CONTRACT_NETWORK_PASSPHRASE
const READONLY_SOURCE = import.meta.env.VITE_STELLAR_READONLY_SOURCE ?? ''

// ---------------------------------------------------------------------------
// Proof registration (existing + quorum path)
// ---------------------------------------------------------------------------

/**
 * Register a proof on Stellar using the standard single-verifier path or
 * the new quorum-based path (when `useQuorum` is set in the input).
 */
export async function registerProofOnStellar(input: RegisterProofInput): Promise<RegisterProofResult> {
  const normalized = normalizeRegisterProofInput(input)
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(normalized.publicKey)
  const contract = new Contract(normalized.contractId)
  const method = methodForTier(normalized.tier, normalized.useQuorum)
  const operation = contract.call(method, ...argsForTier(normalized))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: normalized.publicKey,
  })

  if (signed.error) {
    throw new Error(signed.error.message)
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }

  return {
    hash: submitted.hash,
    status: submitted.status,
  }
}

// ---------------------------------------------------------------------------
// Proof lookup
// ---------------------------------------------------------------------------

export async function getProofByVideoHash(
  contractId: string,
  videoHash: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_by_video' satisfies RegistryMethod, scBytes32(asHex32(videoHash, 'videoHash'))))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }
  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  return {
    videoHash: bytesToHex(native.video_hash),
    metadataHash: bytesToHex(native.metadata_hash),
    tier: Number(native.tier),
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

// ---------------------------------------------------------------------------
// Verifier-set admin helpers (#126)
//
// These are admin-only operations used by governance tooling.
// They require a connected wallet (Freighter) with the admin key.
// ---------------------------------------------------------------------------

export interface VerifierSetProposalInput {
  contractId: string
  adminPublicKey: string
  /** Up to 3 verifier contract addresses (for propose_verifier_set_1/2/3). */
  members: string[]
  threshold: number
  circuitVersion: string
}

export interface VerifierSetResult {
  version: number
  memberCount: number
  threshold: number
  activeFrom: string
  retiredAt: string
  disabled: boolean
  circuitVersion: string
}

/**
 * Propose a new verifier set with 1–3 members (uses propose_verifier_set_1/2/3).
 * Returns the proposed version number (activated after timelock expires).
 */
export async function proposeVerifierSet(input: VerifierSetProposalInput): Promise<RegisterProofResult> {
  if (input.members.length < 1 || input.members.length > 3) {
    throw new Error('proposeVerifierSet supports 1–3 members. Use the contract CLI for larger sets.')
  }
  if (input.threshold < 1 || input.threshold > input.members.length) {
    throw new Error(`threshold must be between 1 and ${input.members.length}`)
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(input.adminPublicKey)
  const contract = new Contract(input.contractId)

  const adminScVal = new Address(input.adminPublicKey).toScVal()
  const thresholdScVal = nativeToScVal(input.threshold, { type: 'u32' })
  const circuitVersionScVal = nativeToScVal(input.circuitVersion, { type: 'string' })
  const memberScVals = input.members.map(m => new Address(m).toScVal())

  const methodName = (`propose_verifier_set_${input.members.length}`) as RegistryMethod
  const args = [adminScVal, ...memberScVals, thresholdScVal, circuitVersionScVal]

  const operation = contract.call(methodName, ...args)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: input.adminPublicKey,
  })
  if (signed.error) throw new Error(signed.error.message)

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)
  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }
  return { hash: submitted.hash, status: submitted.status }
}

/**
 * Activate the pending verifier set (timelock must have expired).
 */
export async function activateVerifierSet(contractId: string, adminPublicKey: string): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(adminPublicKey)
  const contract = new Contract(contractId)

  const operation = contract.call(
    'activate_verifier_set' satisfies RegistryMethod,
    new Address(adminPublicKey).toScVal(),
  )
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: adminPublicKey,
  })
  if (signed.error) throw new Error(signed.error.message)

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)
  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }
  return { hash: submitted.hash, status: submitted.status }
}

/**
 * Emergency-disable a verifier set version.
 */
export async function disableVerifierSet(
  contractId: string,
  adminPublicKey: string,
  version: number,
): Promise<RegisterProofResult> {
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(adminPublicKey)
  const contract = new Contract(contractId)

  const operation = contract.call(
    'disable_verifier_set' satisfies RegistryMethod,
    new Address(adminPublicKey).toScVal(),
    nativeToScVal(version, { type: 'u32' }),
  )
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: adminPublicKey,
  })
  if (signed.error) throw new Error(signed.error.message)

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted = await server.sendTransaction(signedTransaction)
  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    throw new Error(`Stellar RPC rejected the transaction: ${submitted.errorResultXdr}`)
  }
  return { hash: submitted.hash, status: submitted.status }
}

/**
 * Read the currently active verifier set (simulation, no signature required).
 */
export async function getActiveVerifierSet(
  contractId: string,
  sourceAddress?: string,
): Promise<VerifierSetResult | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) throw new Error('Set VITE_STELLAR_READONLY_SOURCE for read-only calls.')

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_active_verifier_set' satisfies RegistryMethod))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)
  if (rpc.Api.isSimulationError(simulation)) throw new Error(simulation.error)
  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) return null

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  return {
    version: Number(native.version),
    memberCount: Number(native.member_count),
    threshold: Number(native.threshold),
    activeFrom: native.active_from?.toString?.() ?? String(native.active_from),
    retiredAt: native.retired_at?.toString?.() ?? String(native.retired_at),
    disabled: Boolean(native.disabled),
    circuitVersion: String(native.circuit_version ?? ''),
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function normalizeRegisterProofInput(input: RegisterProofInput): NormalizedRegisterProofInput {
  return {
    ...input,
    videoHash: asHex32(input.videoHash, 'videoHash'),
    metadataHash: asHex32(input.metadataHash, 'metadataHash'),
    proofId: asHex32(input.proofId, 'proofId'),
    silentWitness: input.silentWitness
      ? {
          publicInputs: asHexBytes(input.silentWitness.publicInputs, 'silentWitness.publicInputs'),
          proof: asHexBytes(input.silentWitness.proof, 'silentWitness.proof'),
        }
      : undefined,
  }
}

/**
 * Select the contract method based on identity tier and quorum preference.
 *
 * - `silent` tier with `useQuorum=true`  → `register_anon_verified_quorum`
 * - `silent` tier with `useQuorum=false` → `register_anonymous_verified` (legacy)
 * - `seal`                               → `register_seal`
 * - `source`                             → `register_source`
 */
function methodForTier(tier: IdentityTier, useQuorum?: boolean): RegistryMethod {
  if (tier === 'silent') {
    return useQuorum ? 'register_anon_verified_quorum' : 'register_anonymous_verified'
  }
  if (tier === 'seal') return 'register_seal'
  return 'register_source'
}

function argsForTier(input: NormalizedRegisterProofInput) {
  const videoHash = scBytes32(input.videoHash)
  const metadataHash = scBytes32(input.metadataHash)
  const proofId = scBytes32(input.proofId)
  const address = new Address(input.publicKey).toScVal()

  if (input.tier === 'silent') {
    if (!input.silentWitness) {
      throw new Error('Silent Witness registration requires Noir proof artifacts.')
    }
    return [
      videoHash,
      metadataHash,
      proofId,
      scBytes(input.silentWitness.publicInputs),
      scBytes(input.silentWitness.proof),
    ]
  }

  return [address, videoHash, metadataHash, proofId]
}
