export type IdentityTier = 'silent' | 'source' | 'seal'

export type Hex32 = string & { readonly __hex32: unique symbol }
export type HexBytes = string & { readonly __hexBytes: unique symbol }

export type SilentWitnessArtifacts = {
  publicInputs: HexBytes
  proof: HexBytes
}

export type RegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: string
  metadataHash: string
  proofId: string
  silentWitness?: {
    publicInputs: string
    proof: string
  }
  /** When true, routes silent-witness proofs through the quorum verifier set (#126). */
  useQuorum?: boolean
}

export type NormalizedRegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: Hex32
  metadataHash: Hex32
  proofId: Hex32
  silentWitness?: SilentWitnessArtifacts
  useQuorum?: boolean
}

export type RegisterProofResult = {
  hash: string
  status: string
}

export type ChainProofRecord = {
  videoHash: string
  metadataHash: string
  tier: number
  status: number
  createdAt: string
  source: string | null
  issuer: string | null
}

export type RegistryMethod =
  | 'register_anonymous_verified'
  | 'register_anon_verified_quorum'
  | 'register_source'
  | 'register_seal'
  | 'get_by_video'
  | 'propose_verifier_set_1'
  | 'propose_verifier_set_2'
  | 'propose_verifier_set_3'
  | 'activate_verifier_set'
  | 'disable_verifier_set'
  | 'get_active_verifier_set'
  | 'get_verifier_set'
  | 'get_verifier_set_member'
