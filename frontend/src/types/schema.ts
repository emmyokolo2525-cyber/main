export type PredicateType = 'Equality' | 'SetMembership' | 'Range'

export type AttributeDef = {
  name: string
  index: number
}

export type CredentialSchema = {
  schemaHash: string
  issuerNamespace: string
  version: number
  attributeCount: number
  attributes: AttributeDef[]
  active: boolean
  createdAt: string
}

export type Predicate = {
  predicateType: PredicateType
  attrIndex: number
  publicValue?: string
  setValues?: string[]
  setLen?: number
  lowerBound?: string
  upperBound?: string
}

export type SelectiveDisclosureInput = {
  schemaHash: string
  issuerNamespace: string
  schemaVersion: number
  credentialRoot: string
  nullifier: string
  videoHashHi: string
  videoHashLo: string
  verifierDigest: string
  circuitVersion: number
  evidenceDigest: string
  predicateCommitment: string
  numAttributes: number
  attrValues: string[]
  attrBlindings: string[]
  numPredicates: number
  predicates: Predicate[]
}

export type SelectiveDisclosureProof = {
  proof: string
  publicInputs: string
}

const SELECTIVE_DISCLOSURE_PUBLIC_INPUT_COUNT = 11

export const SCHEMA_CONSTANTS = {
  MAX_ATTRIBUTES: 16,
  MAX_PREDICATES: 8,
  MAX_SET_MEMBERS: 8,
  CURRENT_CIRCUIT_VERSION: 1,
  PUBLIC_INPUT_BYTE_LENGTH: SELECTIVE_DISCLOSURE_PUBLIC_INPUT_COUNT * 32,
} as const
