export type LineageOperation = 'crop' | 'transcode' | 'blur' | 'redact' | 'compose'

export type TransformationManifest = {
  protocol: 'harpocrates'
  version: number
  parentProofIds: string[]
  operationType: LineageOperation
  parametersDigest: string
  toolIdentity: string
  toolVersion: string
  outputDigest: string
  network: string
  actorAddress: string
}

export type TransformationManifestInput = {
  parentProofIds: string[]
  operationType: LineageOperation
  parametersDigest: string
  toolIdentity: string
  toolVersion: string
  outputDigest: string
  network: string
  actorAddress: string
}

const SUPPORTED_OPERATIONS = new Set<LineageOperation>(['crop', 'transcode', 'blur', 'redact', 'compose'])

export function createTransformationManifest(input: TransformationManifestInput): TransformationManifest {
  if (!SUPPORTED_OPERATIONS.has(input.operationType)) {
    throw new Error('Unsupported lineage operation')
  }

  return {
    protocol: 'harpocrates',
    version: 2,
    parentProofIds: input.parentProofIds,
    operationType: input.operationType,
    parametersDigest: input.parametersDigest,
    toolIdentity: input.toolIdentity,
    toolVersion: input.toolVersion,
    outputDigest: input.outputDigest,
    network: input.network,
    actorAddress: input.actorAddress,
  }
}

export function serializeTransformationManifest(manifest: TransformationManifest): string {
  return JSON.stringify(manifest, Object.keys(manifest).sort())
}
