import type { ChainProofRecord } from '../stellarTypes'
import { shortHash } from '../utils'

type Props = {
  chainProof: ChainProofRecord | null
}

export function ChainProofPanel({ chainProof }: Props) {
  if (!chainProof) {
    return <p className="muted">No on-chain match loaded.</p>
  }

  return (
    <div className="chain-grid">
      <span>Tier</span>
      <strong>{chainProof.tier}</strong>
      <span>Status</span>
      <strong>{chainProof.status}</strong>
      <span>Source</span>
      <code>{chainProof.source ? shortHash(chainProof.source) : 'None'}</code>
      <span>Metadata</span>
      <code>{shortHash(chainProof.metadataHash)}</code>
    </div>
  )
}
