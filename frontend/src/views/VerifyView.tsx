import { CheckCircle2, Upload } from 'lucide-react'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { EventList } from '../components/EventList'
import { shortHash } from '../utils'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'

type Props = {
  wallet: string
  verification: UseVerificationReturn
  provenanceRecord: ProvenanceRecord | null
}

export function VerifyView({ wallet, verification, provenanceRecord }: Props) {
  const { verifyHash, verifyResult, events, chainProof, verifyEvidence, loadEvents } = verification

  return (
    <section className="workspace app-page verify-page" id="verify">
      <div className="studio verify-studio">
        <header className="page-header">
          <h2>Verify Artifact</h2>
          <p>Inspect a received video against embedded metadata and the Stellar registry.</p>
        </header>

        <label className="dropzone">
          <Upload size={20} aria-hidden="true" />
          <span>Drop or choose a received video</span>
          <input
            type="file"
            accept="video/*"
            onChange={(event) =>
              void verifyEvidence(event.target.files?.[0] ?? null, wallet || undefined)
            }
          />
        </label>

        <div className="verify-result large">
          <CheckCircle2 size={14} aria-hidden="true" />
          <p>{verifyResult || 'No verification run yet.'}</p>
        </div>

        <dl className="data-list">
          <div>
            <dt>Received Hash</dt>
            <dd>{shortHash(verifyHash)}</dd>
          </div>
          <div>
            <dt>Chain Status</dt>
            <dd>{chainProof ? 'Confirmed' : 'Not loaded'}</dd>
          </div>
        </dl>
      </div>

      <aside className="side-rail">
        <div className="rail-block">
          <h3>Chain Registry</h3>
          <ChainProofPanel chainProof={chainProof} />
          {provenanceRecord ? <ProvenanceCard provenance={provenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          <EventList events={events} onRefresh={() => void loadEvents()} />
        </div>
      </aside>
    </section>
  )
}
