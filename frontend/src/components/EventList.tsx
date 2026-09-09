import type { ProofEvent } from '../types'
import { shortHash } from '../utils'

type Props = {
  events: ProofEvent[]
  onRefresh: () => void
}

export function EventList({ events, onRefresh }: Props) {
  return (
    <>
      <button className="verify-input" type="button" onClick={onRefresh}>
        Refresh NeonDB feed
      </button>
      <div className="event-list">
        {events.length === 0 ? (
          <p>No events loaded.</p>
        ) : (
          events.map((event) => (
            <div className="event-row" key={event.id}>
              <strong>{event.event_type}</strong>
              <span>{event.tx_status ?? event.tier ?? 'untiered'}</span>
              <code>{shortHash(event.video_hash ?? event.proof_id ?? '')}</code>
              {event.tx_hash ? <code>{shortHash(event.tx_hash)}</code> : null}
            </div>
          ))
        )}
      </div>
    </>
  )
}
