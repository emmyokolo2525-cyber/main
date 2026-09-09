from __future__ import annotations

import base64
import binascii
import hashlib
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

# Max page size for GET /api/proofs cursor pagination.
PROOF_EVENTS_MAX_LIMIT = 100
PROOF_EVENTS_DEFAULT_LIMIT = 25


def encode_proof_events_cursor(event_id: int) -> str:
    """Return a stable opaque cursor for the given proof_events.id."""
    return base64.urlsafe_b64encode(str(event_id).encode("ascii")).decode("ascii")


def decode_proof_events_cursor(cursor: str) -> int:
    """Decode an opaque proof-events cursor.

    Raises ValueError when the cursor is malformed.
    """
    if not isinstance(cursor, str) or not cursor.strip():
        raise ValueError("invalid cursor")

    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        text = raw.decode("ascii")
        event_id = int(text)
    except (ValueError, UnicodeDecodeError, binascii.Error, TypeError) as exc:
        raise ValueError("invalid cursor") from exc

    if event_id < 1:
        raise ValueError("invalid cursor")
    return event_id


def clamp_proof_events_limit(limit: int) -> int:
    return max(1, min(limit, PROOF_EVENTS_MAX_LIMIT))


def database_url() -> str | None:
    return os.getenv("DATABASE_URL")


@contextmanager
def get_connection() -> Iterator[psycopg.Connection]:
    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")

    with psycopg.connect(url, row_factory=dict_row) as connection:
        yield connection


def init_db() -> None:
    """Initialise the database schema via the versioned migration system.

    This replaces the earlier inline ``CREATE TABLE IF NOT EXISTS`` approach
    with an ordered, auditable migration ledger.  Safe to call repeatedly.
    """
    from migration import run_migrations  # late import to avoid cycles

    run_migrations()


def detect_drift() -> list[dict[str, str]]:
    """Check for schema drift and return a list of issues.

    Each dict has keys ``table_name``, ``issue``, ``detail``."""
    from migration import detect_drift as _detect_drift

    return [
        {"table_name": d.table_name, "issue": d.issue, "detail": d.detail}
        for d in _detect_drift()
    ]


def get_migration_report() -> list[dict[str, object]]:
    """Return the list of migrations and their current status.

    Useful for health-check endpoints and operational observability."""
    from migration import run_migrations

    return run_migrations()


def check_db() -> bool:
    if not database_url():
        return False

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("select 1 as ok")
            row = cursor.fetchone()
            return bool(row and row["ok"] == 1)


def insert_lineage_event(
    *,
    manifest_digest: str,
    manifest: dict[str, Any],
    actor_address: str,
    parent_proof_ids: list[str],
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into lineage_events (manifest_digest, manifest, actor_address, parent_proof_ids)
                values (%s, %s, %s, %s)
                on conflict (manifest_digest) do nothing
                returning id, manifest_digest, created_at;
                """,
                (manifest_digest, Jsonb(manifest), actor_address, parent_proof_ids),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_lineage_events(limit: int = 25) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                order by id desc
                limit %s;
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]


def find_lineage_by_output_digest(output_digest: str) -> dict[str, Any] | None:
    """Find lineage record by the output digest of the derivative.
    
    Args:
        output_digest: The output digest (32-byte hex string)
    
    Returns:
        Lineage record or None if not found
    """
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                where (manifest ->> 'outputDigest') = %s
                limit 1;
                """,
                (output_digest,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def find_lineage_by_actor(actor_address: str, limit: int = 25) -> list[dict[str, Any]]:
    """Find lineage records by actor address with pagination.
    
    Args:
        actor_address: The actor's address
        limit: Maximum number of records to return (bounded to 100)
    
    Returns:
        List of lineage records
    """
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                where actor_address = %s
                order by id desc
                limit %s;
                """,
                (actor_address, limit),
            )
            return [dict(row) for row in cursor.fetchall()]


def insert_proof_event(
    *,
    event_type: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    embedded_hash: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    retention_class: str | None = None,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    time_attestation: dict[str, Any] | None = None,
    claimed_capture_time: str | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    Jsonb(metadata) if metadata is not None else None,
                    Jsonb(time_attestation) if time_attestation is not None else None,
                    claimed_capture_time,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_events(
    limit: int = PROOF_EVENTS_DEFAULT_LIMIT,
    *,
    cursor_id: int | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """List proof events with stable keyset (cursor) pagination.

    Ordering is deterministic: ``id DESC`` (primary key is the unique tie-breaker).
    Returns ``(events, next_cursor)`` where ``next_cursor`` is an opaque token for
    the next page, or ``None`` when there are no further rows.
    """
    if not database_url():
        return [], None

    page_size = clamp_proof_events_limit(limit)
    fetch_size = page_size + 1

    with get_connection() as connection:
        with connection.cursor() as cursor:
            if cursor_id is None:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    order by id desc
                    limit %s;
                    """,
                    (fetch_size,),
                )
            else:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    where id < %s
                    order by id desc
                    limit %s;
                    """,
                    (cursor_id, fetch_size),
                )
            rows = [dict(row) for row in cursor.fetchall()]

    next_cursor: str | None = None
    if len(rows) > page_size:
        rows = rows[:page_size]
        next_cursor = encode_proof_events_cursor(int(rows[-1]["id"]))
    return rows, next_cursor


def find_proof_events_by_video(video_hash: str) -> list[dict[str, Any]]:
    if not database_url():
        return []

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    legal_hold,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    created_at
                from proof_events
                where video_hash = %s
                order by id desc;
                """,
                (video_hash,),
            )
            return [dict(row) for row in cursor.fetchall()]


def make_idempotency_key(video_hash: str, proof_id: str, tx_hash: str | None) -> str:
    """Derive the idempotency key for a register event.

    Key material: ``video_hash:proof_id:tx_hash`` where ``tx_hash`` defaults
    to the empty string when absent.  Using SHA-256 keeps the stored value a
    fixed-length hex string and avoids any length-extension ambiguity.
    """
    raw = f"{video_hash}:{proof_id}:{tx_hash or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


# Fields compared when deciding whether a retry carries a conflicting payload.
_CONFLICT_FIELDS = ("video_hash", "metadata_hash", "proof_id", "tier", "source_address", "contract_id")


def upsert_register_event(
    *,
    idempotency_key: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    retention_class: str | None = None,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    time_attestation: dict[str, Any] | None = None,
    claimed_capture_time: str | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert a register event idempotently.

    Returns ``(row, created)`` where *created* is ``True`` when a new row was
    written and ``False`` when an existing row was found via the idempotency
    key.

    Raises ``ConflictError`` when the same idempotency key is reused with a
    payload that differs in one of the canonical proof-identity fields.

    The insert is done with ``ON CONFLICT DO NOTHING`` so that concurrent
    requests with the same key race safely: only one writer wins and the
    other falls back to the ``SELECT`` path.
    """
    if not database_url():
        # When no database is configured return a stub so the rest of the app
        # remains functional in minimal dev environments.
        stub: dict[str, Any] = {
            "id": None,
            "created_at": None,
            "video_hash": video_hash,
            "metadata_hash": metadata_hash,
            "proof_id": proof_id,
            "tier": tier,
            "source_address": source_address,
            "contract_id": contract_id,
            "retention_class": retention_class,
            "expires_at": expires_at,
            "legal_hold": False,
        }
        return stub, True

    with get_connection() as connection:
        with connection.cursor() as cursor:
            # Attempt the insert; if the unique key already exists the row is
            # silently skipped and nothing is returned.
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    idempotency_key
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (idempotency_key)
                where idempotency_key is not null
                do nothing
                returning
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    legal_hold,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    created_at;
                """,
                (
                    "register",
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    Jsonb(metadata) if metadata is not None else None,
                    Jsonb(time_attestation) if time_attestation is not None else None,
                    claimed_capture_time,
                    idempotency_key,
                ),
            )
            row = cursor.fetchone()

            if row is not None:
                # Fresh insert – committed below.
                connection.commit()
                return dict(row), True

            # Key already existed (concurrent insert or retry): fetch the
            # previously stored row.
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    legal_hold,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    created_at
                from proof_events
                where idempotency_key = %s;
                """,
                (idempotency_key,),
            )
            existing = cursor.fetchone()

        # No commit needed for the read-only fallback path; any uncommitted
        # state is just the no-op insert.
        connection.rollback()

    if existing is None:
        # Should not happen – the constraint guarantees the row is visible.
        raise RuntimeError("idempotency key collision but row not found; please retry")

    existing_row = dict(existing)

    # Check whether the caller is re-submitting with a conflicting payload.
    incoming = {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "proof_id": proof_id,
        "tier": tier,
        "source_address": source_address,
        "contract_id": contract_id,
    }
    for field in _CONFLICT_FIELDS:
        if existing_row.get(field) != incoming.get(field):
            raise ConflictError(
                idempotency_key=idempotency_key,
                field=field,
                existing_value=existing_row.get(field),
                incoming_value=incoming.get(field),
            )

    return existing_row, False


class ConflictError(Exception):
    """Raised when the same idempotency key is reused with a conflicting payload."""

    def __init__(
        self,
        *,
        idempotency_key: str,
        field: str,
        existing_value: object,
        incoming_value: object,
    ) -> None:
        super().__init__(
            f"idempotency key reused with conflicting value for '{field}'"
        )
        self.idempotency_key = idempotency_key
        self.field = field
        self.existing_value = existing_value
        self.incoming_value = incoming_value


def insert_proof_history_event(
    *,
    proof_id: str,
    action: str,
    actor: str | None = None,
    reason_code: int,
    contract_id: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_history_events (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status
                )
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_history_events(
    proof_id: str, limit: int = 50, offset: int = 0
) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                    created_at
                from proof_history_events
                where proof_id = %s
                order by id asc
                limit %s offset %s;
                """,
                (proof_id, limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]

def update_tx_status(tx_hash: str, status: str) -> None:
    if not database_url():
        return
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update proof_events
                set tx_status = %s
                where tx_hash = %s;
                """,
                (status, tx_hash)
            )
        connection.commit()


def set_legal_hold(proof_id: str, hold: bool) -> None:
    """Set or clear the legal-hold flag on a proof event."""
    if not database_url():
        return
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update proof_events
                set legal_hold = %s
                where proof_id = %s;
                """,
                (hold, proof_id),
            )
        connection.commit()


def purge_expired_events() -> list[dict[str, Any]]:
    """Delete proof events past their expiration that are not on legal hold.

    Returns a list of deletion receipts (proof_id, deleted_at, etc.) for
    each purged event.
    """
    if not database_url():
        return []
    now = datetime.now(timezone.utc)
    receipts: list[dict[str, Any]] = []
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, proof_id, video_hash, metadata_hash,
                       retention_class, tier
                from proof_events
                where expires_at is not null
                  and expires_at <= %s
                  and legal_hold = false;
                """,
                (now,),
            )
            expired = [dict(row) for row in cursor.fetchall()]
            for event in expired:
                cursor.execute(
                    """
                    insert into deletion_receipts (proof_id, video_hash, metadata_hash)
                    values (%s, %s, %s)
                    returning id, created_at;
                    """,
                    (event["proof_id"], event.get("video_hash"), event.get("metadata_hash")),
                )
                receipt = cursor.fetchone()
                if receipt:
                    receipts.append(dict(receipt))
                cursor.execute(
                    "delete from proof_events where id = %s;",
                    (event["id"],),
                )
        connection.commit()
    return receipts


_JOBS: dict[int, dict[str, Any]] = {}
_next_job_id = 1


def enqueue_job(job_type: str, payload: dict[str, Any]) -> int:
    """Enqueue a background job and return its job id."""
    global _next_job_id
    job_id = _next_job_id
    _next_job_id += 1
    _JOBS[job_id] = {
        "id": job_id,
        "type": job_type,
        "payload": payload,
        "status": "pending",
        "result": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return job_id


def get_job(job_id: int) -> dict[str, Any] | None:
    """Return a job by id, or None."""
    return _JOBS.get(job_id)


def cancel_job(job_id: int) -> bool:
    """Cancel a pending job. Returns True on success."""
    job = _JOBS.get(job_id)
    if job and job["status"] == "pending":
        job["status"] = "cancelled"
        return True
    return False
