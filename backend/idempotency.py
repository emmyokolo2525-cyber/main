from __future__ import annotations

import json
import hashlib
import datetime
from typing import Any, Tuple, Optional

from db import get_connection, Jsonb

# Table: idempotency_records
# Columns:
#   id SERIAL PRIMARY KEY
#   request_digest TEXT NOT NULL
#   request_type TEXT NOT NULL
#   created_at TIMESTAMPTZ NOT NULL DEFAULT now()
#   expires_at TIMESTAMPTZ NOT NULL
#   status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED'))
#   response_payload JSONB NULL
#   error_payload JSONB NULL
#   UNIQUE (request_digest, request_type)

def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def _default_expiry(window_seconds: int = 86400) -> datetime.datetime:
    return _now() + datetime.timedelta(seconds=window_seconds)

def create_idempotency_record(request_digest: str, request_type: str, expires_at: Optional[datetime.datetime] = None) -> Tuple[int, str]:
    """Insert a new idempotency record with status PENDING.
    Returns (record_id, status). If a record already exists, returns its id and current status.
    """
    if expires_at is None:
        expires_at = _default_expiry()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO idempotency_records (request_digest, request_type, expires_at, status)
                VALUES (%s, %s, %s, 'PENDING')
                ON CONFLICT (request_digest, request_type) DO UPDATE SET status = idempotency_records.status
                RETURNING id, status;
                """,
                (request_digest, request_type, expires_at),
            )
            row = cur.fetchone()
            conn.commit()
            return int(row['id']), row['status']

def get_idempotency_record(request_digest: str, request_type: str) -> Optional[dict]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM idempotency_records WHERE request_digest = %s AND request_type = %s",
                (request_digest, request_type),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
            return None

def store_response(record_id: int, payload: Any) -> None:
    """Store a successful response payload and mark record as COMPLETED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'COMPLETED', response_payload = %s, error_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(payload), record_id),
            )
            conn.commit()

def store_error(record_id: int, error: dict) -> None:
    """Store an error payload and mark record as FAILED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'FAILED', error_payload = %s, response_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(error), record_id),
            )
            conn.commit()
import functools
from flask import request, jsonify, Response


def _canonical_digest() -> str:
    """Create a SHA-256 digest of the request method, path, query string, and raw body.
    This ensures that identical requests produce the same digest regardless of content type.
    """
    method = request.method.encode()
    path = request.path.encode()
    query = request.query_string  # already bytes
    body = request.get_data() or b""
    data = b"|".join([method, path, query, body])
    return hashlib.sha256(data).hexdigest()


def idempotent(request_type: str):
    """Flask view decorator to enforce idempotent request handling.

    It checks for an existing idempotency record based on a canonical request digest.
    If a completed record exists, it returns the stored response payload.
    If a pending record exists, it returns a 409 conflict indicating duplicate in‑flight request.
    Otherwise, it creates a PENDING record, executes the view, stores the successful
    response (or error) and returns the original view result.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            digest = _canonical_digest()
            record = get_idempotency_record(digest, request_type)
            if record:
                status = record.get("status")
                if status == "COMPLETED":
                    payload = record.get("response_payload")
                    # Assume payload is JSON‑serialisable
                    return jsonify(payload), 200
                if status == "FAILED":
                    error = record.get("error_payload") or {"error": "previous request failed"}
                    return jsonify(error), 500
                # PENDING – another request is currently processing
                return jsonify({"error": "duplicate request in progress"}), 409
            # No record – create a pending entry
            record_id, _ = create_idempotency_record(digest, request_type)
            try:
                result = func(*args, **kwargs)
                # Extract payload for storage – handle common Flask return patterns
                if isinstance(result, tuple):
                    data = result[0]
                else:
                    data = result
                store_response(record_id, data)
                return result
            except Exception as exc:
                err = {"error": str(exc)}
                store_error(record_id, err)
                raise
        return wrapper
    return decorator
