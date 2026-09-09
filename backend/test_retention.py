import os
import pytest
import time
from datetime import datetime, timedelta, timezone
from db import init_db, insert_proof_event, set_legal_hold, purge_expired_events, get_connection
from config import load_config
from retention import init_retention_worker, stop_retention_worker, _worker

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    db_url = os.environ.get("TEST_DATABASE_URL") or "postgresql://postgres:password@localhost:5432/postgres"
    monkeypatch.setenv("DATABASE_URL", db_url)
    try:
        init_db()
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("truncate table proof_events cascade;")
                cursor.execute("truncate table deletion_receipts cascade;")
            conn.commit()
    except Exception as e:
        pytest.skip(f"Database connection failed: {e}")
    
    yield
    
    stop_retention_worker()

@pytest.mark.integration
def test_purge_expired_events():
    # Insert an event that is expired
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    ev1 = insert_proof_event(event_type="test", video_hash="1"*64, proof_id="a"*64, expires_at=expired_time)
    
    # Insert an event that is not expired
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    ev2 = insert_proof_event(event_type="test", video_hash="2"*64, proof_id="b"*64, expires_at=future_time)
    
    # Insert an event that is expired but on legal hold
    ev3 = insert_proof_event(event_type="test", video_hash="3"*64, proof_id="c"*64, expires_at=expired_time)
    set_legal_hold("c"*64, True)
    
    # Insert an event with no expiration
    ev4 = insert_proof_event(event_type="test", video_hash="4"*64, proof_id="d"*64)
    
    receipts = purge_expired_events()
    
    assert len(receipts) == 1
    assert receipts[0]["proof_id"] == "a"*64
    
    # Verify remaining in DB
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from proof_events order by id")
            remaining = [r["proof_id"] for r in cursor.fetchall()]
    assert remaining == ["b"*64, "c"*64, "d"*64]

    # Verify receipt is in table
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from deletion_receipts")
            in_receipts = [r["proof_id"] for r in cursor.fetchall()]
    assert in_receipts == ["a"*64]

@pytest.mark.integration
def test_retention_worker(monkeypatch):
    monkeypatch.setenv("RETENTION_INTERVAL_SECONDS", "1")
    
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    insert_proof_event(event_type="test", video_hash="5"*64, proof_id="e"*64, expires_at=expired_time)
    
    init_retention_worker()
    time.sleep(2)  # Wait for worker to run at least once
    
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select count(*) as c from deletion_receipts")
            count = cursor.fetchone()["c"]
    assert count == 1
