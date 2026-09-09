from __future__ import annotations

import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def clear_database_url():
    """Ensure DATABASE_URL is unset or set to a test value."""
    original = os.environ.get("DATABASE_URL")
    # Set a dummy URL for tests that need DB access.
    # Tests that don't need a DB will override this per test.
    os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
    yield
    if original is not None:
        os.environ["DATABASE_URL"] = original
    else:
        os.environ.pop("DATABASE_URL", None)


# ---------------------------------------------------------------------------
# Tests for the migration runner (without a real database)
# ---------------------------------------------------------------------------


@patch("migration._database_url", return_value=None)
def test_run_migrations_no_db(mock_url):
    """When DATABASE_URL is not configured, run_migrations returns []."""
    from migration import run_migrations
    assert run_migrations() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_applies_all(mock_conn, mock_url):
    """All migrations are applied when the ledger is empty."""
    from migration import run_migrations

    # Simulate an empty migrations table (no applied migrations)
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []  # _applied_migrations returns empty
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    result = run_migrations()

    assert len(result) > 0
    for entry in result:
        assert entry["action"] in ("applied",)
    # Verify migration SQL was executed
    assert mock_cursor.execute.call_count > 1  # ledger table + migrations


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_run_migrations_skips_applied(mock_conn, mock_url):
    """Migrations that are already in the ledger are skipped."""
    from migration import MIGRATIONS, run_migrations

    # Simulate that migration 1 is already applied
    applied_migration_ids = {1}

    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        {"migration_id": mid} for mid in applied_migration_ids
    ]
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    result = run_migrations()

    mid_1_entry = [e for e in result if e["migration_id"] == 1]
    assert len(mid_1_entry) == 1
    assert mid_1_entry[0]["action"] == "skipped"


# ---------------------------------------------------------------------------
# Tests for drift detection (without a real database)
# ---------------------------------------------------------------------------


def test_detect_drift_no_db():
    """When no DATABASE_URL is set, detect_drift returns []."""
    from migration import detect_drift

    with patch("migration._database_url", return_value=None):
        assert detect_drift() == []


@patch("migration._database_url", return_value="postgresql://localhost/test")
@patch("migration._get_connection")
def test_detect_drift_missing_table(mock_conn, mock_url):
    """A table missing from the database is reported as a drift."""
    from migration import detect_drift, EXPECTED_TABLES

    # First query returns only tables that are NOT in EXPECTED_TABLES
    mock_cursor = MagicMock()
    # information_schema.tables returns no expected tables
    mock_cursor.fetchall.side_effect = [
        [{"table_name": "some_other_table"}],  # first fetch: no expected tables found
        [],  # columns query for each expected table won't be reached
    ]
    mock_connection = MagicMock()
    mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.return_value.__enter__.return_value = mock_connection

    drifts = detect_drift()

    assert len(drifts) == len(EXPECTED_TABLES)
    for d in drifts:
        assert d.issue == "missing_table"


# ---------------------------------------------------------------------------
# Tests for migration checksum stability
# ---------------------------------------------------------------------------


def test_migration_checksum_stability():
    """Migration SQL checksums are deterministic (same input = same hash)."""
    from migration import MIGRATIONS, _compute_checksum

    for m in MIGRATIONS:
        c1 = _compute_checksum(m.sql)
        c2 = _compute_checksum(m.sql)
        assert c1 == c2, f"Migration {m.id} ({m.name}) checksum is not stable"
        assert len(c1) == 64, f"Checksum should be 64 hex chars, got {len(c1)}"


# ---------------------------------------------------------------------------
# Tests for the migrations table query
# ---------------------------------------------------------------------------


def test_applied_migrations_empty():
    """When no migrations are applied, the set is empty."""
    from migration import _applied_migrations

    with patch("migration._get_connection") as mock_conn:
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_connection = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_conn.return_value.__enter__.return_value = mock_connection

        result = _applied_migrations()
        assert result == set()


# ---------------------------------------------------------------------------
# Tests for expected table definitions consistency
# ---------------------------------------------------------------------------


def test_expected_tables_cover_all_migration_tables():
    """Every table that a migration creates has a corresponding drift-check entry."""
    from migration import MIGRATIONS, EXPECTED_TABLES
    import re

    created_tables = set()
    for m in MIGRATIONS:
        for match in re.finditer(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", m.sql, re.IGNORECASE
        ):
            created_tables.add(match.group(1).lower())

    missing = created_tables - set(k.lower() for k in EXPECTED_TABLES)
    assert not missing, (
        f"Tables created by migrations but missing from EXPECTED_TABLES: {missing}"
    )
