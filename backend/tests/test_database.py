"""
SENTINEL-GRC — Database Connection Leak Tests
Verifies that the get_db_session context manager cleans up connections
properly even when exceptions occur.
"""

import pytest
import time
from sqlalchemy import select
from app.db.database import get_db_session, sync_engine
from app.models.risk import Risk


def get_connection_count():
    """Helper to get the current number of checked-out connections in the pool"""
    return sync_engine.pool.checkedout()


def test_sync_session_cleanup_on_success(mock_db):
    """Verify session is closed on successful execution"""
    initial_conns = get_connection_count()
    
    with get_db_session() as session:
        session.execute(select(Risk))
        active_conns = get_connection_count()
        assert active_conns == initial_conns + 1, "Connection should be checked out"
        
    final_conns = get_connection_count()
    assert final_conns == initial_conns, f"Connection leak: {final_conns - initial_conns} connections not released"


def test_sync_session_cleanup_on_error(mock_db):
    """Verify session is closed even if an exception occurs mid-block"""
    initial_conns = get_connection_count()
    
    try:
        with get_db_session() as session:
            session.execute(select(Risk))
            active_conns = get_connection_count()
            assert active_conns == initial_conns + 1, "Connection should be checked out"
            raise ValueError("Simulated error mid-session")
    except ValueError:
        pass
    
    final_conns = get_connection_count()
    assert final_conns == initial_conns, f"Connection leak: {final_conns - initial_conns} connections not released"
