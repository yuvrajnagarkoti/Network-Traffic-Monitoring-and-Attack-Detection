"""
Database helper utilities.

Provides health check, connection verification, and retry logic
for database operations.
"""

import logging
import time
from typing import Optional

from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.extensions import db

logger = logging.getLogger(__name__)


def check_database_health() -> dict:
    """Verify database connectivity and return status.

    Returns:
        Dictionary with connection status, latency, and version info.
    """
    try:
        start_time = time.monotonic()
        result = db.session.execute(text("SELECT version()"))
        version = result.scalar()
        latency_ms = (time.monotonic() - start_time) * 1000

        db.session.execute(text("SELECT 1"))
        db.session.commit()

        return {
            "status": "connected",
            "latency_ms": round(latency_ms, 2),
            "version": version,
        }
    except OperationalError as exc:
        logger.error("Database health check failed: %s", exc)
        return {
            "status": "disconnected",
            "error": str(exc.orig) if exc.orig else str(exc),
        }
    except SQLAlchemyError as exc:
        logger.error("Database health check error: %s", exc)
        return {
            "status": "error",
            "error": str(exc),
        }
    finally:
        db.session.rollback()


def execute_with_retry(
    func,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    backoff_factor: float = 2.0,
) -> Optional[any]:
    """Execute a database operation with retry logic.

    Uses exponential backoff for transient failures like
    connection drops or pool exhaustion.

    Args:
        func: Callable that performs the database operation.
        max_retries: Maximum number of retry attempts.
        retry_delay: Initial delay between retries in seconds.
        backoff_factor: Multiplier for delay on each retry.

    Returns:
        Result of the function call, or None if all retries fail.

    Raises:
        SQLAlchemyError: If the error is not retryable.
    """
    last_exception = None

    for attempt in range(1, max_retries + 1):
        try:
            result = func()
            return result
        except OperationalError as exc:
            last_exception = exc
            logger.warning(
                "Database operation failed (attempt %d/%d): %s",
                attempt,
                max_retries,
                exc,
            )
            if attempt < max_retries:
                sleep_time = retry_delay * (backoff_factor ** (attempt - 1))
                logger.info("Retrying in %.1f seconds...", sleep_time)
                time.sleep(sleep_time)
                db.session.rollback()
            else:
                db.session.rollback()
                raise
        except SQLAlchemyError:
            db.session.rollback()
            raise

    raise last_exception


def get_table_sizes() -> dict:
    """Get sizes of all application tables for monitoring.

    Returns:
        Dictionary mapping table names to their sizes in bytes.
    """
    try:
        query = text("""
            SELECT
                relname AS table_name,
                pg_total_relation_size(relid) AS total_bytes,
                pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
                n_live_tup AS row_count
            FROM pg_stat_user_tables
            ORDER BY pg_total_relation_size(relid) DESC
        """)
        result = db.session.execute(query)
        tables = {}
        for row in result:
            tables[row.table_name] = {
                "total_bytes": row.total_bytes,
                "total_size": row.total_size,
                "row_count": row.row_count,
            }
        return tables
    except SQLAlchemyError as exc:
        logger.error("Failed to get table sizes: %s", exc)
        return {}
    finally:
        db.session.rollback()
