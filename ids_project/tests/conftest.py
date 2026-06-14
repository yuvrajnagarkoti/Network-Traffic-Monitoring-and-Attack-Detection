"""
Pytest fixtures for the IDS test suite.

Provides reusable test fixtures including:
- Flask application with test configuration
- Database session with automatic rollback
- Test HTTP client
- Sample model factories
"""

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from app import create_app
from app.extensions import db as _db
from app.models.user import User, UserRole


@pytest.fixture(scope="session")
def app():
    """Create Flask application with test configuration.

    Scoped to session — created once for all tests.
    """
    app = create_app("testing")

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope="function")
def db_session(app):
    """Provide a database session that rolls back after each test.

    Ensures test isolation — each test starts with a clean state.
    """
    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()

        session = _db.session
        yield session

        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(app):
    """Provide a Flask test client for HTTP request testing."""
    return app.test_client()


@pytest.fixture(scope="function")
def runner(app):
    """Provide a Flask CLI test runner."""
    return app.test_cli_runner()


@pytest.fixture
def sample_admin_user(db_session):
    """Create a sample admin user for testing."""
    from app.extensions import bcrypt

    user = User(
        id=uuid.uuid4(),
        username="test_admin",
        email="admin@test.com",
        password_hash=bcrypt.generate_password_hash("TestPassword123!").decode("utf-8"),
        role=UserRole.ADMIN,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def sample_analyst_user(db_session):
    """Create a sample analyst user for testing."""
    from app.extensions import bcrypt

    user = User(
        id=uuid.uuid4(),
        username="test_analyst",
        email="analyst@test.com",
        password_hash=bcrypt.generate_password_hash("TestPassword123!").decode("utf-8"),
        role=UserRole.ANALYST,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def sample_viewer_user(db_session):
    """Create a sample viewer user for testing."""
    from app.extensions import bcrypt

    user = User(
        id=uuid.uuid4(),
        username="test_viewer",
        email="viewer@test.com",
        password_hash=bcrypt.generate_password_hash("TestPassword123!").decode("utf-8"),
        role=UserRole.VIEWER,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def sample_attack_event(db_session):
    """Create a sample attack event for testing."""
    from app.models.attack import AttackEvent, AttackType, AttackStatus

    event = AttackEvent(
        id=uuid.uuid4(),
        attack_type=AttackType.PORT_SCAN,
        source_ip="203.0.113.50",
        target_ip="10.0.0.5",
        target_port=None,
        evidence={
            "scanned_ports": [22, 80, 443, 8080],
            "scan_rate": 2.3,
            "technique": "syn",
        },
        confidence_score=0.85,
        packet_count=16,
        duration_seconds=7,
        first_seen=datetime.now(timezone.utc) - timedelta(minutes=5),
        last_seen=datetime.now(timezone.utc),
        status=AttackStatus.ACTIVE,
    )
    db_session.add(event)
    db_session.flush()
    return event


@pytest.fixture
def sample_packet_log(db_session):
    """Create a sample packet log entry for testing."""
    from app.models.packet import PacketLog

    packet = PacketLog(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=1460,
        flags="SYN",
        payload_hash="a" * 64,
        captured_at=datetime.now(timezone.utc),
    )
    db_session.add(packet)
    db_session.flush()
    return packet
