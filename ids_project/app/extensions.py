"""
Flask extension instances.

All extensions are instantiated here without binding to a specific app.
They are initialized with the app inside the application factory (create_app).
This pattern prevents circular imports.
"""

from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()
login_manager = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()

login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


# ============================================
# Database Compatibility Types (Postgres/SQLite)
# ============================================
import json
from sqlalchemy.types import TypeDecorator, String, JSON, Text

class INET(TypeDecorator):
    """Platform-independent INET type.
    Uses PostgreSQL's INET type on PostgreSQL, and String(45) on other databases.
    """
    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            from sqlalchemy.dialects.postgresql import INET as PG_INET
            return dialect.type_descriptor(PG_INET())
        else:
            return dialect.type_descriptor(String(45))

class JSONB(TypeDecorator):
    """Platform-independent JSONB type.
    Uses PostgreSQL's JSONB type on PostgreSQL, and JSON on other databases.
    """
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
            return dialect.type_descriptor(PG_JSONB())
        else:
            return dialect.type_descriptor(JSON())

class ARRAY(TypeDecorator):
    """Platform-independent ARRAY type.
    Uses PostgreSQL's ARRAY type on PostgreSQL, and Text (storing JSON-serialized list) on other databases.
    """
    impl = Text
    cache_ok = True

    def __init__(self, item_type=None, *args, **kwargs):
        self.item_type = item_type
        super().__init__(*args, **kwargs)

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
            from sqlalchemy.dialects.postgresql import INET as PG_INET
            
            # Resolve custom INET to native PG_INET
            underlying = self.item_type
            if underlying == INET or isinstance(underlying, INET):
                underlying = PG_INET()
            elif isinstance(underlying, type) and issubclass(underlying, TypeDecorator):
                underlying = underlying()
            
            return dialect.type_descriptor(PG_ARRAY(underlying))
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if dialect.name == 'postgresql':
            return value
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if dialect.name == 'postgresql':
            return value
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return []

