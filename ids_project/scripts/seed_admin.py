"""
Seed script to create an initial admin user.

Usage:
    python scripts/seed_admin.py

Creates admin/admin@ids.local with password 'Admin@1234' (role: admin).
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db, bcrypt
from app.models.user import User, UserRole


def seed_admin():
    app = create_app("development")

    with app.app_context():
        # Check if admin already exists
        existing = User.query.filter_by(username="admin").first()
        if existing:
            print(f"[INFO] Admin user already exists: {existing.username} ({existing.email})")
            print(f"       Role: {existing.role}")
            print(f"       Active: {existing.is_active}")
            return

        # Create admin user
        pw_hash = bcrypt.generate_password_hash("Admin@1234").decode("utf-8")
        admin = User(
            username="admin",
            email="admin@ids.local",
            password_hash=pw_hash,
            role=UserRole.ADMIN,
            is_active=True,
            is_2fa_enabled=False,
        )
        db.session.add(admin)
        db.session.commit()
        print("[SUCCESS] Admin user created!")
        print("  Username : admin")
        print("  Password : Admin@1234")
        print("  Email    : admin@ids.local")
        print("  Role     : admin")
        print()
        print("  Login at : http://127.0.0.1:5000/auth/login")


if __name__ == "__main__":
    seed_admin()
