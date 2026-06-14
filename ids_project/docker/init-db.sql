-- ============================================
-- PostgreSQL Initialization Script
-- Creates test database and enables extensions
-- ============================================

-- Create test database for pytest
CREATE DATABASE ids_test_db OWNER ids_user;

-- Enable useful extensions on main database
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Enable extensions on test database
\c ids_test_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
