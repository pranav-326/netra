-- ==============================================================================
-- Netra Database Initialization Script (Layer 8: PostgreSQL)
-- ==============================================================================

-- Enable UUID generation extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable cryptographic hashing functions (for attachment & IOC hashing)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create dedicated schemas for modular separation
CREATE SCHEMA IF NOT EXISTS ingestion;
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS audit_logs;

-- Set timezone to UTC
SET timezone = 'UTC';

-- Informational message
DO $$
BEGIN
    RAISE NOTICE 'Netra PostgreSQL database and extensions successfully initialized.';
END $$;
