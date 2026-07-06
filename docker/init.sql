-- SENTINEL-GRC Database Initialisation
-- Run automatically on first PostgreSQL startup

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Enable UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for full-text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Log that init ran
DO $$
BEGIN
  RAISE NOTICE 'SENTINEL-GRC database extensions initialised successfully';
END
$$;
