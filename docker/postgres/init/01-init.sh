#!/usr/bin/env bash
set -euo pipefail

# Runs only on first init (empty volume). Safe to rerun manually.

psql -v ON_ERROR_STOP=1 --username "postgres" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'studioapi') THEN
    CREATE ROLE studioapi LOGIN PASSWORD 'studioapi';
  END IF;
END
$$;
SQL

if ! psql -v ON_ERROR_STOP=1 --username "postgres" --tuples-only --no-align \
  --command "SELECT 1 FROM pg_database WHERE datname = 'studio_db'" | grep -qx 1; then
  createdb --username "postgres" --owner "studioapi" "studio_db"
fi

psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "studio_db" <<'SQL'
CREATE SCHEMA IF NOT EXISTS studioapi AUTHORIZATION studioapi;

-- Ensure app schema is preferred.
ALTER ROLE studioapi IN DATABASE studio_db SET search_path = studioapi, public;

-- pgvector
CREATE EXTENSION IF NOT EXISTS vector;
SQL
