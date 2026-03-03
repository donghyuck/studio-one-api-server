FROM postgres:18.3

# Install pgvector for PostgreSQL 18 (Debian/PGDG).
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends postgresql-18-pgvector; \
  rm -rf /var/lib/apt/lists/*
