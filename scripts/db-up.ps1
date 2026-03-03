$ErrorActionPreference = "Stop"

# Run from repo root in PowerShell.

docker compose -f docker/compose.yml up -d --build

Write-Host "OK: Postgres is starting on localhost:5432 (container: studio-one-postgres)"
Write-Host "OK: jdbc:log4jdbc:postgresql://localhost:5432/studio_db"
Write-Host "OK: username=studioapi password=studioapi"
