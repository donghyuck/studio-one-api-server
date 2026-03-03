$ErrorActionPreference = "Stop"

# Stops/removes the container but keeps the volume (data).

docker compose -f docker/compose.yml down
