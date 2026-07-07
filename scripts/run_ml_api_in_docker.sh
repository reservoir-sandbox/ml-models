#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="$(mktemp -d /private/tmp/reservoir_ml_api.XXXXXX)"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
API_PORT="${API_PORT:-8000}"

cleanup() {
  if [[ "${KEEP_DOCKER_STAGE:-0}" != "1" ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "Keeping Docker staging directory: $STAGE_DIR"
  fi
}
trap cleanup EXIT

echo "Staging ML API at $STAGE_DIR"
cp "$ROOT_DIR/requirements.txt" "$STAGE_DIR/requirements.txt"
cp -R "$ROOT_DIR/Reservoir" "$STAGE_DIR/Reservoir"
cp -R "$ROOT_DIR/models" "$STAGE_DIR/models"

docker run --rm --platform "$DOCKER_PLATFORM" \
  -p "$API_PORT":8000 \
  -v "$STAGE_DIR":/work \
  -w /work \
  python:3.10-slim \
  bash -lc 'python -m pip install --no-cache-dir -r requirements.txt && RESERVOIR_API_HOST=0.0.0.0 RESERVOIR_API_PORT=8000 gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 2 --timeout 120 Reservoir.api.app:app'
