#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="$(mktemp -d /private/tmp/reservoir_mvp.XXXXXX)"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

cleanup() {
  if [[ "${KEEP_DOCKER_STAGE:-0}" != "1" ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "Keeping Docker staging directory: $STAGE_DIR"
  fi
}
trap cleanup EXIT

echo "Staging project for Docker at $STAGE_DIR"
cp "$ROOT_DIR/README.md" "$STAGE_DIR/README.md"
cp "$ROOT_DIR/requirements.txt" "$STAGE_DIR/requirements.txt"
cp "$ROOT_DIR/build_suspicious_samples.sh" "$STAGE_DIR/build_suspicious_samples.sh"
cp -R "$ROOT_DIR/Reservoir" "$STAGE_DIR/Reservoir"
cp -R "$ROOT_DIR/scripts" "$STAGE_DIR/scripts"
cp -R "$ROOT_DIR/samples" "$STAGE_DIR/samples"

docker run --rm --platform "$DOCKER_PLATFORM" \
  -v "$STAGE_DIR":/work \
  -w /work \
  ubuntu:22.04 \
  bash scripts/run_ml_mvp_inside_container.sh

mkdir -p "$ROOT_DIR/samples/clean" \
         "$ROOT_DIR/samples/suspicious" \
         "$ROOT_DIR/data" \
         "$ROOT_DIR/models" \
         "$ROOT_DIR/output"

cp -R "$STAGE_DIR/samples/clean/." "$ROOT_DIR/samples/clean/"
cp -R "$STAGE_DIR/samples/suspicious/." "$ROOT_DIR/samples/suspicious/"
cp -R "$STAGE_DIR/data/." "$ROOT_DIR/data/"
cp -R "$STAGE_DIR/models/." "$ROOT_DIR/models/"
cp -R "$STAGE_DIR/output/." "$ROOT_DIR/output/"

echo "Copied MVP artifacts back to $ROOT_DIR"
