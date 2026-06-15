#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="$(mktemp -d /private/tmp/reservoir_model_test.XXXXXX)"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

cleanup() {
  if [[ "${KEEP_DOCKER_STAGE:-0}" != "1" ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "Keeping Docker staging directory: $STAGE_DIR"
  fi
}
trap cleanup EXIT

echo "Staging model test at $STAGE_DIR"
cp "$ROOT_DIR/requirements.txt" "$STAGE_DIR/requirements.txt"
cp -R "$ROOT_DIR/Reservoir" "$STAGE_DIR/Reservoir"
cp -R "$ROOT_DIR/samples" "$STAGE_DIR/samples"
cp -R "$ROOT_DIR/models" "$STAGE_DIR/models"
mkdir -p "$STAGE_DIR/output"

docker run --rm --platform "$DOCKER_PLATFORM" \
  -v "$STAGE_DIR":/work \
  -w /work \
  python:3.10-slim \
  bash -lc 'python -m pip install --no-cache-dir -r requirements.txt >/tmp/reservoir-pip.log && python -m Reservoir.file_analysis.evaluate_model'

mkdir -p "$ROOT_DIR/output"
cp -R "$STAGE_DIR/output/." "$ROOT_DIR/output/"

echo
echo "Copied test outputs back to:"
echo "  $ROOT_DIR/output/model_test_predictions.csv"
echo "  $ROOT_DIR/output/model_test_summary.json"
