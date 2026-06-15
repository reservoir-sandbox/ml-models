#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: bash scripts/predict_file_in_docker.sh <path-to-elf> [output-json]" >&2
  echo "Example: bash scripts/predict_file_in_docker.sh samples/suspicious/fake_combo" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_PATH="$1"
OUTPUT_PATH="${2:-output/$(basename "$INPUT_PATH")_prediction.json}"
STAGE_DIR="$(mktemp -d /private/tmp/reservoir_predict.XXXXXX)"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

cleanup() {
  if [[ "${KEEP_DOCKER_STAGE:-0}" != "1" ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "Keeping Docker staging directory: $STAGE_DIR"
  fi
}
trap cleanup EXIT

if [[ "$INPUT_PATH" = /* ]]; then
  ABS_INPUT="$INPUT_PATH"
else
  ABS_INPUT="$ROOT_DIR/$INPUT_PATH"
fi

if [[ ! -f "$ABS_INPUT" ]]; then
  echo "Input file not found: $INPUT_PATH" >&2
  exit 1
fi

REL_INPUT="input/$(basename "$ABS_INPUT")"
mkdir -p "$STAGE_DIR/input" "$STAGE_DIR/output"
cp "$ABS_INPUT" "$STAGE_DIR/$REL_INPUT"
cp "$ROOT_DIR/requirements.txt" "$STAGE_DIR/requirements.txt"
cp -R "$ROOT_DIR/Reservoir" "$STAGE_DIR/Reservoir"
cp -R "$ROOT_DIR/models" "$STAGE_DIR/models"

docker run --rm --platform "$DOCKER_PLATFORM" \
  -v "$STAGE_DIR":/work \
  -w /work \
  python:3.10-slim \
  bash -lc "python -m pip install --no-cache-dir -r requirements.txt >/tmp/reservoir-pip.log && python -m Reservoir.file_analysis.predict_file --input '$REL_INPUT' --output 'output/prediction.json'"

mkdir -p "$ROOT_DIR/$(dirname "$OUTPUT_PATH")"
cp "$STAGE_DIR/output/prediction.json" "$ROOT_DIR/$OUTPUT_PATH"

echo "Saved prediction to $OUTPUT_PATH"
