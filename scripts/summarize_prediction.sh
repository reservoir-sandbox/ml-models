#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: bash scripts/summarize_prediction.sh <prediction-json> [output-markdown]" >&2
  echo "Example: bash scripts/summarize_prediction.sh output/fake_combo_prediction.json" >&2
  exit 1
fi

INPUT_PATH="$1"
OUTPUT_PATH="${2:-output/$(basename "$INPUT_PATH" .json)_summary.md}"

python3 -m Reservoir.summarizer.summarize_prediction \
  --input "$INPUT_PATH" \
  --output "$OUTPUT_PATH"

echo "Summary written to $OUTPUT_PATH"
