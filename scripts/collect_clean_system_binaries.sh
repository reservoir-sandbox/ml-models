#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-samples/clean}"
MAX_FILES="${MAX_FILES:-25}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script should be run on Linux or inside Docker." >&2
  exit 1
fi

if ! command -v file >/dev/null 2>&1; then
  echo "file command is required." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

count=0
for candidate in /bin/* /usr/bin/*; do
  [[ -f "$candidate" ]] || continue
  [[ -x "$candidate" ]] || continue
  if file "$candidate" | grep -q "ELF"; then
    name="$(basename "$candidate")"
    cp "$candidate" "$OUT_DIR/system_$name"
    count=$((count + 1))
    if [[ "$count" -ge "$MAX_FILES" ]]; then
      break
    fi
  fi
done

echo "Copied $count trusted system ELF binaries to $OUT_DIR"
file "$OUT_DIR"/* || true
