#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="$(mktemp -d /private/tmp/reservoir_ml_api_test.XXXXXX)"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

cleanup() {
  if [[ "${KEEP_DOCKER_STAGE:-0}" != "1" ]]; then
    rm -rf "$STAGE_DIR"
  else
    echo "Keeping Docker staging directory: $STAGE_DIR"
  fi
}
trap cleanup EXIT

echo "Staging ML API smoke test at $STAGE_DIR"
cp "$ROOT_DIR/requirements.txt" "$STAGE_DIR/requirements.txt"
cp -R "$ROOT_DIR/Reservoir" "$STAGE_DIR/Reservoir"
cp -R "$ROOT_DIR/models" "$STAGE_DIR/models"
cp -R "$ROOT_DIR/samples" "$STAGE_DIR/samples"
mkdir -p "$STAGE_DIR/output"

docker run --rm --platform "$DOCKER_PLATFORM" \
  -v "$STAGE_DIR":/work \
  -w /work \
  python:3.10-slim \
  bash -lc 'python -m pip install --no-cache-dir -r requirements.txt >/tmp/reservoir-pip.log && python - <<'"'"'PY'"'"'
import base64
import io
import json
from pathlib import Path

from Reservoir.api.app import app

client = app.test_client()

health = client.get("/health")
assert health.status_code == 200, health.get_data(as_text=True)

sample_path = Path("samples/suspicious/fake_combo")
with sample_path.open("rb") as sample:
    upload = client.post(
        "/api/v1/analyze",
        data={
            "include_summary": "1",
            "file": (sample, "fake_combo"),
        },
        content_type="multipart/form-data",
    )
assert upload.status_code == 200, upload.get_data(as_text=True)
upload_json = upload.get_json()
assert upload_json["predicted_class"] == "suspicious", upload_json
assert "summary_markdown" in upload_json, upload_json

encoded = base64.b64encode(sample_path.read_bytes()).decode("ascii")
json_upload = client.post(
    "/api/v1/analyze-json",
    json={
        "filename": "fake_combo",
        "content_base64": encoded,
        "include_summary": True,
    },
)
assert json_upload.status_code == 200, json_upload.get_data(as_text=True)
json_upload_payload = json_upload.get_json()
assert json_upload_payload["predicted_class"] == "suspicious", json_upload_payload

summary = client.post("/api/v1/summarize", json=json_upload_payload)
assert summary.status_code == 200, summary.get_data(as_text=True)
summary_payload = summary.get_json()
assert "Reservoir File Analysis Summary" in summary_payload["summary_markdown"], summary_payload

Path("output/api_fake_combo_response.json").write_text(json.dumps(upload_json, indent=2), encoding="utf-8")
print("API smoke test passed")
print("health:", health.get_json())
print("upload predicted_class:", upload_json["predicted_class"])
print("json predicted_class:", json_upload_payload["predicted_class"])
PY'

mkdir -p "$ROOT_DIR/output"
cp -R "$STAGE_DIR/output/." "$ROOT_DIR/output/"

echo "Copied API test output to $ROOT_DIR/output/api_fake_combo_response.json"
