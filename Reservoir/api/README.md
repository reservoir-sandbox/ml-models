# Reservoir ML API MVP

This package exposes the ML file-analysis pipeline through HTTP.

It supports:

- health check
- multipart ELF upload
- JSON/base64 ELF upload
- prediction JSON -> Markdown summary

## Run

From the repository root:

```bash
bash scripts/run_ml_api_in_docker.sh
```

The API will listen on:

```text
http://localhost:8000
```

## Endpoints

### Health

```bash
curl -s http://localhost:8000/health
```

### Analyze Uploaded File

```bash
curl -s \
  -F "file=@samples/suspicious/fake_combo" \
  -F "include_summary=1" \
  http://localhost:8000/api/v1/analyze
```

### Analyze JSON/Base64 File

Request shape:

```json
{
  "filename": "sample",
  "content_base64": "...",
  "include_summary": true
}
```

Endpoint:

```text
POST /api/v1/analyze-json
```

### Summarize Existing Prediction JSON

```text
POST /api/v1/summarize
```

Request body is the prediction JSON produced by the file-analysis model.

## Response Shape

The analysis endpoints return JSON with:

```text
predicted_class
suspicious_probability
heuristic_score
sha256
evidence.strings
evidence.imports
features
summary_markdown
```

## Smoke Test

```bash
bash scripts/test_ml_api_in_docker.sh
```

This verifies `/health`, `/api/v1/analyze`, `/api/v1/analyze-json`, and
`/api/v1/summarize`.
