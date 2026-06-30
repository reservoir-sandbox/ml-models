#!/usr/bin/env python3
"""Flask API for Reservoir ML file analysis and summarization."""

from __future__ import annotations

import base64
import binascii
import os
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from Reservoir.file_analysis.predictor import (
    DEFAULT_FEATURE_COLUMNS_PATH,
    DEFAULT_MODEL_PATH,
    predict_elf,
)
from Reservoir.summarizer.summarize_prediction import build_summary


MAX_UPLOAD_BYTES = int(os.environ.get("RESERVOIR_MAX_UPLOAD_BYTES", str(32 * 1024 * 1024)))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.errorhandler(413)
    def upload_too_large(_: Exception):
        return jsonify({"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES}), 413

    @app.errorhandler(Exception)
    def unhandled_error(exc: Exception):
        return jsonify({"error": "internal_error", "message": str(exc)}), 500

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "reservoir-ml-api",
            "model_exists": DEFAULT_MODEL_PATH.exists(),
            "feature_columns_exist": DEFAULT_FEATURE_COLUMNS_PATH.exists(),
        })

    @app.post("/api/v1/analyze")
    def analyze_upload():
        uploaded = request.files.get("file")
        if uploaded is None:
            return jsonify({"error": "missing_file", "message": "Upload a file field named 'file'."}), 400
        return jsonify(_analyze_filestorage(uploaded, request.form))

    @app.post("/api/v1/analyze-json")
    def analyze_json():
        payload = request.get_json(silent=True) or {}
        filename = secure_filename(str(payload.get("filename") or "uploaded_elf"))
        encoded = payload.get("content_base64")
        if not encoded:
            return jsonify({"error": "missing_content_base64"}), 400
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return jsonify({"error": "invalid_base64"}), 400
        if len(content) > MAX_UPLOAD_BYTES:
            return jsonify({"error": "file_too_large", "max_bytes": MAX_UPLOAD_BYTES}), 413
        options = {
            "keep_raw": payload.get("keep_raw", False),
            "include_summary": payload.get("include_summary", True),
        }
        return jsonify(_analyze_bytes(filename, content, options))

    @app.post("/api/v1/summarize")
    def summarize_prediction():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_json"}), 400
        return jsonify({"summary_markdown": build_summary(payload)})

    return app


def _bool_option(options: dict[str, Any], name: str, default: bool = False) -> bool:
    value = options.get(name, default)
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _analyze_filestorage(uploaded: FileStorage, options: dict[str, Any]) -> dict[str, Any]:
    filename = secure_filename(uploaded.filename or "uploaded_elf")
    content = uploaded.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Uploaded file exceeds {MAX_UPLOAD_BYTES} bytes")
    return _analyze_bytes(filename, content, options)


def _analyze_bytes(filename: str, content: bytes, options: dict[str, Any]) -> dict[str, Any]:
    include_summary = _bool_option(options, "include_summary", True)
    keep_raw = _bool_option(options, "keep_raw", False)

    with tempfile.TemporaryDirectory(prefix="reservoir-ml-api-") as tmpdir:
        sample_path = Path(tmpdir) / (secure_filename(filename) or "uploaded_elf")
        sample_path.write_bytes(content)
        prediction = predict_elf(sample_path, keep_raw=keep_raw)

    if include_summary:
        prediction["summary_markdown"] = build_summary(prediction)
    return prediction


app = create_app()


if __name__ == "__main__":
    app.run(host=os.environ.get("RESERVOIR_API_HOST", "127.0.0.1"), port=int(os.environ.get("RESERVOIR_API_PORT", "8000")))
